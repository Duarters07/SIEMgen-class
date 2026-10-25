"""One deterministic timeline, two pacing modes.

`siemgen generate` renders the organisation's activity as native log FILES only —
no SIEM, no network. It has two phases that share the same generator:

  * **history** — the last N days are rendered at once, with their real (past)
    timestamps, so the files hold a ready-made archive to build parsers against;
  * **live**    — the timeline keeps advancing in real time (or faster, see `speed`):
    every tick, the events whose simulated timestamp has just passed are appended.

Because every (user, day) has its own seeded RNG when the behavioural Director is
on, ANY day can be re-rendered on its own and is byte-identical. That gives:

  * reproducibility — the same seed produces the same files on every machine;
  * resume without duplicates — the run records the last emitted timestamp in a
    state file; on restart it fills the gap up to "now" and continues live;
  * time compression — `speed=12` plays a simulated day in two hours.

A `MANIFEST.json` / `MANIFEST.txt` pair in the output directory records the seed,
the organisation, the time range and per-file line counts.
"""
from __future__ import annotations

import hashlib
import json
import signal
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

STATE_FILE = ".siemgen-state.json"
MANIFEST_JSON = "MANIFEST.json"
MANIFEST_TXT = "MANIFEST.txt"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def _midnight(ts: datetime) -> datetime:
    return ts.replace(hour=0, minute=0, second=0, microsecond=0)


def config_digest(cfg: dict) -> str:
    """Digest of the parts of the config that change the generated content."""
    keep = {k: cfg.get(k) for k in ("seed", "organization", "sources", "leisure", "behavior")}
    return hashlib.sha1(json.dumps(keep, sort_keys=True, default=str).encode()).hexdigest()[:12]


class Timeline:
    def __init__(self, engine, out_dir: str, cfg: dict, speed: float = 1.0,
                 tick: float = 1.0, log=print) -> None:
        self.eng = engine
        self.out = Path(out_dir)
        self.cfg = cfg
        self.speed = max(0.01, float(speed))
        self.tick = max(0.2, float(tick))
        self.log = log
        self.state_path = self.out / STATE_FILE
        self.per_source: Counter = Counter()
        self.events_total = 0
        self.first_ts: datetime | None = None
        self.last_ts: datetime | None = None
        self.started = _utcnow()
        self._stop = False
        self._ready = False        # True once the state file was checked (or absent)

    # -- state ------------------------------------------------------------------
    def _identity(self) -> dict:
        return {"seed": self.eng.seed, "org": self.eng.org.name,
                "users": len(self.eng.org.users), "config": config_digest(self.cfg)}

    def load_state(self) -> dict | None:
        if not self.state_path.exists():
            self._ready = True
            return None
        try:
            st = json.loads(self.state_path.read_text())
        except Exception:  # noqa: BLE001 — a corrupt state file must not block a run
            self._ready = True
            return None
        ident = self._identity()
        mine = {k: st.get(k) for k in ident}
        if mine != ident:
            raise SystemExit(
                f"[siemgen] {self.state_path} belongs to another run "
                f"(seed={st.get('seed')}, org={st.get('org')}, users={st.get('users')}, "
                f"config={st.get('config')}) but this run is {ident}.\n"
                f"          Use the same seed/org/config to resume, or empty the output "
                f"directory to start a new dataset.")
        self.per_source = Counter(st.get("per_source", {}))
        self.events_total = int(st.get("events", 0))
        if st.get("first_ts"):
            self.first_ts = _parse(st["first_ts"])
        if st.get("last_ts"):
            self.last_ts = _parse(st["last_ts"])
        self._ready = True
        return st

    def save_state(self) -> None:
        if not self._ready:            # never overwrite another run's state
            return
        self.out.mkdir(parents=True, exist_ok=True)
        st = {**self._identity(),
              "first_ts": _iso(self.first_ts) if self.first_ts else None,
              "last_ts": _iso(self.last_ts) if self.last_ts else None,
              "events": self.events_total, "per_source": dict(self.per_source),
              "updated": _iso(_utcnow())}
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(st, indent=2))
        tmp.replace(self.state_path)

    # -- emission ---------------------------------------------------------------
    def _emit(self, ev) -> None:
        self.eng.emit(ev)
        self.per_source[ev.source] += 1
        self.events_total += 1
        if self.first_ts is None or ev.timestamp < self.first_ts:
            self.first_ts = ev.timestamp
        if self.last_ts is None or ev.timestamp > self.last_ts:
            self.last_ts = ev.timestamp

    # -- phases -----------------------------------------------------------------
    def history(self, days: int, until: datetime | None = None) -> int:
        """Render [midnight(now - days), until] to the files. If a state file says
        part of that range was already written, only the gap after `last_ts` is
        rendered (no duplicates)."""
        until = until or _utcnow()
        start = _midnight(until - timedelta(days=days))
        st = self.load_state()
        if st and st.get("last_ts"):
            last = _parse(st["last_ts"])
            if last >= until:
                self.log(f"[siemgen] history already up to date ({_iso(last)})")
                self.last_ts = last
                return 0
            start = last + timedelta(microseconds=1)
            self.last_ts = last
            self.log(f"[siemgen] resuming: filling {_iso(start)} .. {_iso(until)}")
        else:
            self.log(f"[siemgen] history: {_iso(start)} .. {_iso(until)} ({days} days)")
        n = 0
        day = _midnight(start)
        while day <= until and not self._stop:
            evs = self.eng.day_events(day, start, until)
            for ev in evs:
                self._emit(ev)
            n += len(evs)
            self.eng.flush_all()
            self.save_state()
            self.log(f"[siemgen]   {day:%Y-%m-%d %a}  {len(evs):>8} events  (total {self.events_total})")
            day += timedelta(days=1)
        self.write_manifest(phase="history")
        return n

    def live(self) -> int:
        """Advance the timeline in (compressed) real time until SIGINT/SIGTERM."""
        self._install_signals()
        real0 = time.monotonic()
        sim0 = _utcnow()
        if not self._ready:
            self.load_state()
        # never re-emit what history (or a previous live run) already wrote
        floor = self.last_ts or (sim0 - timedelta(microseconds=1))
        day = _midnight(sim0)
        buf = self._day_buffer(day)
        idx = 0
        while idx < len(buf) and buf[idx].timestamp <= floor:
            idx += 1
        n = 0
        last_save = time.monotonic()
        self.log(f"[siemgen] live: speed x{self.speed:g}, tick {self.tick:g}s, "
                 f"{len(self.eng.org.users)} users — Ctrl-C / SIGTERM to stop")
        while not self._stop:
            sim_now = sim0 + timedelta(seconds=(time.monotonic() - real0) * self.speed)
            # roll over midnight(s)
            while sim_now >= day + timedelta(days=1):
                while idx < len(buf):
                    self._emit(buf[idx]); idx += 1; n += 1
                day += timedelta(days=1)
                buf = self._day_buffer(day)
                idx = 0
                self.log(f"[siemgen]   new day {day:%Y-%m-%d %a}: {len(buf)} events scheduled")
            while idx < len(buf) and buf[idx].timestamp <= sim_now:
                self._emit(buf[idx]); idx += 1; n += 1
            self.eng.flush_all()
            if time.monotonic() - last_save > 10:
                self.save_state()
                self.write_manifest(phase="live")
                last_save = time.monotonic()
            time.sleep(self.tick)
        self.eng.flush_all()
        self.save_state()
        self.write_manifest(phase="live")
        self.log(f"[siemgen] stopped: {n} live events this run, {self.events_total} in total")
        return n

    def _day_buffer(self, day: datetime) -> list:
        return self.eng.day_events(day, day, day + timedelta(days=1) - timedelta(microseconds=1))

    def _install_signals(self) -> None:
        def _stop(signum, frame):
            self._stop = True
        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)

    # -- manifest ---------------------------------------------------------------
    def write_manifest(self, phase: str) -> None:
        if not self._ready:
            return
        org = self.eng.org
        sink = self.eng._file
        files = []
        if sink is not None:
            for path in sorted(sink.lines):
                rel = str(Path(path).relative_to(self.out)) if str(path).startswith(str(self.out)) else path
                files.append({"file": rel, "lines": sink.lines[path], "bytes": sink.bytes[path]})
        sources = {name: {"dataset": src.dataset, "file": self._rel(name), "events": self.per_source.get(name, 0)}
                   for name, src in self.eng.sources.items()}
        m = {
            "generator": "siemgen", "version": _version(), "phase": phase,
            "seed": self.eng.seed, "organization": {
                "name": org.name, "dns_domain": org.dns_domain, "windows_domain": org.windows_domain,
                "egress_ip": org.egress_ip, "users": len(org.users), "workstations": sum(1 for h in org.hosts if h.kind == "workstation"),
                "servers": org.servers},
            "time_range": {"first": _iso(self.first_ts) if self.first_ts else None,
                           "last": _iso(self.last_ts) if self.last_ts else None, "timezone": "UTC"},
            "events_total": self.events_total, "sources": sources, "files": files,
            "generated_at": _iso(_utcnow()),
        }
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / MANIFEST_JSON).write_text(json.dumps(m, indent=2))
        (self.out / MANIFEST_TXT).write_text(self._manifest_txt(m))

    def _rel(self, name: str) -> str | None:
        route = self.eng.routes.get(name) or {}
        p = route.get("path")
        if not p:
            return None
        return str(Path(p).relative_to(self.out)) if str(p).startswith(str(self.out)) else p

    def _manifest_txt(self, m: dict) -> str:
        o = m["organization"]
        lines = [
            f"siemgen {m['version']} — run manifest ({m['phase']})",
            f"seed: {m['seed']}   organization: {o['name']}   dns: {o['dns_domain']}   "
            f"windows domain: {o['windows_domain']}   egress ip: {o['egress_ip']}",
            f"users: {o['users']}   workstations: {o['workstations']}   servers: {', '.join(o['servers'])}",
            f"time range (UTC): {m['time_range']['first']}  ..  {m['time_range']['last']}",
            f"events: {m['events_total']}",
            "",
            f"{'source':<12} {'dataset':<28} {'events':>10}  file",
        ]
        for name, s in sorted(m["sources"].items()):
            lines.append(f"{name:<12} {s['dataset']:<28} {s['events']:>10}  {s['file'] or '-'}")
        lines += ["", f"{'file':<36} {'lines':>10} {'bytes':>12}"]
        for f in m["files"]:
            lines.append(f"{f['file']:<36} {f['lines']:>10} {f['bytes']:>12}")
        lines.append("")
        lines.append("'events' are logical records; some records span several lines "
                     "(SSH sessions, auditd groups, Postfix chains, DNS query/reply).")
        return "\n".join(lines) + "\n"


def _version() -> str:
    try:
        from . import __version__
        return __version__
    except Exception:  # noqa: BLE001
        return "?"
