"""Generation engine: drives org × time × sources -> events -> sinks."""
from __future__ import annotations

import random
import time
from datetime import datetime, timedelta, timezone

from .behavior.clock import WorkClock
from .behavior import leisure as leisuremod
from .behavior import statemap as statemapmod
from .behavior import work as workmod
from .behavior.profiles import (
    _stable_seed, arrival_time, day_factor, departure_time, make_persona,
    per_tick_lambda, poisson,
)
from .config import resolve_es_password, resolve_path
from .sinks import EsBulkSink, FileSink, SyslogSink
from .sources import SOURCES
from .sources.base import LogEvent

# Intensity scales the per-user activity rate (how busy the simulated company is).
_INTENSITY_MULT = {"calm": 0.4, "normal": 1.0, "noisy": 2.5}


class Engine:
    def __init__(self, cfg: dict, org, seed: int = 1337) -> None:
        self.cfg = cfg
        self.org = org
        self.seed = seed
        self.rng = random.Random(seed)
        self.clock = WorkClock(seed)
        self.base_dir = (cfg.get("output", {}) or {}).get("base_dir", "")
        # data_stream namespace -> indices become logs-<dataset>-<namespace>.
        # Set e.g. "siemgen" to isolate generated data in its own Kibana data view.
        self.namespace = (cfg.get("elasticsearch", {}) or {}).get("namespace", "default")
        # Index naming for backfill. Default = logs data streams. Set to e.g.
        # "siemgen-{dataset}" to write plain indices that BYPASS any logs-* default
        # pipeline / TSDS that could overwrite or reject the backdated @timestamp.
        self.index_tpl = (cfg.get("elasticsearch", {}) or {}).get(
            "index", "logs-{dataset}-{namespace}")
        # ground-truth labels (labels.state/activity/offtask/app/category) are synthetic
        # annotations, NOT real-log fields — keep for evaluation, but set
        # ground_truth.labels: false to emit a "clean"/production-like dataset.
        # NEVER use labels.* as a detection/UEBA feature (data leakage).
        self.gt_labels = bool((cfg.get("ground_truth", {}) or {}).get("labels", True))
        self.sources: dict = {}
        self.routes: dict = {}
        self._file = None
        self._es = None
        self._syslog: dict = {}
        # leisure / off-task profiles (modelled from real captures)
        lcfg = cfg.get("leisure", {}) or {}
        self.leisure = (leisuremod.load_leisure(lcfg.get("profiles", "config/leisure-profiles.yaml"))
                        if lcfg.get("enabled", True) else None)
        if self.leisure:   # carry the volume knob from the run config into the profiles
            self.leisure["rate_multiplier"] = lcfg.get("rate_multiplier", 1.0)
        self._offtask: dict = {}
        self._personas: dict = {}
        # Optional LLM/rules "director": a per-user state machine over
        # {absent, working, leisure, mixed, meeting}. Opt-in via the `behavior`
        # block; absent/off -> the classic day_factor + leisure path below.
        self._setup_director()

    # -- director (optional behavioural state machine) ----------------------
    def _setup_director(self) -> None:
        self.director_on = False
        self.director = None
        self.scheduler = None
        self.personas_cfg = None
        self.meeting_app = None
        self.work = None
        self._traits_cache: dict = {}
        b = self.cfg.get("behavior", {}) or {}
        mode = b.get("director", "off")
        if mode not in ("rules", "llm"):
            return
        from .behavior import personas as personasmod
        pcfg = personasmod.load_personas(b.get("personas", "config/personas.yaml"))
        if not pcfg:
            print("[siemgen] behavior.director set but personas config missing -> disabled",
                  flush=True)
            return
        self.personas_cfg = pcfg
        self.meeting_app = pcfg.get("meeting_app")
        # role-aware WORK network baseline (so 'working' has realistic log density)
        self.work = workmod.load_work(b.get("work_profiles", "config/work-profiles.yaml"))
        if self.work:
            self.work["work_intensity"] = b.get("work_intensity", 1.0)
        # scale the per-minute endpoint/identity rates (windows/sysmon/auditd/azuread)
        # without editing work-profiles.yaml — the main volume knob for small labs
        self.endpoint_intensity = float(b.get("endpoint_intensity", 1.0))
        llm = cache = None
        if mode == "llm":
            try:
                from .behavior.cache import DecisionCache
                from .behavior.llm_ollama import OllamaClient
                lc = b.get("llm", {}) or {}
                client = OllamaClient(
                    url=lc.get("url", "http://localhost:11434"),
                    model=lc.get("model", "llama3.2:3b"),
                    temperature=lc.get("temperature", 0),
                    timeout=lc.get("timeout_s", 20),
                )
                if client.available():
                    llm = client
                    cache = DecisionCache(lc.get("cache_file")) if lc.get("cache", True) else None
                else:
                    print("[siemgen] Ollama unavailable -> director falling back to rules",
                          flush=True)
                    mode = "rules"
            except Exception as e:  # noqa: BLE001 — never let LLM init kill the run
                print(f"[siemgen] LLM director init failed ({e}) -> rules", flush=True)
                mode = "rules"
        from .behavior.director import Director, Scheduler
        self.director = Director(mode, self.leisure, self.seed, llm=llm, cache=cache)
        self.scheduler = Scheduler(self.director, self.seed)
        self.director_on = True
        print(f"[siemgen] behavioural director ON (mode={mode})", flush=True)

    def _traits(self, user):
        t = self._traits_cache.get(user.username)
        if t is None:
            from .behavior.personas import sample_traits
            t = sample_traits(user, self.personas_cfg, self.seed)
            self._traits_cache[user.username] = t
        return t

    # -- sink factories (shared instances) ----------------------------------
    def _file_sink(self) -> FileSink:
        if self._file is None:
            self._file = FileSink()
        return self._file

    def _es_sink(self) -> EsBulkSink:
        if self._es is None:
            es = self.cfg.get("elasticsearch", {}) or {}
            self._es = EsBulkSink(
                url=es.get("url", "https://localhost:9200"),
                user=es.get("user", "elastic"),
                password=resolve_es_password(es),
                ca_cert=es.get("ca_cert", "") or "",
                verify=bool(es.get("verify", False)),
            )
        return self._es

    def _syslog_sink(self, host: str, port: int) -> SyslogSink:
        key = (host, int(port))
        if key not in self._syslog:
            self._syslog[key] = SyslogSink(host, port)
        return self._syslog[key]

    # -- wiring -------------------------------------------------------------
    def build(self, mode: str, default_sink: str | None = None) -> None:
        """Instantiate the enabled sources and route each one to a sink.
        `default_sink` overrides the per-mode default (esbulk for backfill, file
        otherwise) for sources whose config does not name a sink explicitly."""
        scfg = self.cfg.get("sources", {}) or {}
        fallback = default_sink or ("esbulk" if mode == "backfill" else "file")
        for name, klass in SOURCES.items():
            c = scfg.get(name, {}) or {}
            if not c.get("enabled"):
                continue
            src = klass()
            src.bind(self.org)
            self.sources[name] = src
            kind = c.get("sink") or fallback
            if kind == "esbulk":
                self.routes[name] = {"sink": self._es_sink(), "path": None}
            elif kind == "syslog":
                self.routes[name] = {
                    "sink": self._syslog_sink(c.get("host", "127.0.0.1"), c.get("port", 5140)),
                    "path": None,
                }
            else:
                path = resolve_path(self.base_dir, c.get("path", f"/var/log/{name}.log"))
                self.routes[name] = {"sink": self._file_sink(), "path": path}

    def _emit(self, ev: LogEvent) -> None:
        src = self.sources[ev.source]
        route = self.routes[ev.source]
        sink = route["sink"]
        if sink.kind == "es":
            doc = src.render_ecs(ev)
            # route into the configured namespace + tag every doc so the generated
            # data is trivial to isolate (data view) and to clean up (delete-by-query).
            doc.setdefault("data_stream", {})["namespace"] = self.namespace
            lbl = doc.setdefault("labels", {})
            lbl["generator"] = "siemgen"
            if not self.gt_labels:                 # clean dataset: drop ground-truth tags
                for k in ("state", "activity", "offtask", "app", "category"):
                    lbl.pop(k, None)
            index = self.index_tpl.format(dataset=src.dataset, namespace=self.namespace)
            sink.write_doc(index, doc)
        else:
            sink.write_line(route["path"], src.render_native(ev))

    def emit(self, ev: LogEvent) -> None:
        """Public emit (used by the scenario engine too)."""
        self._emit(ev)

    @staticmethod
    def _as_list(ev) -> list:
        """Sources may return one LogEvent, a list of them, or None."""
        if ev is None:
            return []
        if isinstance(ev, list):
            return [e for e in ev if e is not None]
        return [ev]

    # -- modes --------------------------------------------------------------
    def backfill(self, start: datetime, end: datetime) -> int:
        """Bulk historical data, one day at a time (bounded memory). Each day's events
        are sorted chronologically before emission."""
        total = 0
        day = start.replace(hour=0, minute=0, second=0, microsecond=0)
        while day <= end:
            events = self.day_events(day, start, end)
            for ev in events:
                self._emit(ev)
            total += len(events)
            self.flush_all()
            day += timedelta(days=1)
        return total

    def _offtask_profile(self, user):
        off = self._offtask.get(user.username)
        if off is None:
            off = leisuremod.user_offtask(user, self.leisure, self.seed)
            self._offtask[user.username] = off
        return off

    def _leisure_sessions(self, user, host, day, start, end) -> list:
        """Off-task sessions for one working day (backfill)."""
        if not all(n in self.sources for n in ("dns", "pfsense", "suricata")):
            return []
        off = self._offtask_profile(user)
        midnight = day.replace(hour=0, minute=0, second=0, microsecond=0)
        out: list = []
        for app, start_min, dur in leisuremod.plan_day_sessions(user, off, self.leisure, self.rng):
            st = midnight + timedelta(minutes=start_min)
            prof = self.leisure["profiles"][app]
            evs = leisuremod.expand_session(self.sources, user, host, app, prof, st, dur,
                                            self.leisure, self.rng)
            out += [e for e in evs if start <= e.timestamp <= end]
        return out

    # -- director rendering (backfill) --------------------------------------
    def _director_backfill_day(self, user, host, day, start, end, persona) -> list:
        """Render one day for a user under the state-machine director: ask the
        Scheduler for the day's Segments, then render each segment with the
        matching emitters. Empty schedule => user absent that day (no events)."""
        traits = self._traits(user)
        segs = self.scheduler.day_segments(user, traits, day, persona)
        if not segs:
            return []
        rng = random.Random(_stable_seed(self.seed, "render", user.username, day.toordinal()))
        midnight = day.replace(hour=0, minute=0, second=0, microsecond=0)
        out: list = []

        # arrival logon at the first active segment. NOTE: always generate, then
        # filter — every RNG draw must happen regardless of the [start, end] window,
        # otherwise a day rendered in two halves differs from a day rendered at once.
        first_active = next((s for s in segs if s.state != "absent"), None)
        if first_active is not None:
            lts = midnight + timedelta(minutes=first_active.start_min,
                                       seconds=rng.randint(0, 59), microseconds=rng.randint(0, 999999))
            arrival = self._as_list(self._logon_event(user, host, lts, persona, rng))
            # DHCP lease at arrival -> historical IP->host->owner join for UEBA
            if "dhcp" in self.sources:
                arrival.append(self.sources["dhcp"].lease_event(user, host, lts, self.org, rng))
            out += [ev for ev in arrival if start <= ev.timestamp <= end]

        workday_min = max(60, (user.work_end - user.work_start) * 60)
        for seg in segs:
            self._render_segment(user, host, midnight, seg, persona, traits,
                                 workday_min, start, end, rng, out)
        return out

    def _render_segment(self, user, host, midnight, seg, persona, traits,
                        workday_min, start, end, rng, out) -> None:
        if seg.state == "absent":
            return
        seg_start = midnight + timedelta(minutes=seg.start_min)
        minutes = max(1, seg.end_min - seg.start_min)
        leisure_ready = all(n in self.sources for n in ("dns", "pfsense", "suricata"))

        # leisure / meeting: calibrated per-minute network sessions (labels.state set)
        if seg.state in ("leisure", "meeting") and leisure_ready:
            ctx = self._state_ctx(seg, rng)
            if ctx is not None:
                for m in range(minutes):
                    ts = seg_start + timedelta(minutes=m)
                    for ev in statemapmod.minute(self.sources, host, ts, ctx, rng):
                        if start <= ev.timestamp <= end:
                            out.append(ev)
            if seg.state == "meeting":
                return

        # working (and the work half of mixed): baseline activity mix, volume
        # proportional to the segment length vs a full working day.
        if seg.state in ("working", "mixed"):
            lam = persona.daily_events * (minutes / workday_min)
            for _ in range(poisson(rng, lam)):
                ts = seg_start + timedelta(seconds=rng.randint(0, minutes * 60 - 1),
                                           microseconds=rng.randint(0, 999999))
                for ev in self._as_list(self._activity_event(user, host, ts, persona, rng)):
                    if start <= ev.timestamp <= end:
                        ev.labels = {**(ev.labels or {}), "state": seg.state}
                        out.append(ev)
            # role-aware WORK network baseline (DNS + flows + TLS on the host AND
            # passes on the firewall) — the bulk of a realistic working day's logs.
            if self.work and leisure_ready:
                wctx = workmod.work_context(user, self.work, rng, self.org.dns_domain)
                for m in range(minutes):
                    ts = seg_start + timedelta(minutes=m)
                    for ev in workmod.minute_events(self.sources, host, ts, wctx, rng):
                        if start <= ev.timestamp <= end:
                            out.append(ev)
            # endpoint/identity per-minute telemetry (host-heavy, ~EDR on)
            for m in range(minutes):
                ts = seg_start + timedelta(minutes=m)
                for ev in self._endpoint_minute(user, host, ts, rng):
                    if start <= ev.timestamp <= end:
                        ev.labels = {**(ev.labels or {}), "state": seg.state}
                        out.append(ev)

        # mixed: a fraction of minutes (gated by focus_bias) also carry leisure
        if seg.state == "mixed" and leisure_ready and seg.app:
            ctx = self._state_ctx(seg, rng)
            if ctx is not None:
                share = max(0.0, 1.0 - traits.focus_bias)
                for m in range(minutes):
                    if rng.random() >= share:
                        continue
                    ts = seg_start + timedelta(minutes=m)
                    for ev in statemapmod.minute(self.sources, host, ts, ctx, rng):
                        if start <= ev.timestamp <= end:
                            out.append(ev)

    def _state_ctx(self, seg, rng):
        """Build the leisure/meeting session context for a segment."""
        if seg.state == "meeting":
            if not self.meeting_app:
                return None
            return statemapmod.meeting_context(self.meeting_app, self.leisure, rng)
        if seg.app and self.leisure and seg.app in self.leisure["profiles"]:
            prof = self.leisure["profiles"][seg.app]
            return statemapmod.leisure_context(seg.app, prof, self.leisure, rng)
        return None

    def _endpoint_minute(self, user, host, ts, rng) -> list:
        """Per-minute endpoint/identity telemetry for a working minute: Windows
        Security (4688 chains + periodic 4624/4769/5140/4625) on Windows hosts, or
        auditd EXECVE on Linux hosts. Volume knobs live in work-profiles.yaml under
        `endpoint:`; absent config falls back to host-heavy defaults in the sources."""
        cfg = (self.work or {}).get("endpoint", {}) or {}
        k = getattr(self, "endpoint_intensity", 1.0)

        def rates(section: str) -> dict:
            base = cfg.get(section, {}) or {}
            return {name: float(v) * k for name, v in base.items()} if k != 1.0 else base

        out = []
        if host.os == "windows" and "windows" in self.sources:
            out += self.sources["windows"].minute_events(user, host, ts, self.org, rng, rates("windows"))
            if "sysmon" in self.sources:           # rich EDR-style endpoint telemetry
                out += self.sources["sysmon"].minute_events(user, host, ts, self.org, rng, rates("sysmon"))
        elif host.os == "linux" and "auditd" in self.sources:
            out += self.sources["auditd"].minute_events(user, host, ts, self.org, rng, rates("linux"))
        # cloud sign-in (M365/Azure AD) — OS-independent, low rate
        if "azuread" in self.sources:
            out += self.sources["azuread"].minute_events(user, host, ts, self.org, rng, rates("azuread"))
        return out

    def _plan_leisure(self, user, now, rng) -> list:
        """Plan a working day's off-task sessions for the live stream."""
        if not self.leisure or not all(n in self.sources for n in ("dns", "pfsense", "suricata")):
            return []
        off = self._offtask_profile(user)
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        plan = []
        for app, start_min, dur in leisuremod.plan_day_sessions(user, off, self.leisure, rng):
            st = midnight + timedelta(minutes=start_min)
            plan.append({"app": app, "start": st, "end": st + timedelta(minutes=dur),
                         "ctx": None, "last_min": -1})
        return plan

    def stream(self) -> None:
        """Realistic, session-based live stream of a normal company day (no attacks).

        Each user has a stable persona and a daily schedule: they 'arrive' near their
        start time (a logon event), produce activity through the day following a diurnal
        curve (lunch dip), then leave. Content is high-entropy so it never repeats."""
        st = (self.cfg.get("time", {}) or {}).get("stream", {}) or {}
        tick = float(st.get("tick", 5.0))             # seconds between ticks
        jitter = float(st.get("jitter", 0.2))
        rate_mult = _INTENSITY_MULT.get(st.get("intensity", "normal"), 1.0)

        # system-seeded RNG -> activity differs every run (never replays a week)
        srng = random.Random()
        personas: dict = {}
        weights: dict = {}     # username -> (hour_weight_map, total_weight)
        sessions: dict = {}    # username -> session state
        n = 0

        import signal

        def _stop(signum, frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, _stop)
        print(f"[siemgen] session stream: intensity={st.get('intensity', 'normal')} "
              f"tick={tick}s, {len(self.org.users)} users (Ctrl-C to stop)", flush=True)
        try:
            while True:
                now = datetime.now(timezone.utc)
                for user in self.org.users:
                    n += self._tick_user(user, now, tick, rate_mult, srng,
                                         personas, weights, sessions)
                self.flush_all()
                time.sleep(max(0.5, tick * (1 + srng.uniform(-jitter, jitter))))
        except KeyboardInterrupt:
            print(f"\n[siemgen] stopped after {n} events")
        finally:
            self.flush_all()

    def _tick_user(self, user, now, tick, rate_mult, srng, personas, weights, sessions) -> int:
        host = self.org.host_for(user)
        p = personas.get(user.username)
        if p is None:
            p = make_persona(user, host, self.seed)
            personas[user.username] = p
            wm = self.clock.hour_weights_map(user)
            weights[user.username] = (wm, sum(wm.values()) or 1.0)
        wm, total_w = weights[user.username]
        if self.director_on:
            return self._tick_user_director(user, host, now, tick, rate_mult, srng,
                                            p, wm, total_w, sessions)

        s = sessions.setdefault(user.username,
                                {"day": None, "scheduled": False, "on": False, "factor": 1.0})
        if s["day"] != now.date():
            s["day"] = now.date()
            f = day_factor(user, now, self.seed)
            if self.clock.works_today(user, now) and f > 0:
                s["arrival"] = arrival_time(user, p, now)
                s["departure"] = departure_time(user, p, now)
                s["scheduled"], s["on"], s["factor"] = True, False, f
                s["leisure_plan"] = self._plan_leisure(user, now, srng)
            else:
                s["scheduled"], s["on"] = False, False
        if not s["scheduled"]:
            return 0

        if not s["on"]:
            if s["arrival"] <= now < s["departure"]:
                count = 0
                for ev in self._as_list(self._logon_event(user, host, now, p, srng)):
                    self._emit(ev); count += 1
                if "dhcp" in self.sources:        # host gets/renews its lease on arrival
                    self._emit(self.sources["dhcp"].lease_event(user, host, now, self.org, srng))
                    count += 1
                s["on"] = True
                return count
            return 0
        if now >= s["departure"]:
            s["on"], s["scheduled"] = False, False
            return 0

        count = 0
        # leisure / off-task: DNS burst at session start, one flow record per minute
        for sess in s.get("leisure_plan", []):
            if sess["start"] <= now < sess["end"]:
                if sess["ctx"] is None:
                    prof = self.leisure["profiles"][sess["app"]]
                    sess["ctx"] = leisuremod.session_context(sess["app"], prof, self.leisure, srng)
                    sess["last_min"] = 0
                    for ev in leisuremod.minute_events(self.sources, host, now, sess["ctx"], srng):
                        self._emit(ev); count += 1
                else:
                    cur_min = int((now - sess["start"]).total_seconds() // 60)
                    if cur_min > sess["last_min"]:
                        sess["last_min"] = cur_min
                        for ev in leisuremod.minute_events(self.sources, host, now, sess["ctx"], srng):
                            self._emit(ev); count += 1

        lam = per_tick_lambda(p, wm, total_w, now.hour, tick) * rate_mult * s["factor"]
        for _ in range(poisson(srng, lam)):
            for ev in self._as_list(self._activity_event(user, host, now, p, srng)):
                self._emit(ev)
                count += 1
        return count

    def _tick_user_director(self, user, host, now, tick, rate_mult, srng, p, wm,
                            total_w, sessions) -> int:
        """One stream tick under the director: run the per-user state machine,
        re-deciding the next state at each transition and rendering the current
        state. Guardrails (present/absent today) come from the Scheduler."""
        from .behavior.director import DirectorContext

        traits = self._traits(user)
        s = sessions.setdefault(user.username, {"day": None, "scheduled": False, "on": False})
        if s["day"] != now.date():
            s["day"] = now.date()
            drng = random.Random(_stable_seed(self.seed, "director-stream",
                                              user.username, now.toordinal()))
            if self.scheduler._present_today(user, traits, now, drng):
                s["arrival"] = arrival_time(user, p, now)
                s["departure"] = departure_time(user, p, now)
                s.update(scheduled=True, on=False, state=None, state_until=None,
                         state_app=None, state_ctx=None, state_start=now, last_min=-1,
                         today={"work_min": 0, "leisure_min": 0, "meeting_min": 0})
            else:
                s.update(scheduled=False, on=False)
        if not s["scheduled"]:
            return 0

        if not s["on"]:
            if s["arrival"] <= now < s["departure"]:
                count = 0
                for ev in self._as_list(self._logon_event(user, host, now, p, srng)):
                    self._emit(ev); count += 1
                if "dhcp" in self.sources:
                    self._emit(self.sources["dhcp"].lease_event(user, host, now, self.org, srng))
                    count += 1
                s["on"] = True
                return count
            return 0
        if now >= s["departure"]:
            s["on"], s["scheduled"] = False, False
            return 0

        count = 0
        # re-decide at a transition (or at first activation)
        if s["state"] is None or s["state_until"] is None or now >= s["state_until"]:
            mins_in = int((now - s["state_start"]).total_seconds() // 60) if s["state"] else 0
            ctx = DirectorContext(
                archetype=traits.archetype, role=user.role, domain=user.domain,
                username=user.username,
                traits={"distractibility": round(traits.distractibility, 2),
                        "focus_bias": round(traits.focus_bias, 2),
                        "leisure_propensity": round(traits.leisure_propensity, 2),
                        "meeting_propensity": round(traits.meeting_propensity, 2),
                        "preferred_leisure": traits.preferred_leisure,
                        "slump_hour": traits.slump_hour},
                weekday=now.strftime("%A"), date=now.strftime("%Y-%m-%d"),
                is_weekend=now.weekday() >= 5, is_holiday=False,
                hour=now.hour, minute=now.minute,
                current_state=s["state"] or "absent", minutes_in_state=mins_in,
                today_so_far={k: round(v) for k, v in s["today"].items()},
                events=self.scheduler._day_events(user, now),
            )
            dec = self.director.decide(ctx, traits, srng)
            s["state"] = dec.next_state
            s["state_app"] = dec.app
            s["state_start"] = now
            s["state_until"] = now + timedelta(minutes=max(2, int(dec.duration_min)))
            s["state_ctx"] = None
            s["last_min"] = -1
            s["work_ctx"] = None
            s["work_last_min"] = -1
            s["ep_last_min"] = -1

        state = s["state"]
        if state in ("leisure", "meeting"):
            if s["state_ctx"] is None:
                s["state_ctx"] = self._state_ctx_stream(state, s["state_app"], srng)
            if s["state_ctx"] is not None:
                cur_min = int((now - s["state_start"]).total_seconds() // 60)
                if cur_min > s["last_min"]:
                    s["last_min"] = cur_min
                    for ev in statemapmod.minute(self.sources, host, now, s["state_ctx"], srng):
                        self._emit(ev)
                        count += 1
        if state in ("working", "mixed"):
            lam = per_tick_lambda(p, wm, total_w, now.hour, tick) * rate_mult
            for _ in range(poisson(srng, lam)):
                for ev in self._as_list(self._activity_event(user, host, now, p, srng)):
                    ev.labels = {**(ev.labels or {}), "state": state}
                    self._emit(ev)
                    count += 1
            # role-aware WORK network baseline (host + firewall), once per new minute
            if self.work:
                if s.get("work_ctx") is None:
                    s["work_ctx"] = workmod.work_context(user, self.work, srng, self.org.dns_domain)
                cur_min = int((now - s["state_start"]).total_seconds() // 60)
                if cur_min > s.get("work_last_min", -1):
                    s["work_last_min"] = cur_min
                    for ev in workmod.minute_events(self.sources, host, now, s["work_ctx"], srng):
                        self._emit(ev)
                        count += 1
            # endpoint/identity telemetry (host-heavy), once per new minute
            ep_min = int((now - s["state_start"]).total_seconds() // 60)
            if ep_min > s.get("ep_last_min", -1):
                s["ep_last_min"] = ep_min
                for ev in self._endpoint_minute(user, host, now, srng):
                    ev.labels = {**(ev.labels or {}), "state": state}
                    self._emit(ev)
                    count += 1
            if state == "mixed" and s["state_app"]:
                if s["state_ctx"] is None:
                    s["state_ctx"] = self._state_ctx_stream("leisure", s["state_app"], srng)
                cur_min = int((now - s["state_start"]).total_seconds() // 60)
                if cur_min > s["last_min"]:
                    s["last_min"] = cur_min
                    if s["state_ctx"] is not None and srng.random() < max(0.0, 1.0 - traits.focus_bias):
                        for ev in statemapmod.minute(self.sources, host, now, s["state_ctx"], srng):
                            self._emit(ev)
                            count += 1

        inc = tick / 60.0
        if state == "working":
            s["today"]["work_min"] += inc
        elif state == "meeting":
            s["today"]["meeting_min"] += inc
        elif state in ("leisure", "mixed"):
            s["today"]["leisure_min"] += inc
            if state == "mixed":
                s["today"]["work_min"] += inc
        return count

    def _state_ctx_stream(self, state, app, rng):
        if state == "meeting":
            return (statemapmod.meeting_context(self.meeting_app, self.leisure, rng)
                    if self.meeting_app else None)
        if app and self.leisure and app in self.leisure["profiles"]:
            return statemapmod.leisure_context(app, self.leisure["profiles"][app],
                                               self.leisure, rng)
        return None

    def _logon_event(self, user, host, now, persona, rng=None):
        """How the user 'arrives', picked by topology: remote->VPN (+ the host logon
        behind it), Windows->4624, Linux/admin->sshd, else a web-app login.
        Returns a list of events. `rng` keeps the arrival reproducible."""
        rng = rng or self.rng
        s = self.sources
        out = []
        if user.site == "remote" and "vpn" in s:
            out.append(s["vpn"].login_event(user, host, now, self.org, rng, persona))
            now = now + timedelta(seconds=rng.randint(3, 20))
        if host.os == "windows" and "windows" in s:
            out.append(s["windows"].login_event(user, host, now, self.org, rng, persona))
        elif (host.os == "linux" or user.role in ("it-admin", "ops")) and "linux_auth" in s:
            out.append(s["linux_auth"].login_event(user, host, now, self.org, rng, persona))
        elif "nginx" in s:
            out.append(s["nginx"].login_event(user, host, now, self.org, rng, persona))
        elif not out:
            any_src = next(iter(s.values()))
            out += self._as_list(any_src.make_event(user, host, now, self.org, rng, persona))
        return out

    def _activity_event(self, user, host, now, persona, srng):
        """Pick an applicable source weighted by its activity_weight, then emit one event."""
        cands = [s for s in self.sources.values() if s.applies_to(user, host)]
        weights = [s.activity_weight(user) for s in cands]
        cands = [c for c, w in zip(cands, weights) if w > 0]
        weights = [w for w in weights if w > 0]
        if not cands:
            return None
        src = srng.choices(cands, weights=weights, k=1)[0]
        return src.make_event(user, host, now, self.org, srng, persona)

    # -- deterministic day rendering (used by `generate`) ------------------
    def day_events(self, day: datetime, start: datetime, end: datetime) -> list:
        """All events of one calendar day for every user, chronologically sorted and
        clipped to [start, end]. Deterministic per (seed, day) when the Director is
        on: every user/day has its own RNG, so any day can be re-rendered on its own
        and yields the same events — the basis of the resumable `generate` timeline.
        Without the Director the classic per-source lottery is used (one shared RNG,
        so only a full sequential run is reproducible)."""
        events: list = []
        for user in self.org.users:
            host = self.org.host_for(user)
            p = self._personas.get(user.username)
            if p is None:
                p = make_persona(user, host, self.seed)
                self._personas[user.username] = p
            if self.director_on:
                events += self._director_backfill_day(user, host, day, start, end, p)
                continue
            if not self.clock.works_today(user, day):
                continue
            f = day_factor(user, day, self.seed)
            if f <= 0:
                continue
            for src in self.sources.values():
                if not src.applies_to(user, host):
                    continue
                n = max(0, int(round(src.daily_volume(user, self.rng) * f)))
                for _ in range(n):
                    ts = self.clock.sample_time(user, day, self.rng)
                    if ts < start or ts > end:
                        continue
                    events += self._as_list(src.make_event(user, host, ts, self.org, self.rng, p))
            if self.leisure:
                events += self._leisure_sessions(user, host, day, start, end)
        events.sort(key=lambda e: e.timestamp)
        return events

    # -- lifecycle ----------------------------------------------------------
    def flush_all(self) -> None:
        for s in self._all_sinks():
            s.flush()

    def close_all(self) -> None:
        for s in self._all_sinks():
            if hasattr(s, "close"):
                s.close()

    def _all_sinks(self):
        out = []
        if self._file:
            out.append(self._file)
        if self._es:
            out.append(self._es)
        out.extend(self._syslog.values())
        return out

    def stats(self) -> dict:
        d = {}
        if self._file:
            d["file_lines"] = self._file.count
        if self._es:
            d["es_docs"] = self._es.count
            d["es_errors"] = self._es.errors
            if self._es.first_error:
                d["es_first_error"] = self._es.first_error
        if self._syslog:
            d["syslog_lines"] = sum(s.count for s in self._syslog.values())
        if self.director_on and self.director is not None:
            dd = {"mode": self.director.mode}
            if self.director.mode == "llm":
                dd["llm_calls"] = self.director.llm_calls
                dd["llm_fallbacks"] = self.director.llm_fallbacks
                if self.director.cache is not None:
                    dd["cache_hits"] = self.director.cache.hits
                    dd["cache_misses"] = self.director.cache.misses
            d["director"] = dd
        return d
