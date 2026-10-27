"""`siemgen incident` — append ONE simulated intrusion to the log files of a run.

The generator never writes attacks: the baseline is clean on purpose. This command
is the classroom "red button". It writes, in the same native formats as the rest
of the files, the traces that a short intrusion would leave, so that students can
check whether the detection rules they wrote beforehand actually fire.

Nothing here touches the network. It only appends text lines to files under the
output folder (auth.log, pfsense/filterlog.log, suricata/eve.json); Filebeat picks
them up like any other line.

Scenario ``outside-login`` (the only one for now), about four minutes long:

  1. A forgotten port-forward on the firewall lets TCP/22 in from the internet
     to the web server: every connection is a pfSense ``pass,in`` on the WAN.
  2. An external address (one of the org's "malicious" IPs) tries ~36 passwords
     over two minutes: common account names first, then a real IT admin.
  3. The last attempt succeeds: ``Accepted password`` for that admin, from an
     address outside 10.0.0.0/8, with no OpenVPN session before it.
  4. As that admin, it runs ``sudo cat /etc/shadow`` and creates a local account
     with sudo rights (persistence), then disconnects.

The company, the admin, the attacker IP and the ports all derive from the run's
seed, so the instructor can predict the answer for every group.
"""
from __future__ import annotations

import json
import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .sources import _util
from .sources.linux_auth import LinuxAuth

_INVALID_USERS = ["admin", "root", "test", "ubuntu", "oracle", "postgres", "user",
                  "ftpuser", "pi", "guest", "support", "git"]
_FW_RULE, _FW_TRACKER = 9, 1000000121      # the forgotten "NAT: ssh -> web" rule
_FW_PID = 1000 + _util.stable_int("filterlog-pid") % 60000
_IFACE = "ens192"
_NEW_ACCOUNT = "svc-backup"


def _state(out: Path) -> dict:
    p = out / ".siemgen-state.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except (OSError, ValueError):
            pass
    return {}


def build(org, seed: int, end: datetime) -> dict[str, list[tuple[datetime, str]]]:
    """Return {relative file path: [(timestamp, line), ...]} for the scenario,
    with the last event at `end`."""
    rng = random.Random(f"incident:outside-login:{seed}")
    web = org.server("web") or org.linux_servers()[0]
    web_short = _util.short(web.name)
    admins = sorted((u for u in org.users if u.role == "it-admin"), key=lambda u: u.username)
    victim = rng.choice(admins) if admins else sorted(org.users, key=lambda u: u.username)[0]
    attackers = [ip for ip in org.external_malicious if not ip.startswith(("192.0.2.", "198.51.100.", "203.0.113."))]
    attacker = rng.choice(attackers or ["185.220.101.45"])
    uid = LinuxAuth._uid(victim)
    sshd_base = rng.randint(20000, 60000)

    t0 = end - timedelta(seconds=230)
    auth: list[tuple[datetime, str]] = []
    fw: list[tuple[datetime, str]] = []
    eve: list[tuple[datetime, str]] = []

    def auth_line(ts, proc, msg):
        auth.append((ts, f"{_util.syslog_ts(ts)} {web_short} {proc}: {msg}"))

    def fw_pass(ts, sport):
        length = rng.randint(52, 60)
        csv = [str(_FW_RULE), "", "", str(_FW_TRACKER), "igb0", "match", "pass", "in", "4", "0x0", "",
               str(rng.randint(40, 56)), str(rng.randint(1, 65535)), "0", "DF", "6", "tcp", str(length),
               attacker, org.egress_ip, str(sport), "22", str(length - 40), "S",
               str(rng.randint(1, 4_000_000_000)), "", str(rng.choice([64240, 65535, 29200])), "",
               "mss;sackOK;TS;nop;wscale"]
        fw.append((ts, f"{_util.syslog_ts(ts)} pfsense filterlog[{_FW_PID}]: {','.join(csv)}"))

    def flow(ts, sport, age, up, down):
        e = {
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
            "flow_id": rng.randint(10**14, 10**15), "in_iface": _IFACE, "event_type": "flow",
            "src_ip": attacker, "src_port": sport, "dest_ip": web.ip, "dest_port": 22,
            "proto": "TCP", "app_proto": "ssh",
            "flow": {"pkts_toserver": max(1, up // 120), "pkts_toclient": max(1, down // 120),
                     "bytes_toserver": up, "bytes_toclient": down,
                     "start": _util.iso(ts), "end": _util.iso(ts + timedelta(seconds=age)),
                     "age": age, "state": "closed", "reason": "shutdown"},
            "community_id": _util.community_id(attacker, web.ip, sport, 22, "tcp"),
            "tcp": {"tcp_flags": "1b", "tcp_flags_ts": "1b", "tcp_flags_tc": "1b",
                    "syn": True, "fin": True, "psh": True, "ack": True, "state": "closed"},
        }
        eve.append((ts, json.dumps(e)))

    # -- 1+2: the guessing, ~36 connections in two minutes -------------------------
    names = [rng.choice(_INVALID_USERS) for _ in range(28)] + [victim.username] * 8
    ts = t0
    for i, name in enumerate(names):
        sport = rng.randint(32768, 60999)
        pid = sshd_base + i
        fw_pass(ts, sport)
        flow(ts, sport, rng.randint(2, 4), rng.randint(1800, 2600), rng.randint(2200, 3200))
        invalid = name != victim.username
        if invalid:
            auth_line(ts, f"sshd[{pid}]", f"Invalid user {name} from {attacker} port {sport}")
        who = f"invalid user {name}" if invalid else name
        auth_line(ts, f"sshd[{pid}]", f"Failed password for {who} from {attacker} port {sport} ssh2")
        auth_line(ts + timedelta(seconds=2), f"sshd[{pid}]",
                  f"Connection closed by {'invalid' if invalid else 'authenticating'} user {name} "
                  f"{attacker} port {sport} [preauth]")
        ts += timedelta(seconds=rng.uniform(2.6, 4.0))

    # -- 3: success ------------------------------------------------------------------
    ts = t0 + timedelta(seconds=140)
    sport = rng.randint(32768, 60999)
    pid = sshd_base + len(names)
    session = rng.randint(800, 4000)
    logind = 1000 + _util.stable_int("logind", web.name) % 3000
    fw_pass(ts, sport)
    auth_line(ts, f"sshd[{pid}]", f"Accepted password for {victim.username} from {attacker} port {sport} ssh2")
    auth_line(ts, f"sshd[{pid}]", f"pam_unix(sshd:session): session opened for user {victim.username}(uid={uid}) by (uid=0)")
    auth_line(ts, f"systemd-logind[{logind}]", f"New session {session} of user {victim.username}.")

    # -- 4: what it does as root -----------------------------------------------------
    tty = f"pts/{rng.randint(1, 6)}"
    for dt_s, cmd in ((25, "/usr/bin/cat /etc/shadow"),
                      (48, f"/usr/sbin/useradd -m -s /bin/bash -G sudo {_NEW_ACCOUNT}"),
                      (61, f"/usr/bin/passwd {_NEW_ACCOUNT}")):
        t = ts + timedelta(seconds=dt_s)
        auth_line(t, "sudo", f"{victim.username} : TTY={tty} ; PWD=/home/{victim.username} ; USER=root ; COMMAND={cmd}")
        auth_line(t, "sudo", f"pam_unix(sudo:session): session opened for user root(uid=0) by {victim.username}(uid={uid})")
        auth_line(t + timedelta(seconds=1), "sudo", "pam_unix(sudo:session): session closed for user root")

    # -- disconnect at `end` -------------------------------------------------------------
    auth_line(end, f"sshd[{pid}]", f"Received disconnect from {attacker} port {sport}:11: disconnected by user")
    auth_line(end, f"sshd[{pid}]", f"Disconnected from user {victim.username} {attacker} port {sport}")
    auth_line(end, f"sshd[{pid}]", f"pam_unix(sshd:session): session closed for user {victim.username}")
    auth_line(end, f"systemd-logind[{logind}]", f"Removed session {session}.")
    age = int((end - ts).total_seconds())
    flow(ts, sport, age, rng.randint(9000, 16000), rng.randint(40000, 90000))

    meta = {"attacker": attacker, "victim": victim.username, "victim_department": victim.department,
            "server": web.name, "server_ip": web.ip, "public_ip": org.egress_ip,
            "attempts": len(names), "start": t0, "end": end, "new_account": _NEW_ACCOUNT}
    return {"auth.log": sorted(auth, key=lambda x: x[0]),
            "pfsense/filterlog.log": sorted(fw, key=lambda x: x[0]),
            "suricata/eve.json": sorted(eve, key=lambda x: x[0]),
            "_meta": meta}


def run(cfg, org, args) -> int:
    out = Path(args.out or os.environ.get("SIEMGEN_OUT") or (cfg.get("output", {}) or {}).get("base_dir") or "./logs")
    seed = int(cfg.get("seed", 1337))
    end = datetime.now(timezone.utc).replace(tzinfo=None)
    plan = build(org, seed, end)
    meta = plan.pop("_meta")

    if not args.dry_run:
        missing = [f for f in plan if not (out / f).parent.exists()]
        if missing:
            print(f"[siemgen] ERROR: {out.resolve()} does not look like a generator output folder "
                  f"(missing {', '.join(missing)}). Start the generator first.", file=sys.stderr)
            return 1

    print(f"[siemgen] incident 'outside-login' -> {out.resolve()}")
    if args.live:
        # replay in real time: rewrite the timestamps so the scenario starts now
        shift = datetime.now(timezone.utc).replace(tzinfo=None) - meta["start"]
        print(f"[siemgen] live replay, about {int((meta['end'] - meta['start']).total_seconds())} s. Ctrl-C stops it.")
        plan = build(org, seed, meta["end"] + shift)
        plan.pop("_meta")
        events = sorted(((ts, f, line) for f, rows in plan.items() for ts, line in rows), key=lambda x: x[0])
        try:
            for ts, f, line in events:
                delay = (ts - datetime.now(timezone.utc).replace(tzinfo=None)).total_seconds()
                if delay > 0:
                    time.sleep(delay)
                with open(out / f, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
        except KeyboardInterrupt:
            print("\n[siemgen] stopped: the scenario was only partly written.")
            return 130
    else:
        for f, rows in plan.items():
            text = "".join(line + "\n" for _, line in rows)
            if args.dry_run:
                print(f"--- {f} ({len(rows)} lines)")
                sys.stdout.write(text)
            else:
                with open(out / f, "a", encoding="utf-8") as fh:
                    fh.write(text)

    n = sum(len(r) for r in plan.values())
    print(f"[siemgen] {'would write' if args.dry_run else 'wrote'} {n} lines "
          + ", ".join(f"{f}: {len(r)}" for f, r in plan.items()))
    print(f"[siemgen] window (UTC): {meta['start']:%Y-%m-%d %H:%M:%S} .. {meta['end']:%H:%M:%S}")
    if args.reveal:
        print("[siemgen] instructor view: " + ", ".join(f"{k}={v}" for k, v in meta.items()
                                                       if k not in ("start", "end")))
    print("[siemgen] done. Give your rules a few minutes (the next run of each rule), then check Security -> Alerts.")
    return 0
