"""Linux auditd log (/var/log/audit/audit.log) — benign process execution.

A single ``execve`` produces a GROUP of records that share the same
``msg=audit(<epoch>:<serial>)`` key, in this order:

    type=SYSCALL   ... syscall=59 success=yes ... comm="ls" exe="/usr/bin/ls" key="exec"
    type=EXECVE    ... argc=2 a0="ls" a1="-la"
    type=CWD       ... cwd="/home/user"
    type=PATH      ... item=0 name="/usr/bin/ls" inode=... mode=0100755 ...
    type=PATH      ... item=1 name="/lib64/ld-linux-x86-64.so.2" ...
    type=PROCTITLE ... proctitle=6C73002D6C61          (hex-encoded argv)

Reassembling the group by the audit serial is the classic auditd parsing exercise,
so the emitter renders the whole group, not just the SYSCALL line."""
from __future__ import annotations

import random
from datetime import datetime, timedelta

from .. import ECS_VERSION
from ..org.model import Host, Org, User
from . import _util
from .base import LogEvent, Source

# (executable, argv list)  — ordinary day-to-day commands
_PROGRAMS = [
    ("/usr/bin/ls", ["ls", "-la"]), ("/usr/bin/ls", ["ls", "--color=auto"]),
    ("/usr/bin/cat", ["cat", "/etc/hosts"]), ("/usr/bin/grep", ["grep", "-r", "TODO", "."]),
    ("/usr/bin/python3", ["python3", "main.py"]), ("/usr/bin/python3", ["python3", "-m", "pytest"]),
    ("/usr/bin/git", ["git", "status"]), ("/usr/bin/git", ["git", "pull", "--rebase"]),
    ("/usr/bin/git", ["git", "commit", "-m", "wip"]), ("/usr/bin/ssh", ["ssh", "web"]),
    ("/usr/bin/vim", ["vim", "notes.md"]), ("/usr/bin/cp", ["cp", "report.pdf", "/tmp/"]),
    ("/usr/bin/curl", ["curl", "-s", "https://api.github.com"]), ("/usr/bin/find", ["find", ".", "-name", "*.log"]),
    ("/usr/bin/tar", ["tar", "czf", "backup.tgz", "src"]), ("/usr/bin/bash", ["bash"]),
    ("/usr/bin/sed", ["sed", "-i", "s/foo/bar/", "config.yaml"]), ("/usr/bin/less", ["less", "/var/log/syslog"]),
    ("/usr/bin/id", ["id"]), ("/usr/bin/uname", ["uname", "-a"]), ("/usr/bin/whoami", ["whoami"]),
    ("/usr/bin/ps", ["ps", "aux"]), ("/usr/bin/df", ["df", "-h"]), ("/usr/bin/awk", ["awk", "{print $1}"]),
]
_ADMIN_PROGRAMS = [
    ("/usr/bin/sudo", ["sudo", "systemctl", "restart", "nginx"]), ("/usr/bin/systemctl", ["systemctl", "status", "docker"]),
    ("/usr/bin/ansible-playbook", ["ansible-playbook", "site.yml"]), ("/usr/bin/apt", ["apt", "list", "--upgradable"]),
    ("/usr/bin/docker", ["docker", "ps"]), ("/usr/bin/docker", ["docker", "logs", "-f", "api"]),
    ("/usr/bin/journalctl", ["journalctl", "-u", "sshd", "-n", "50"]), ("/usr/bin/ip", ["ip", "a"]),
    ("/usr/bin/ss", ["ss", "-tulpn"]), ("/usr/bin/tcpdump", ["tcpdump", "-i", "eth0", "-c", "100"]),
]
_LOADER = "/usr/lib64/ld-linux-x86-64.so.2"


def _hex(s: str) -> str:
    return s.encode().hex().upper()


class LinuxAuditd(Source):
    name = "auditd"
    dataset = "linux.audit"

    def daily_volume(self, user: User, rng: random.Random) -> int:
        return max(1, int(rng.gauss(45, 15)))

    def applies_to(self, user: User, host: Host) -> bool:
        return host.os == "linux"

    def activity_weight(self, user: User) -> float:
        return 3.0

    def make_event(self, user: User, host: Host, ts: datetime, org: Org,
                   rng: random.Random, persona=None) -> LogEvent:
        pool = _PROGRAMS + (_ADMIN_PROGRAMS if user.role in ("it-admin", "ops") else [])
        exe, argv = rng.choice(pool)
        comm = argv[0]
        uid = 1000 + _util.stable_int("uid", user.username) % 4000
        euid = 0 if comm in ("sudo", "systemctl") and rng.random() < 0.5 else uid
        return LogEvent(timestamp=ts, source=self.name, fields={
            "exe": exe, "comm": comm, "argv": argv, "uid": uid, "euid": euid, "auid": uid,
            "pid": rng.randint(1000, 60000), "ppid": rng.randint(500, 4000),
            "syscall": 59, "seq": rng.randint(100, 999999), "user": user.username,
            "host": host.name, "tty": f"pts{rng.randint(0, 5)}", "ses": rng.randint(1, 900),
            "cwd": rng.choice([f"/home/{user.username}", f"/home/{user.username}/src",
                               "/opt/app", "/var/log", "/tmp"]),
            "inode": rng.randint(100000, 9999999), "dev": rng.choice(["fd:01", "08:01", "fc:02"]),
        })

    def minute_events(self, user: User, host: Host, ts: datetime, org: Org,
                      rng: random.Random, rates: dict) -> list[LogEvent]:
        """One working minute of Linux process-execution telemetry (the endpoint
        volume driver on Linux hosts, mirroring Windows 4688)."""
        out: list[LogEvent] = []
        for _ in range(_util.jit(rng, rates.get("exec_per_min", 10))):
            tt = ts + timedelta(seconds=rng.randint(0, 59), microseconds=rng.randint(0, 999999))
            out.append(self.make_event(user, host, tt, org, rng))
        return out

    def render_native(self, ev: LogEvent) -> str:
        f = ev.fields
        key = f'msg=audit({ev.timestamp.timestamp():.3f}:{f["seq"]})'
        uid, euid = f["uid"], f["euid"]
        argv = f["argv"]
        syscall = (f'type=SYSCALL {key}: arch=c000003e syscall={f["syscall"]} success=yes exit=0 '
                   f'a0=55d2c3e4a2b0 a1=55d2c3e4a3f0 a2=55d2c3e4b6a0 a3=8 items=2 '
                   f'ppid={f["ppid"]} pid={f["pid"]} auid={f["auid"]} uid={uid} gid={uid} euid={euid} '
                   f'suid={euid} fsuid={euid} egid={uid} sgid={uid} fsgid={uid} tty={f["tty"]} '
                   f'ses={f["ses"]} comm="{f["comm"]}" exe="{f["exe"]}" '
                   f'subj=unconfined key="exec"')
        execve = f'type=EXECVE {key}: argc={len(argv)} ' + " ".join(
            f'a{i}="{a}"' for i, a in enumerate(argv))
        cwd = f'type=CWD {key}: cwd="{f["cwd"]}"'
        path0 = (f'type=PATH {key}: item=0 name="{f["exe"]}" inode={f["inode"]} dev={f["dev"]} '
                 f'mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 '
                 f'cap_fe=0 cap_fver=0 cap_frootid=0')
        path1 = (f'type=PATH {key}: item=1 name="{_LOADER}" inode={f["inode"] + 7} dev={f["dev"]} '
                 f'mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 '
                 f'cap_fe=0 cap_fver=0 cap_frootid=0')
        proctitle = f'type=PROCTITLE {key}: proctitle={_hex(chr(0).join(argv))}'
        return "\n".join([syscall, execve, cwd, path0, path1, proctitle])

    def render_ecs(self, ev: LogEvent) -> dict:
        f = ev.fields
        doc = {
            "@timestamp": _util.iso(ev.timestamp),
            "ecs": {"version": ECS_VERSION},
            "event": {
                "kind": "event", "category": ["process"], "type": ["start"],
                "action": "executed", "outcome": "success",
                "dataset": self.dataset, "module": "auditd",
                "sequence": f["seq"],
            },
            "data_stream": _util.ds(self.dataset),
            "host": {"name": f["host"], "os": {"type": "linux"}},
            "user": {"name": f["user"], "id": str(f["uid"]),
                     "effective": {"id": str(f["euid"])}, "audit": {"id": str(f["auid"])}},
            "process": {"executable": f["exe"], "name": f["comm"], "pid": f["pid"],
                        "args": list(f["argv"]), "args_count": len(f["argv"]),
                        "command_line": " ".join(f["argv"]),
                        "working_directory": f["cwd"], "parent": {"pid": f["ppid"]}},
            "auditd": {"log": {"sequence": f["seq"], "record_type": "SYSCALL"}},
            "related": {"user": [f["user"]], "hosts": [f["host"]]},
            "message": self.render_native(ev).split("\n")[0],
        }
        if ev.labels:
            doc["labels"] = ev.labels
        return doc
