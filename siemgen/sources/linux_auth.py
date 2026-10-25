"""Linux authentication log (/var/log/auth.log, Debian/Ubuntu rsyslog format).

What a real auth.log contains during a normal day, and what is emitted here:

  * sshd: ``Accepted publickey/password ...`` (with key type + fingerprint),
    ``Failed password ...`` (incl. ``invalid user``), the matching
    ``pam_unix(sshd:session): session opened/closed`` lines and the
    ``Disconnected from user ...`` line when the session ends;
  * sudo: the command line (``TTY= ; PWD= ; USER= ; COMMAND=``) followed by its
    ``pam_unix(sudo:session)`` open/close pair;
  * su: ``(to root) user on pts/N`` + pam session open, and the close later;
  * CRON: the ``pam_unix(cron:session)`` open/close pair for root and for service
    accounts, the background noise every Linux box has;
  * systemd-logind: ``New session N of user X.`` / ``Removed session N.``.

A logical action may span several syslog lines (``render_native`` joins them with
newlines, exactly as the file shows them). When the lines are far apart in time (an
SSH session that closes an hour later) the source returns TWO events so the file
stays chronological, like a real log.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta

from .. import ECS_VERSION
from ..org.model import Host, Org, User
from . import _util
from .base import LogEvent, Source

_KEY_TYPES = ["ED25519", "RSA", "ECDSA"]
_SUDO_CMDS = [
    "/usr/bin/systemctl restart nginx", "/usr/bin/systemctl status docker",
    "/usr/bin/apt update", "/usr/bin/apt upgrade -y", "/usr/bin/journalctl -u sshd -n 50",
    "/usr/bin/tail -f /var/log/syslog", "/usr/bin/docker ps", "/usr/bin/docker compose up -d",
    "/usr/sbin/ufw status", "/usr/bin/less /var/log/auth.log", "/usr/bin/vim /etc/hosts",
    "/usr/bin/cat /etc/ssh/sshd_config", "/usr/bin/tcpdump -i eth0 -c 100",
    "/usr/bin/du -sh /var/lib/docker", "/usr/bin/systemctl restart postgresql",
]
_FAKE_USERS = ["admin", "test", "ubuntu", "oracle", "postgres", "git", "deploy", "user"]
_SERVICE_ACCOUNTS = [("root", 0), ("root", 0), ("root", 0), ("root", 0),
                     ("www-data", 33), ("postgres", 114), ("backup", 34)]


def _fingerprint(rng: random.Random) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return "SHA256:" + "".join(rng.choice(alphabet) for _ in range(43))


class LinuxAuth(Source):
    name = "linux_auth"
    dataset = "system.auth"

    def daily_volume(self, user: User, rng: random.Random) -> int:
        # admins log in a lot more (jump to servers); office users a few times
        base = 14 if user.role == "it-admin" else 4
        return max(1, int(rng.gauss(base, base * 0.5)))

    def applies_to(self, user: User, host: Host) -> bool:
        return host.os == "linux" or user.role in ("it-admin", "ops")

    def activity_weight(self, user: User) -> float:
        return 1.5 if user.role == "it-admin" else 0.3

    # -- helpers ------------------------------------------------------------
    @staticmethod
    def _uid(user: User) -> int:
        return 1000 + _util.stable_int("uid", user.username) % 4000

    @staticmethod
    def _target(user: User, host: Host, org: Org, rng: random.Random) -> Host:
        # admins mostly SSH into servers; others log into their own workstation
        if user.role == "it-admin" and org.linux_servers() and rng.random() < 0.7:
            return rng.choice(org.linux_servers())
        return host

    def _ev(self, ts: datetime, **fields) -> LogEvent:
        return LogEvent(timestamp=ts, source=self.name, fields=fields)

    # -- builders -----------------------------------------------------------
    def _ssh_session(self, user: User, host: Host, ts: datetime, target: Host,
                     rng: random.Random, method: str, duration: int | None = None) -> list[LogEvent]:
        """Accepted logon now + the disconnect `duration` seconds later (two events)."""
        common = dict(user=user.username, uid=self._uid(user), src_ip=host.ip,
                      port=rng.randint(40000, 65000), target_host=target.name,
                      pid=rng.randint(1000, 60000), logind_pid=rng.randint(500, 1500),
                      session=rng.randint(1, 900))
        dur = duration if duration is not None else rng.randint(20, 5400)
        return [
            self._ev(ts, kind="ssh_accept", method=method, key_type=rng.choice(_KEY_TYPES),
                     fingerprint=_fingerprint(rng), outcome="success", **common),
            self._ev(ts + timedelta(seconds=dur), kind="ssh_close", outcome="success", **common),
        ]

    def _ssh_fail(self, user: User, host: Host, ts: datetime, target: Host,
                  rng: random.Random) -> LogEvent:
        invalid = rng.random() < 0.3
        return self._ev(ts, kind="ssh_fail", outcome="failure", method="password",
                        user=rng.choice(_FAKE_USERS) if invalid else user.username,
                        invalid=invalid, src_ip=host.ip, port=rng.randint(40000, 65000),
                        target_host=target.name, pid=rng.randint(1000, 60000))

    def _sudo(self, user: User, host: Host, ts: datetime, target: Host, rng: random.Random) -> LogEvent:
        return self._ev(ts, kind="sudo", user=user.username, uid=self._uid(user),
                        target_host=target.name, tty=f"pts/{rng.randint(0, 6)}",
                        pwd=rng.choice([f"/home/{user.username}", "/", "/var/log", "/etc", "/opt"]),
                        command=rng.choice(_SUDO_CMDS), pid=rng.randint(1000, 60000))

    def _su(self, user: User, host: Host, ts: datetime, target: Host, rng: random.Random) -> list[LogEvent]:
        common = dict(user=user.username, uid=self._uid(user), target_host=target.name,
                      tty=f"pts/{rng.randint(0, 6)}", pid=rng.randint(1000, 60000))
        return [self._ev(ts, kind="su_open", **common),
                self._ev(ts + timedelta(seconds=rng.randint(15, 600)), kind="su_close", **common)]

    def _cron(self, host: Host, ts: datetime, rng: random.Random) -> LogEvent:
        who, uid = rng.choice(_SERVICE_ACCOUNTS)
        return self._ev(ts, kind="cron", user=who, uid=uid, target_host=host.name,
                        pid=rng.randint(1000, 60000))

    def make_event(self, user: User, host: Host, ts: datetime, org: Org,
                   rng: random.Random, persona=None):
        target = self._target(user, host, org, rng)
        roll = rng.random()
        admin = user.role in ("it-admin", "ops")
        if roll < 0.40:
            if rng.random() < 0.93:
                method = rng.choices(["publickey", "password"], weights=[0.7, 0.3], k=1)[0]
                return self._ssh_session(user, host, ts, target, rng, method)
            return self._ssh_fail(user, host, ts, target, rng)
        if roll < 0.72 and admin:
            return self._sudo(user, host, ts, target, rng)
        if roll < 0.78 and admin:
            return self._su(user, host, ts, target, rng)
        return self._cron(target if admin else host, ts, rng)

    def login_event(self, user: User, host: Host, ts: datetime, org: Org,
                    rng: random.Random, persona=None) -> LogEvent:
        """A successful interactive logon to the user's own workstation (arrival).
        The matching session close is not modelled (the user stays logged in)."""
        return self._ssh_session(user, host, ts, host, rng, "publickey", duration=0)[0]

    # -- rendering ----------------------------------------------------------
    def render_native(self, ev: LogEvent) -> str:
        f = ev.fields
        h = _util.short(f["target_host"])
        ts = ev.timestamp

        def line(t: datetime, proc: str, msg: str) -> str:
            return f"{_util.syslog_ts(t)} {h} {proc}: {msg}"

        kind = f["kind"]
        if kind == "ssh_accept":
            sshd = f'sshd[{f["pid"]}]'
            if f["method"] == "publickey":
                acc = (f'Accepted publickey for {f["user"]} from {f["src_ip"]} port {f["port"]} '
                       f'ssh2: {f["key_type"]} {f["fingerprint"]}')
            else:
                acc = f'Accepted password for {f["user"]} from {f["src_ip"]} port {f["port"]} ssh2'
            return "\n".join([
                line(ts, sshd, acc),
                line(ts, sshd, f'pam_unix(sshd:session): session opened for user '
                               f'{f["user"]}(uid={f["uid"]}) by (uid=0)'),
                line(ts, f'systemd-logind[{f["logind_pid"]}]',
                     f'New session {f["session"]} of user {f["user"]}.'),
            ])
        if kind == "ssh_close":
            sshd = f'sshd[{f["pid"]}]'
            return "\n".join([
                line(ts, sshd, f'Received disconnect from {f["src_ip"]} port {f["port"]}:11: '
                               f'disconnected by user'),
                line(ts, sshd, f'Disconnected from user {f["user"]} {f["src_ip"]} port {f["port"]}'),
                line(ts, sshd, f'pam_unix(sshd:session): session closed for user {f["user"]}'),
                line(ts, f'systemd-logind[{f["logind_pid"]}]', f'Removed session {f["session"]}.'),
            ])
        if kind == "ssh_fail":
            sshd = f'sshd[{f["pid"]}]'
            who = f'{"invalid user " if f["invalid"] else ""}{f["user"]}'
            out = []
            if f["invalid"]:
                out.append(line(ts, sshd, f'Invalid user {f["user"]} from {f["src_ip"]} port {f["port"]}'))
            out.append(line(ts, sshd, f'Failed password for {who} from {f["src_ip"]} port {f["port"]} ssh2'))
            out.append(line(ts + timedelta(seconds=2), sshd,
                            f'Connection closed by {"invalid" if f["invalid"] else "authenticating"} '
                            f'user {f["user"]} {f["src_ip"]} port {f["port"]} [preauth]'))
            return "\n".join(out)
        if kind == "sudo":
            end = ts + timedelta(seconds=1)
            return "\n".join([
                line(ts, "sudo", f'{f["user"]} : TTY={f["tty"]} ; PWD={f["pwd"]} ; USER=root ; '
                                 f'COMMAND={f["command"]}'),
                line(ts, "sudo", f'pam_unix(sudo:session): session opened for user root(uid=0) by '
                                 f'{f["user"]}(uid={f["uid"]})'),
                line(end, "sudo", 'pam_unix(sudo:session): session closed for user root'),
            ])
        if kind == "su_open":
            return "\n".join([
                line(ts, f'su[{f["pid"]}]', f'(to root) {f["user"]} on {f["tty"]}'),
                line(ts, f'su[{f["pid"]}]', f'pam_unix(su:session): session opened for user root(uid=0) by '
                                            f'{f["user"]}(uid={f["uid"]})'),
            ])
        if kind == "su_close":
            return line(ts, f'su[{f["pid"]}]', 'pam_unix(su:session): session closed for user root')
        # cron
        return "\n".join([
            line(ts, f'CRON[{f["pid"]}]', f'pam_unix(cron:session): session opened for user '
                                          f'{f["user"]}(uid={f["uid"]}) by (uid=0)'),
            line(ts + timedelta(seconds=1), f'CRON[{f["pid"]}]',
                 f'pam_unix(cron:session): session closed for user {f["user"]}'),
        ])

    def render_ecs(self, ev: LogEvent) -> dict:
        f = ev.fields
        kind = f["kind"]
        doc = {
            "@timestamp": _util.iso(ev.timestamp),
            "ecs": {"version": ECS_VERSION},
            "event": {"kind": "event", "dataset": self.dataset, "module": "system"},
            "data_stream": _util.ds(self.dataset),
            "host": {"name": f["target_host"], "os": {"type": "linux"}},
            "user": {"name": f["user"]},
            "related": {"user": [f["user"]], "hosts": [f["target_host"]]},
            "message": self.render_native(ev).split("\n")[0],
        }
        if kind.startswith("ssh"):
            doc["event"].update({
                "category": ["authentication"],
                "type": ["end"] if kind == "ssh_close" else ["start"],
                "action": {"ssh_accept": "ssh_login", "ssh_close": "ssh_logout",
                           "ssh_fail": "ssh_login"}[kind],
                "outcome": f["outcome"]})
            doc["source"] = {"ip": f["src_ip"], "port": f["port"]}
            doc["process"] = {"name": "sshd", "pid": f["pid"]}
            doc["related"]["ip"] = [f["src_ip"]]
            if "uid" in f:
                doc["user"]["id"] = str(f["uid"])
        elif kind == "sudo":
            doc["event"].update({"category": ["process"], "type": ["start"],
                                 "action": "sudo", "outcome": "success"})
            doc["process"] = {"name": "sudo", "command_line": f["command"],
                              "executable": f["command"].split(" ")[0]}
            doc["user"].update({"id": str(f["uid"]), "effective": {"name": "root", "id": "0"}})
        elif kind.startswith("su_"):
            doc["event"].update({"category": ["authentication"],
                                 "type": ["end"] if kind == "su_close" else ["start"],
                                 "action": "su", "outcome": "success"})
            doc["process"] = {"name": "su", "pid": f["pid"]}
            doc["user"].update({"id": str(f["uid"]), "effective": {"name": "root", "id": "0"}})
        else:
            doc["event"].update({"category": ["session"], "type": ["start"],
                                 "action": "cron_session", "outcome": "success"})
            doc["process"] = {"name": "cron", "pid": f["pid"]}
            doc["user"]["id"] = str(f["uid"])
        if ev.labels:
            doc["labels"] = ev.labels
        return doc
