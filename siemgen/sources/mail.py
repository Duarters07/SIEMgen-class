"""Postfix mail log (/var/log/mail.log) — one message = a chain of syslog lines from
several Postfix daemons sharing the same queue id:

  outbound:  smtpd client=  ->  cleanup message-id=  ->  qmgr from= size= nrcpt=
             ->  smtp to= relay= delay= delays= dsn= status=  ->  qmgr removed
  inbound:   smtpd connect from  ->  smtpd client=  ->  cleanup  ->  qmgr  ->
             local/lmtp to= status=sent (delivered to mailbox)  ->  qmgr removed
             ->  smtpd disconnect from

Correlating the chain by queue id is the classic Postfix parsing exercise."""
from __future__ import annotations

import random
from datetime import datetime, timedelta

from .. import ECS_VERSION
from ..org.model import Host, Org, User
from . import _util
from .base import LogEvent, Source

_EXTERNAL = [("gmail.com", "gmail-smtp-in.l.google.com", "142.250.27.27"),
             ("outlook.com", "outlook-com.olc.protection.outlook.com", "52.101.8.7"),
             ("partner.example", "mx1.partner.example", "203.0.113.25"),
             ("supplier.example", "mail.supplier.example", "198.51.100.40"),
             ("client.example", "mx.client.example", "192.0.2.77"),
             ("newsletter.example", "mta3.newsletter.example", "198.51.100.120")]
_LOCALPARTS = ["info", "sales", "jane", "team", "noreply", "support", "billing", "john.smith"]
_STATUS = {
    "sent": ("2.0.0", "250 2.0.0 OK  {t} - gsmtp"),
    "deferred": ("4.4.1", "connect to {relay}[{ip}]:25: Connection timed out"),
    "bounced": ("5.1.1", "host {relay}[{ip}] said: 550 5.1.1 The email account that you tried to reach does not exist (in reply to RCPT TO command)"),
}


class MailGateway(Source):
    name = "mail"
    dataset = "postfix.log"

    def __init__(self) -> None:
        self.mail_host = "mail"
        self.dns_domain = "acme.local"

    def bind(self, org: Org) -> None:
        super().bind(org)
        self.dns_domain = org.dns_domain

    def daily_volume(self, user: User, rng: random.Random) -> int:
        return max(1, int(rng.gauss(10, 4)))

    def activity_weight(self, user: User) -> float:
        return 1.0

    def make_event(self, user: User, host: Host, ts: datetime, org: Org,
                   rng: random.Random, persona=None) -> LogEvent:
        outbound = rng.random() < 0.5
        dom, relay, relay_ip = rng.choice(_EXTERNAL)
        ext = f"{rng.choice(_LOCALPARTS)}@{dom}"
        if outbound:
            frm, to = user.email, ext
            status = rng.choices(["sent", "deferred", "bounced"], weights=[0.94, 0.04, 0.02], k=1)[0]
        else:
            frm, to = ext, user.email
            status = "sent"
        return LogEvent(timestamp=ts, source=self.name, fields={
            "from": frm, "to": to, "status": status, "outbound": outbound,
            "qid": _util.rhex(rng, 10).upper(), "size": rng.randint(800, 250000),
            "relay": relay, "relay_ip": relay_ip, "ext_domain": dom,
            "client_host": _util.short(host.name), "client_ip": host.ip,
            "pids": [rng.randint(1000, 30000) for _ in range(5)],
            "msgid": f"<{_util.rhex(rng, 16)}@{dom if not outbound else self.dns_domain}>",
            "delay": round(rng.uniform(0.3, 4.0), 2),
        })

    def render_native(self, ev: LogEvent) -> str:
        f = ev.fields
        h = self.mail_host
        p = f["pids"]
        q = f["qid"]
        t0 = ev.timestamp
        t1 = t0 + timedelta(seconds=max(1, int(f["delay"])))

        def line(ts: datetime, proc: str, pid: int, msg: str) -> str:
            return f"{_util.syslog_ts(ts)} {h} postfix/{proc}[{pid}]: {msg}"

        dsn, resp = _STATUS[f["status"]]
        resp = resp.format(t=str(int(t1.timestamp())), relay=f["relay"], ip=f["relay_ip"])
        if f["outbound"]:
            lines = [
                line(t0, "smtpd", p[0], f'{q}: client={f["client_host"]}.{self.dns_domain}[{f["client_ip"]}], '
                                        f'sasl_method=PLAIN, sasl_username={f["from"]}'),
                line(t0, "cleanup", p[1], f'{q}: message-id={f["msgid"]}'),
                line(t0, "qmgr", p[2], f'{q}: from=<{f["from"]}>, size={f["size"]}, nrcpt=1 (queue active)'),
                line(t1, "smtp", p[3], f'{q}: to=<{f["to"]}>, relay={f["relay"]}[{f["relay_ip"]}]:25, '
                                       f'delay={f["delay"]}, delays=0.05/0.01/{f["delay"] * 0.4:.2f}/{f["delay"] * 0.5:.2f}, '
                                       f'dsn={dsn}, status={f["status"]} ({resp})'),
            ]
            if f["status"] != "deferred":
                lines.append(line(t1, "qmgr", p[2], f'{q}: removed'))
            return "\n".join(lines)
        lines = [
            line(t0, "smtpd", p[0], f'connect from {f["relay"]}[{f["relay_ip"]}]'),
            line(t0, "smtpd", p[0], f'{q}: client={f["relay"]}[{f["relay_ip"]}]'),
            line(t0, "cleanup", p[1], f'{q}: message-id={f["msgid"]}'),
            line(t0, "qmgr", p[2], f'{q}: from=<{f["from"]}>, size={f["size"]}, nrcpt=1 (queue active)'),
            line(t1, "lmtp", p[3], f'{q}: to=<{f["to"]}>, relay={h}.{self.dns_domain}[private/dovecot-lmtp], '
                                   f'delay={f["delay"]}, delays={f["delay"] * 0.8:.2f}/0.01/0.01/{f["delay"] * 0.2:.2f}, '
                                   f'dsn=2.0.0, status=sent (250 2.0.0 <{f["to"]}> {q} Saved)'),
            line(t1, "qmgr", p[2], f'{q}: removed'),
            line(t1, "smtpd", p[0], f'disconnect from {f["relay"]}[{f["relay_ip"]}] ehlo=1 mail=1 rcpt=1 data=1 quit=1 commands=5'),
        ]
        return "\n".join(lines)

    def render_ecs(self, ev: LogEvent) -> dict:
        f = ev.fields
        doc = {
            "@timestamp": _util.iso(ev.timestamp),
            "ecs": {"version": ECS_VERSION},
            "event": {
                "kind": "event", "category": ["email"], "type": ["info"],
                "action": f["status"],
                "outcome": "success" if f["status"] == "sent" else "failure",
                "dataset": self.dataset, "module": "postfix",
                "id": f["qid"],
            },
            "data_stream": _util.ds(self.dataset),
            "host": {"name": f"{self.mail_host}.{self.dns_domain}"},
            "source": {"user": {"email": f["from"]},
                       "ip": f["client_ip"] if f["outbound"] else f["relay_ip"]},
            "destination": {"user": {"email": f["to"]}},
            "email": {"from": {"address": [f["from"]]}, "to": {"address": [f["to"]]},
                      "message_id": f["msgid"].strip("<>"),
                      "direction": "outbound" if f["outbound"] else "inbound"},
            "related": {"user": [f["from"], f["to"]],
                        "ip": [f["client_ip"] if f["outbound"] else f["relay_ip"]]},
            "message": self.render_native(ev).split("\n")[-2 if f["status"] != "deferred" else -1],
        }
        if ev.labels:
            doc["labels"] = ev.labels
        return doc
