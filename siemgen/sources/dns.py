"""DNS query log (dnsmasq ``log-queries`` format) — name resolution as users browse.

A lookup is a small group of lines sharing the same client IP:

    query[A] www.example.com from 10.10.7.11
    forwarded www.example.com to 1.1.1.1          (or: cached www.example.com is 1.2.3.4)
    reply www.example.com is 93.184.216.34        (or: reply ... is NXDOMAIN / <CNAME>)

Records carry the resolved answer so a name can be traced to the IP that the
subsequent Suricata flow / firewall pass uses — the DNS -> IP -> flow chain a real
pipeline exhibits. The leisure/work motors pass the session's destination IP so the
chain is consistent within a session."""
from __future__ import annotations

import random
from datetime import datetime

from .. import ECS_VERSION
from ..org.model import Host, Org, User
from . import _util
from .base import LogEvent, Source

_DOMAINS = [
    "google.com", "www.google.com", "microsoft.com", "login.microsoftonline.com",
    "office.com", "github.com", "api.github.com", "cloudflare.com", "amazonaws.com",
    "slack.com", "zoom.us", "atlassian.net", "salesforce.com", "linkedin.com",
    "fonts.googleapis.com", "cdn.jsdelivr.net", "ubuntu.com", "docker.io",
    "windowsupdate.com", "apple.com", "dropbox.com", "wikipedia.org",
]
_QTYPES = ["A", "A", "A", "AAAA", "HTTPS", "CNAME", "TXT", "PTR"]
# public IP ranges used to synthesize a plausible answer when none is supplied
_PUB_PREFIXES = ["142.250", "172.217", "20.190", "13.107", "104.16", "23.50", "52.96"]
_UPSTREAMS = ["1.1.1.1", "8.8.8.8"]


def _pub_ip(rng: random.Random) -> str:
    return f"{rng.choice(_PUB_PREFIXES)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


class DnsQueries(Source):
    name = "dns"
    dataset = "dns"

    def __init__(self) -> None:
        self.resolver_ip = "10.10.0.16"
        self.resolver_host = "dns"
        self.dns_domain = "acme.local"
        self.pid = 800 + _util.stable_int("dnsmasq-pid") % 5000

    def bind(self, org: Org) -> None:
        super().bind(org)
        self.resolver_ip = org.server_ip("dns", self.resolver_ip)
        self.dns_domain = org.dns_domain

    def daily_volume(self, user: User, rng: random.Random) -> int:
        return max(1, int(rng.gauss(90, 30)))

    def activity_weight(self, user: User) -> float:
        return 5.0

    def _fields(self, host: Host, domain: str, qtype: str, resolved_ip: str | None,
                rng: random.Random) -> dict:
        internal = domain.endswith(self.dns_domain)
        # ~3% of lookups fail (NXDOMAIN); A/AAAA answers carry an IP
        if rng.random() < 0.03 and not internal:
            rcode, answers, path = "NXDOMAIN", [], "forwarded"
        else:
            rcode = "NOERROR"
            if internal:
                ip = resolved_ip or (self.org.host(domain).ip if getattr(self, "org", None)
                                     and self.org.host(domain) else "10.10.0.10")
                path = "config"
            else:
                ip = resolved_ip or (_pub_ip(rng) if qtype in ("A", "AAAA") else None)
                path = "cached" if rng.random() < 0.35 else "forwarded"
            answers = [{"type": qtype, "data": ip}] if ip else []
        return {"qtype": qtype, "domain": domain, "src_ip": host.ip,
                "resolver": self.resolver_ip, "host": self.resolver_host, "pid": self.pid,
                "rcode": rcode, "answers": answers, "path": path,
                "upstream": rng.choice(_UPSTREAMS),
                "txid": rng.randint(1, 65535), "sport": rng.randint(1024, 65000)}

    def make_event(self, user: User, host: Host, ts: datetime, org: Org,
                   rng: random.Random, persona=None) -> LogEvent:
        if rng.random() < 0.2:
            domain = rng.choice([f"intranet.{org.dns_domain}", f"mail.{org.dns_domain}",
                                 org.web_host()])
        else:
            domain = rng.choice(_DOMAINS)
        qtype = rng.choice(_QTYPES)
        return LogEvent(timestamp=ts, source=self.name,
                        fields=self._fields(host, domain, qtype, None, rng))

    def query_event(self, host: Host, ts: datetime, domain: str, rng: random.Random,
                    labels: dict | None = None, qtype: str = "A",
                    resolved_ip: str | None = None) -> LogEvent:
        """A DNS lookup for a specific domain. `resolved_ip` (from the caller's session)
        becomes the answer, so DNS->flow share the same destination IP."""
        return LogEvent(timestamp=ts, source=self.name,
                        fields=self._fields(host, domain, qtype, resolved_ip, rng),
                        labels=labels or {})

    def render_native(self, ev: LogEvent) -> str:
        f = ev.fields
        head = f'{_util.syslog_ts(ev.timestamp)} {f["host"]} dnsmasq[{f["pid"]}]:'
        lines = [f'{head} query[{f["qtype"]}] {f["domain"]} from {f["src_ip"]}']
        ans = f["answers"][0]["data"] if f.get("answers") else None
        if f["path"] == "cached" and ans:
            lines.append(f'{head} cached {f["domain"]} is {ans}')
        elif f["path"] == "config" and ans:
            lines.append(f'{head} config {f["domain"]} is {ans}')
        else:
            lines.append(f'{head} forwarded {f["domain"]} to {f["upstream"]}')
            if f["rcode"] == "NXDOMAIN":
                lines.append(f'{head} reply {f["domain"]} is NXDOMAIN')
            elif ans:
                lines.append(f'{head} reply {f["domain"]} is {ans}')
        return "\n".join(lines)

    def render_ecs(self, ev: LogEvent) -> dict:
        f = ev.fields
        answers = f.get("answers") or []
        resolved = [a["data"] for a in answers if a.get("data")]
        doc = {
            "@timestamp": _util.iso(ev.timestamp),
            "ecs": {"version": ECS_VERSION},
            "event": {"kind": "event", "category": ["network"], "type": ["connection", "protocol"],
                      "action": "lookup", "outcome": "success" if f.get("rcode") == "NOERROR" else "failure",
                      "dataset": self.dataset, "module": "dnsmasq"},
            "data_stream": _util.ds(self.dataset),
            "source": {"ip": f["src_ip"]},
            "destination": {"ip": f["resolver"], "port": 53},
            "dns": {"id": str(f.get("txid", "")),
                    "question": {"name": f["domain"], "type": f["qtype"]},
                    "type": "answer" if answers else "query",
                    "response_code": f.get("rcode", "NOERROR"),
                    "answers": [{"data": a["data"], "type": a["type"]} for a in answers],
                    "resolved_ip": resolved},
            "network": {"protocol": "dns", "transport": "udp"},
            "related": {"ip": [f["src_ip"], f["resolver"]] + resolved, "hosts": [f["domain"]]},
            "message": (f'query[{f["qtype"]}] {f["domain"]} from {f["src_ip"]}'
                        + (f' -> {resolved[0]}' if resolved else f' ({f.get("rcode")})')),
        }
        cid = _util.community_id(f["src_ip"], f["resolver"], f.get("sport", 0), 53, "udp")
        if cid:
            doc["network"]["community_id"] = cid
        if ev.labels:
            doc["labels"] = ev.labels
        return doc
