"""ISC dhcpd server log (syslog) — lease renewal when a host comes online.

A renewal is the two-line ``DHCPREQUEST`` / ``DHCPACK`` exchange; a fresh boot is the
four-line ``DISCOVER / OFFER / REQUEST / ACK`` handshake. Both are rendered as the
server writes them, with a stable MAC per host."""
from __future__ import annotations

import random
from datetime import datetime

from .. import ECS_VERSION
from ..org.model import Host, Org, User
from . import _util
from .base import LogEvent, Source


class Dhcp(Source):
    name = "dhcp"
    dataset = "dhcp"

    def daily_volume(self, user: User, rng: random.Random) -> int:
        return max(1, int(rng.gauss(2, 1)))

    def activity_weight(self, user: User) -> float:
        return 0.0  # emitted at arrival (lease), not as random activity

    def lease_event(self, user: User, host: Host, ts: datetime, org: Org,
                    rng: random.Random, persona=None) -> LogEvent:
        # ~30% of arrivals are a cold boot (full DORA), the rest a renewal
        return self._event(host, ts, rng, full=rng.random() < 0.3)

    def make_event(self, user: User, host: Host, ts: datetime, org: Org,
                   rng: random.Random, persona=None) -> LogEvent:
        return self._event(host, ts, rng, full=False)

    def _event(self, host: Host, ts: datetime, rng: random.Random, full: bool) -> LogEvent:
        return LogEvent(timestamp=ts, source=self.name, fields={
            "ip": host.ip, "mac": _util.stable_mac(host.name), "hostname": _util.short(host.name),
            "pid": 700 + _util.stable_int("dhcpd-pid") % 3000, "full": full,
            "iface": "eth0",
        })

    def render_native(self, ev: LogEvent) -> str:
        f = ev.fields
        head = f'{_util.syslog_ts(ev.timestamp)} dhcp dhcpd[{f["pid"]}]:'
        lines = []
        if f["full"]:
            lines.append(f'{head} DHCPDISCOVER from {f["mac"]} ({f["hostname"]}) via {f["iface"]}')
            lines.append(f'{head} DHCPOFFER on {f["ip"]} to {f["mac"]} ({f["hostname"]}) via {f["iface"]}')
            lines.append(f'{head} DHCPREQUEST for {f["ip"]} ({f["ip"].rsplit(".", 1)[0]}.1) from {f["mac"]} ({f["hostname"]}) via {f["iface"]}')
        else:
            lines.append(f'{head} DHCPREQUEST for {f["ip"]} from {f["mac"]} ({f["hostname"]}) via {f["iface"]}')
        lines.append(f'{head} DHCPACK on {f["ip"]} to {f["mac"]} ({f["hostname"]}) via {f["iface"]}')
        return "\n".join(lines)

    def render_ecs(self, ev: LogEvent) -> dict:
        f = ev.fields
        doc = {
            "@timestamp": _util.iso(ev.timestamp),
            "ecs": {"version": ECS_VERSION},
            "event": {"kind": "event", "category": ["network"], "type": ["info", "allowed"],
                      "action": "dhcpack", "outcome": "success",
                      "dataset": self.dataset, "module": "dhcpd"},
            "data_stream": _util.ds(self.dataset),
            "host": {"name": f["hostname"], "ip": [f["ip"]], "mac": [f["mac"]]},
            "source": {"ip": f["ip"], "mac": f["mac"]},
            "related": {"ip": [f["ip"]], "hosts": [f["hostname"]]},
            "message": self.render_native(ev).split("\n")[-1],
        }
        if ev.labels:
            doc["labels"] = ev.labels
        return doc
