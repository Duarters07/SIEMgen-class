"""OpenVPN server log (syslog) — how remote users 'arrive'.

Real OpenVPN server logs are chatty: a connection is a burst of TLS / VERIFY /
Peer Connection Initiated / MULTI_sva lines that share the ``<ip>:<port>`` (and later
``<user>/<ip>:<port>``) prefix. Periodic TLS soft resets appear during the session and
a SIGTERM line on disconnect. This emitter renders those bursts verbatim so the
connect event is a small multi-line puzzle (the username only appears from the third
line on), like the real thing."""
from __future__ import annotations

import random
from datetime import datetime, timedelta

from .. import ECS_VERSION
from ..org.model import Host, Org, User
from . import _util
from .base import LogEvent, Source

# Plausible residential/ISP public source IPs for remote workers (TEST-NET ranges).
_PUBLIC = ["203.0.113.{}", "198.51.100.{}", "192.0.2.{}"]


class VpnAuth(Source):
    name = "vpn"
    dataset = "vpn"

    def daily_volume(self, user: User, rng: random.Random) -> int:
        return max(1, int(rng.gauss(4, 1)))

    def applies_to(self, user: User, host: Host) -> bool:
        return user.site == "remote"

    def activity_weight(self, user: User) -> float:
        return 0.3

    def _public_ip(self, user: User) -> str:
        """Stable home IP per user (process-independent)."""
        h = _util.stable_int("vpn-pub", user.username)
        return _PUBLIC[h % len(_PUBLIC)].format((h >> 4) % 254 + 1)

    def _vpn_ip(self, host: Host) -> str:
        # tunnel address in the VPN pool, derived from the workstation's last octet
        return f"10.8.0.{int(host.ip.split('.')[-1])}"

    def _base(self, user: User, host: Host, action: str, rng: random.Random) -> dict:
        return {"user": user.username, "outcome": "success", "action": action,
                "pub_ip": self._public_ip(user), "pub_port": rng.randint(1024, 65000),
                "tunnel_ip": self._vpn_ip(host), "assigned_ip": host.ip,
                "pid": 1000 + _util.stable_int("openvpn-pid") % 3000,
                "bytes": rng.randint(200_000, 900_000_000)}

    def login_event(self, user: User, host: Host, ts: datetime, org: Org,
                    rng: random.Random, persona=None) -> LogEvent:
        return LogEvent(timestamp=ts, source=self.name,
                        fields=self._base(user, host, "connected", rng))

    def make_event(self, user: User, host: Host, ts: datetime, org: Org,
                   rng: random.Random, persona=None) -> LogEvent:
        # periodic TLS renegotiation during the session (default reneg-sec 3600)
        return LogEvent(timestamp=ts, source=self.name,
                        fields=self._base(user, host, "rekey", rng))

    def render_native(self, ev: LogEvent) -> str:
        f = ev.fields
        peer = f'{f["pub_ip"]}:{f["pub_port"]}'
        upeer = f'{f["user"]}/{peer}'
        head = f'{_util.syslog_ts(ev.timestamp)} vpn openvpn[{f["pid"]}]:'
        if f["action"] == "connected":
            t1 = _util.syslog_ts(ev.timestamp + timedelta(seconds=1))
            head1 = f'{t1} vpn openvpn[{f["pid"]}]:'
            sid = _util.rhex(random.Random(f["pub_port"]), 8)
            return "\n".join([
                f'{head} {peer} TLS: Initial packet from [AF_INET]{peer}, sid={sid} {_util.rhex(random.Random(f["pub_port"] + 1), 8)}',
                f'{head} {peer} VERIFY OK: depth=1, CN={f.get("ca_cn", "OpenVPN CA")}',
                f'{head} {peer} VERIFY OK: depth=0, CN={f["user"]}',
                f'{head} {peer} peer info: IV_VER=2.6.8',
                f'{head} {peer} peer info: IV_PLAT=win',
                f'{head} {peer} Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384, peer certificate: 2048 bits RSA, signature: RSA-SHA256',
                f'{head} {peer} [{f["user"]}] Peer Connection Initiated with [AF_INET]{peer}',
                f'{head1} {upeer} MULTI_sva: pool returned IPv4={f["tunnel_ip"]}, IPv6=(Not enabled)',
                f'{head1} {upeer} MULTI: Learn: {f["tunnel_ip"]} -> {upeer}',
                f'{head1} {upeer} MULTI: primary virtual IP for {upeer}: {f["tunnel_ip"]}',
                f'{head1} {upeer} Data Channel: cipher \'AES-256-GCM\', peer-id: {f["pub_port"] % 64}',
            ])
        if f["action"] == "disconnected":
            return "\n".join([
                f'{head} {upeer} SIGTERM[soft,remote-exit] received, client-instance exiting',
            ])
        # rekey
        return f'{head} {upeer} TLS: soft reset sec=3600/3600 bytes={f["bytes"]}/-1 pkts={f["bytes"] // 1200}/0'

    def render_ecs(self, ev: LogEvent) -> dict:
        f = ev.fields
        connected = f["action"] == "connected"
        doc = {
            "@timestamp": _util.iso(ev.timestamp),
            "ecs": {"version": ECS_VERSION},
            "event": {
                "kind": "event", "category": ["authentication", "network"],
                "type": ["start"] if connected else ["info"],
                "action": f'vpn-{f["action"]}',
                "dataset": self.dataset, "module": "openvpn",
            },
            "data_stream": _util.ds(self.dataset),
            "source": {"ip": f["pub_ip"], "port": f["pub_port"]},
            "user": {"name": f["user"]},
            "vpn": {"assigned_ip": f["tunnel_ip"]},
            "related": {"ip": [f["pub_ip"], f["tunnel_ip"]], "user": [f["user"]]},
            "message": self.render_native(ev).split("\n")[0],
        }
        if connected:                              # 'connected' has an outcome; rekey is info
            doc["event"]["outcome"] = f["outcome"]
        geo, asd = _util.geo_as(f["pub_ip"])
        if geo:
            doc["source"]["geo"] = geo
            doc["source"]["as"] = asd
        if ev.labels:
            doc["labels"] = ev.labels
        return doc
