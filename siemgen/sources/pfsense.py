"""pfSense firewall log — ``filterlog`` CSV records as received by a remote syslog
server (RFC3164 header written by rsyslog, then the CSV body).

Field order follows the Netgate documentation for filterlog:

    rule,sub-rule,anchor,tracker,iface,reason,action,dir,ip-version,
    tos,ecn,ttl,id,offset,flags,proto-id,proto,length,src,dst,
    [TCP]  src-port,dst-port,data-length,tcp-flags,seq,ack,window,urg,options
    [UDP]  src-port,dst-port,data-length
    [ICMP] icmp-type, ...

Three builders: ``make_event`` (baseline pass/block lottery), ``flow_event`` (a pass
for a specific destination sharing the 5-tuple of a Suricata flow, so both records get
the same community_id) and ``block_event`` (inbound scan noise + blocked egress)."""
from __future__ import annotations

import random
from datetime import datetime

from .. import ECS_VERSION
from ..org.model import Host, Org, User
from . import _util
from .base import LogEvent, Source

_PID = 1000 + _util.stable_int("filterlog-pid") % 60000
_WAN, _LAN = "igb0", "igb1"
# rule ids: pass rules are a few stable numbers (like a real policy), blocks hit the default deny
_PASS_RULES = [(1000000103, 5), (1000000104, 6), (1000000117, 12), (1000000118, 13)]
_BLOCK_RULE = (1000000103, 4)   # "Default deny rule IPv4"


class PfSenseFirewall(Source):
    name = "pfsense"
    dataset = "pfsense.firewall"

    def daily_volume(self, user: User, rng: random.Random) -> int:
        return max(1, int(rng.gauss(60, 18)))

    def activity_weight(self, user: User) -> float:
        return 4.0

    def _rec(self, ts, action, direction, proto, src_ip, dst_ip, sport, dport, rng,
             length=None, labels=None) -> LogEvent:
        tracker, rule = rng.choice(_PASS_RULES) if action == "pass" else _BLOCK_RULE
        iface = _LAN if direction == "out" else _WAN
        return LogEvent(timestamp=ts, source=self.name, fields={
            "action": action, "direction": direction, "proto": proto,
            "src_ip": src_ip, "dst_ip": dst_ip, "src_port": sport, "dst_port": dport,
            "iface": iface, "ttl": rng.randint(48, 128), "ipid": rng.randint(1, 65535),
            "length": length if length is not None else (rng.randint(40, 1500) if proto == "tcp" else rng.randint(28, 1400)),
            "rule": rule, "tracker": tracker, "pid": _PID,
            "tcp_flags": "S" if action == "pass" else rng.choice(["S", "S", "SA", "FA", "R"]),
            "seq": rng.randint(1, 4_000_000_000), "window": rng.choice([64240, 65535, 29200, 26883]),
        }, labels=labels or {})

    def make_event(self, user: User, host: Host, ts: datetime, org: Org,
                   rng: random.Random, persona=None) -> LogEvent:
        proto = rng.choices(["tcp", "udp"], weights=[0.7, 0.3], k=1)[0]
        sport = rng.randint(1024, 65000)
        # ~92% normal outbound pass; ~8% blocked outbound to a "bad" external IP
        if rng.random() < 0.92:
            web = org.server("web")
            dst = rng.choice(org.external_benign + ([web.ip] if web else []))
            dport = rng.choice([443, 443, 443, 80, 53, 587, 993]) if proto == "tcp" else rng.choice([53, 443, 123])
            return self._rec(ts, "pass", "out", proto, host.ip, dst, sport, dport, rng)
        dst = rng.choice(org.external_malicious)
        dport = rng.choice([4444, 8080, 6667, 1337, 23])
        return self._rec(ts, "block", "out", proto, host.ip, dst, sport, dport, rng)

    def flow_event(self, host: Host, ts: datetime, dst_ip: str, transport: str,
                   rng: random.Random, labels: dict | None = None, dport: int = 443,
                   src_port: int | None = None) -> LogEvent:
        """An outbound 'pass' to a specific destination (used by the leisure/work motors).
        transport is 'udp' (QUIC) or 'tcp'. Pass src_port to share the 5-tuple with the
        matching Suricata flow so network.community_id correlates the two records."""
        sport = src_port if src_port is not None else rng.randint(1024, 65000)
        return self._rec(ts, "pass", "out", transport, host.ip, dst_ip, sport, dport, rng,
                         length=60 if transport == "tcp" else rng.randint(1200, 1350), labels=labels)

    def block_event(self, host: Host, ts: datetime, rng: random.Random,
                    labels: dict | None = None) -> LogEvent:
        """A blocked connection — mostly inbound scan/probe noise hitting closed ports,
        plus the occasional blocked egress. What a real perimeter firewall logs all day."""
        inbound = rng.random() < 0.6
        proto = rng.choices(["tcp", "udp"], weights=[0.85, 0.15], k=1)[0]
        rnd_ip = f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        if inbound:                      # internet -> our WAN address, closed service ports
            dport = rng.choice([22, 23, 3389, 445, 3306, 1433, 8080, 5900, 8443, 81])
            return self._rec(ts, "block", "in", proto, rnd_ip, self._wan_ip(), rng.randint(1024, 65000),
                             dport, rng, length=rng.randint(40, 60), labels=labels)
        dport = rng.choice([4444, 6667, 1337, 9001, 8443, 25])
        return self._rec(ts, "block", "out", proto, host.ip, rnd_ip, rng.randint(1024, 65000),
                         dport, rng, length=rng.randint(40, 60), labels=labels)

    def _wan_ip(self) -> str:
        return getattr(getattr(self, "org", None), "egress_ip", "194.65.1.1")

    def render_native(self, ev: LogEvent) -> str:
        f = ev.fields
        protonum = {"tcp": "6", "udp": "17", "icmp": "1"}[f["proto"]]
        csv = [str(f["rule"]), "", "", str(f["tracker"]), f["iface"], "match",
               f["action"], f["direction"], "4", "0x0", "", str(f["ttl"]),
               str(f["ipid"]), "0", "DF" if f["proto"] == "tcp" else "none",
               protonum, f["proto"], str(f["length"]), f["src_ip"], f["dst_ip"]]
        if f["proto"] == "tcp":
            # src,dst ports, data-length, flags, seq, ack, window, urg, options
            csv += [str(f["src_port"]), str(f["dst_port"]), str(max(0, f["length"] - 40)),
                    f["tcp_flags"], str(f["seq"]), "", str(f["window"]), "",
                    "mss;sackOK;TS;nop;wscale"]
        else:
            csv += [str(f["src_port"]), str(f["dst_port"]), str(max(0, f["length"] - 28))]
        return f'{_util.syslog_ts(ev.timestamp)} pfsense filterlog[{f["pid"]}]: {",".join(csv)}'

    def render_ecs(self, ev: LogEvent) -> dict:
        f = ev.fields
        allowed = f["action"] == "pass"
        doc = {
            "@timestamp": _util.iso(ev.timestamp),
            "ecs": {"version": ECS_VERSION},
            "event": {
                "kind": "event", "category": ["network"],
                "type": ["connection", "allowed" if allowed else "denied"],
                "action": f["action"],
                "dataset": self.dataset, "module": "pfsense",
            },
            "data_stream": _util.ds(self.dataset),
            "observer": {"type": "firewall", "vendor": "pfSense",
                         "ingress": {"interface": {"name": f["iface"]}}},
            "source": {"ip": f["src_ip"], "port": f["src_port"]},
            "destination": {"ip": f["dst_ip"], "port": f["dst_port"]},
            "network": {"transport": f["proto"], "iana_number": {"tcp": "6", "udp": "17"}[f["proto"]],
                        "direction": "egress" if f["direction"] == "out" else "ingress"},
            "related": {"ip": [f["src_ip"], f["dst_ip"]]},
            "rule": {"id": str(f["rule"]), "uuid": str(f["tracker"])},
            "message": self.render_native(ev),
        }
        cid = _util.community_id(f["src_ip"], f["dst_ip"], f["src_port"],
                                 f["dst_port"], f["proto"])
        if cid:
            doc["network"]["community_id"] = cid
        for side, ipf in (("source", f["src_ip"]), ("destination", f["dst_ip"])):
            geo, asd = _util.geo_as(ipf)           # GeoIP/ASN on whichever end is external
            if geo:
                doc[side]["geo"] = geo
                doc[side]["as"] = asd
        if ev.labels:
            doc["labels"] = ev.labels
        return doc
