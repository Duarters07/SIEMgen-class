"""Suricata network IDS logs (eve.json) — benign flow / tls / quic / dns / http records.

Flow records carry byte/packet volumes AND timing (start/end/age) — the duration a real
Suricata flow logs. TLS/QUIC handshakes carry the metadata that fingerprints a client and
server: negotiated version, JA3/JA3S, certificate subject/issuer/validity/fingerprint and
SNI — the same signals the pcaps in ../../captures/ measured, and the basis for telling
automated/bot traffic from a real browser/app (thesis Objective 2). No alerts yet."""
from __future__ import annotations

import hashlib
import json
import random
from datetime import datetime, timedelta

from .. import ECS_VERSION
from ..org.model import Host, Org, User
from . import _util
from .base import LogEvent, Source

# benign destination names for the baseline (no longer hardcoded to google.com)
_BENIGN_NAMES = [
    "www.google.com", "www.microsoft.com", "outlook.office365.com", "github.com",
    "www.cloudflare.com", "cdn.jsdelivr.net", "www.linkedin.com", "slack.com",
    "www.bing.com", "fonts.gstatic.com", "api.github.com", "graph.microsoft.com",
]
# certificate authorities seen in the wild, picked deterministically per server.
_CAS = ["WR2", "WE1", "WE2", "Microsoft Azure RSA TLS Issuing CA 03",
        "DigiCert Global G2 TLS RSA SHA256 2020 CA1", "R11", "E5",
        "Sectigo RSA Domain Validation Secure Server CA", "GTS CA 1C3"]
_CIPHERS = ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]
_IFACE = "ens192"


def _ja3(client: str) -> str:
    """Stable JA3 client fingerprint per client family (browser/quic/native_app)."""
    return hashlib.md5(f"ja3|{client}".encode()).hexdigest()


def _server_key(sni: str) -> str:
    parts = sni.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else sni


def _ja3s(sni: str) -> str:
    """Stable JA3S server fingerprint per server platform (keyed by registered domain)."""
    return hashlib.md5(f"ja3s|{_server_key(sni)}".encode()).hexdigest()


def _cert(sni: str):
    """Deterministic (issuer, sha256 fingerprint) for a server's certificate."""
    h = int(hashlib.md5(_server_key(sni).encode()).hexdigest()[:8], 16)
    issuer = _CAS[h % len(_CAS)]
    fingerprint = hashlib.sha256(f"cert|{_server_key(sni)}".encode()).hexdigest()
    return issuer, fingerprint


class Suricata(Source):
    name = "suricata"
    dataset = "suricata.eve"

    def daily_volume(self, user: User, rng: random.Random) -> int:
        return max(1, int(rng.gauss(30, 10)))

    def activity_weight(self, user: User) -> float:
        return 2.0

    # -- builders -----------------------------------------------------------
    def _timing(self, ts: datetime, rng: random.Random, max_age: int = 120) -> dict:
        age = rng.randint(1, max_age)
        end = ts + timedelta(seconds=age)
        return {"start": _util.iso(ts), "end": _util.iso(end), "age": age,
                "state": "established",
                "reason": rng.choices(["timeout", "shutdown"], weights=[0.7, 0.3], k=1)[0]}

    def make_event(self, user: User, host: Host, ts: datetime, org: Org,
                   rng: random.Random, persona=None) -> LogEvent:
        etype = rng.choices(["flow", "http", "dns", "tls"], weights=[0.45, 0.25, 0.2, 0.1], k=1)[0]
        dst = rng.choice(org.external_benign) if org.external_benign else "104.16.0.1"
        name = rng.choice(_BENIGN_NAMES)
        sport = rng.randint(1024, 65000)
        dport = 443 if etype in ("tls", "http") else 53
        proto = "UDP" if etype == "dns" else "TCP"
        eve = {
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
            "flow_id": rng.randint(10**14, 10**15), "in_iface": _IFACE,
            "event_type": etype, "src_ip": host.ip, "src_port": sport,
            "dest_ip": dst, "dest_port": dport, "proto": proto,
            "community_id": _util.community_id(host.ip, dst, sport, dport, proto.lower()),
        }
        if etype == "http":
            eve["app_proto"] = "http"
            eve["http"] = {"hostname": name, "url": "/", "http_user_agent": "Mozilla/5.0",
                           "http_content_type": "text/html", "http_method": "GET",
                           "protocol": "HTTP/1.1", "status": 200, "length": rng.randint(200, 40000)}
        elif etype == "dns":
            eve["dns"] = {"version": 2, "type": "query", "id": rng.randint(1, 65535),
                          "rrname": name, "rrtype": "A", "tx_id": 0}
        elif etype == "tls":
            eve["app_proto"] = "tls"
            eve["tls"] = self._tls_block(name, "browser", ts, rng)
        else:  # flow
            f = self._timing(ts, rng)
            f.update({"pkts_toserver": rng.randint(2, 40), "pkts_toclient": rng.randint(2, 60),
                      "bytes_toserver": rng.randint(200, 60000), "bytes_toclient": rng.randint(200, 200000)})
            eve["flow"] = f
        return LogEvent(timestamp=ts, source=self.name, fields={"eve": eve})

    def _tls_block(self, sni: str, client: str, ts: datetime, rng: random.Random) -> dict:
        issuer, fingerprint = _cert(sni)
        version = "1.3" if rng.random() < 0.85 else "1.2"
        return {
            "sni": sni, "version": f"TLS {version}", "ja3": {"hash": _ja3(client)},
            "ja3s": {"hash": _ja3s(sni)}, "subject": f"CN={sni}",
            "issuerdn": f"C=US, O=Cert Authority, CN={issuer}", "fingerprint": fingerprint,
            "cipher": rng.choice(_CIPHERS),
            "notbefore": _util.iso(ts - timedelta(days=45)),
            "notafter": _util.iso(ts + timedelta(days=75)),
        }

    def flow_event(self, host: Host, ts: datetime, dst_ip: str, transport: str,
                   bytes_down: int, bytes_up: int, sni: str, rng: random.Random,
                   labels: dict | None = None, src_port: int | None = None,
                   dst_port: int = 443) -> LogEvent:
        """A flow record carrying byte volumes AND timing — the vehicle for the
        leisure/work traffic. transport is 'udp' (QUIC) or 'tcp'. Pass src_port/dst_port
        to share the 5-tuple with the matching firewall 'pass' (-> same community_id)."""
        f = self._timing(ts, rng)
        f.update({"pkts_toserver": max(1, bytes_up // 1200), "pkts_toclient": max(1, bytes_down // 1200),
                  "bytes_toserver": int(bytes_up), "bytes_toclient": int(bytes_down)})
        sport = src_port if src_port is not None else rng.randint(1024, 65000)
        proto = "UDP" if transport == "udp" else "TCP"
        eve = {
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
            "flow_id": rng.randint(10**14, 10**15), "in_iface": _IFACE, "event_type": "flow",
            "src_ip": host.ip, "src_port": sport,
            "dest_ip": dst_ip, "dest_port": dst_port, "proto": proto,
            "app_proto": "quic" if transport == "udp" else "tls", "flow": f,
            "community_id": _util.community_id(host.ip, dst_ip, sport, dst_port, transport),
        }
        if proto == "TCP":
            eve["tcp"] = {"tcp_flags": "1b", "tcp_flags_ts": "1b", "tcp_flags_tc": "1b",
                          "syn": True, "fin": True, "psh": True, "ack": True, "state": "closed"}
        if sni:
            eve["tls"] = {"sni": sni}
        return LogEvent(timestamp=ts, source=self.name, fields={"eve": eve}, labels=labels or {})

    def handshake_event(self, host: Host, ts: datetime, dst_ip: str, transport: str,
                        sni: str, rng: random.Random, labels: dict | None = None,
                        client: str = "browser") -> LogEvent:
        """A TLS/QUIC handshake (ClientHello + ServerHello): negotiated version, JA3/JA3S,
        certificate subject/issuer/validity/fingerprint, SNI. No byte volume."""
        et = "quic" if transport == "udp" else "tls"
        cl = "quic" if transport == "udp" else client
        sport = rng.randint(1024, 65000)
        eve = {
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
            "flow_id": rng.randint(10**14, 10**15), "in_iface": _IFACE, "event_type": et,
            "src_ip": host.ip, "src_port": sport,
            "dest_ip": dst_ip, "dest_port": 443, "proto": "UDP" if transport == "udp" else "TCP",
            "app_proto": et, "community_id": _util.community_id(host.ip, dst_ip, sport, 443, transport),
        }
        if et == "quic":
            eve["quic"] = {"version": "1", "sni": sni, "ja3": {"hash": _ja3(cl)}}
        else:
            eve["tls"] = self._tls_block(sni, cl, ts, rng)
        return LogEvent(timestamp=ts, source=self.name, fields={"eve": eve}, labels=labels or {})

    def render_native(self, ev: LogEvent) -> str:
        return json.dumps(ev.fields["eve"], default=str)

    def render_ecs(self, ev: LogEvent) -> dict:
        e = ev.fields["eve"]
        doc = {
            "@timestamp": _util.iso(ev.timestamp),
            "ecs": {"version": ECS_VERSION},
            "event": {"kind": "event", "category": ["network"], "type": ["connection", "protocol"],
                      "action": f'suricata-{e["event_type"]}', "outcome": "success",
                      "dataset": self.dataset, "module": "suricata"},
            "data_stream": _util.ds(self.dataset),
            "source": {"ip": e["src_ip"], "port": e["src_port"]},
            "destination": {"ip": e["dest_ip"], "port": e["dest_port"]},
            "network": {"transport": e["proto"].lower(), "protocol": e.get("app_proto", e["event_type"])},
            "observer": {"type": "ids", "vendor": "Suricata"},
            "related": {"ip": [e["src_ip"], e["dest_ip"]]},
            "message": (f'{e["event_type"]} {e["src_ip"]}:{e["src_port"]} -> '
                        f'{e["dest_ip"]}:{e["dest_port"]} {e.get("app_proto", e["proto"].lower())}'),
        }
        cid = e.get("community_id") or _util.community_id(
            e["src_ip"], e["dest_ip"], e["src_port"], e["dest_port"], e["proto"].lower())
        if cid:
            doc["network"]["community_id"] = cid
        if e.get("in_iface"):
            doc["observer"]["ingress"] = {"interface": {"name": e["in_iface"]}}
        geo, asd = _util.geo_as(e["dest_ip"])      # GeoIP/ASN on the external endpoint
        if geo:
            doc["destination"]["geo"] = geo
            doc["destination"]["as"] = asd
        if "flow" in e:
            fl = e["flow"]
            doc["source"]["bytes"] = fl["bytes_toserver"]
            doc["source"]["packets"] = fl["pkts_toserver"]
            doc["destination"]["bytes"] = fl["bytes_toclient"]
            doc["destination"]["packets"] = fl["pkts_toclient"]
            doc["network"]["bytes"] = fl["bytes_toserver"] + fl["bytes_toclient"]
            doc["network"]["packets"] = fl["pkts_toserver"] + fl["pkts_toclient"]
            if "start" in fl:
                doc["event"]["start"] = fl["start"]
                doc["event"]["end"] = fl["end"]
                doc["event"]["duration"] = int(fl["age"] * 1e9)  # ECS duration = nanoseconds
        if "http" in e:
            h = e["http"]
            doc["url"] = {"original": h.get("url"), "domain": h.get("hostname")}
            doc["http"] = {"request": {"method": h.get("http_method")},
                           "response": {"status_code": h.get("status"),
                                        "bytes": h.get("length")}}
            doc["related"].setdefault("hosts", []).append(h.get("hostname"))
        if "dns" in e:
            doc["dns"] = {"question": {"name": e["dns"].get("rrname"), "type": e["dns"].get("rrtype")},
                          "type": e["dns"].get("type", "query")}
            doc["related"].setdefault("hosts", []).append(e["dns"].get("rrname"))
        if e.get("quic"):
            q = e["quic"]
            doc.setdefault("related", {}).setdefault("hosts", [])
            if q.get("sni"):
                doc["related"]["hosts"].append(q["sni"])
            doc["tls"] = {"client": {"server_name": q.get("sni"), "ja3": q.get("ja3", {}).get("hash")},
                          "version_protocol": "quic", "version": q.get("version")}
        if e.get("tls"):
            t = e["tls"]
            doc.setdefault("related", {}).setdefault("hosts", [])
            if t.get("sni"):
                doc["related"]["hosts"].append(t["sni"])
            tls = {"client": {"server_name": t.get("sni")}}
            if "version" in t:                       # full handshake metadata
                tls["version"] = t["version"].replace("TLS ", "")
                tls["version_protocol"] = "tls"
                tls["cipher"] = t.get("cipher")
                tls["client"]["ja3"] = t.get("ja3", {}).get("hash")
                issuer = t.get("issuerdn", "").split("CN=")[-1] or None
                tls["server"] = {"ja3s": t.get("ja3s", {}).get("hash"),
                                 "hash": {"sha256": t.get("fingerprint")},
                                 "x509": {"subject": {"common_name": t.get("sni")},
                                          "issuer": {"common_name": issuer},
                                          "not_before": t.get("notbefore"),
                                          "not_after": t.get("notafter")}}
            doc["tls"] = tls
        if ev.labels:
            doc["labels"] = ev.labels
        return doc
