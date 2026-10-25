"""Shared helpers for source emitters."""
from __future__ import annotations

import base64
import hashlib
import random
import socket
import struct
from datetime import datetime

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

_PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1}


def community_id(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                 transport: str, seed: int = 0) -> str | None:
    """Community ID v1 flow hash (corelight/community-id-spec): the tool-agnostic
    identifier that lets the SAME flow be correlated across Suricata, Zeek and the
    firewall. Direction-agnostic: (src) and (dst) are ordered canonically."""
    proto = _PROTO_NUM.get(transport.lower())
    if proto is None:
        return None
    try:
        a, b = socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    except OSError:
        return None
    sp, dp = int(src_port), int(dst_port)
    if (a, sp) > (b, dp):                      # canonical ordering
        a, b, sp, dp = b, a, dp, sp
    h = hashlib.sha1()
    h.update(struct.pack("!H", seed))
    h.update(a); h.update(b)
    h.update(struct.pack("!B", proto))
    h.update(b"\x00")
    h.update(struct.pack("!H", sp)); h.update(struct.pack("!H", dp))
    return "1:" + base64.b64encode(h.digest()).decode()


def syslog_ts(ts: datetime) -> str:
    """RFC3164-style 'Mon  d HH:MM:SS' (day space-padded to width 2)."""
    return f"{MONTHS[ts.month - 1]} {ts.day:2d} {ts:%H:%M:%S}"


def iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def rhex(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def jit(rng: random.Random, n: float) -> int:
    """Jittered count with expectation n: x = n * U(0.7, 1.3), then the fractional
    part of x is resolved by a Bernoulli draw, so small rates (0.3 events/min) still
    produce events at the right average instead of rounding to zero. Used by the
    per-minute motors so rates vary minute-to-minute instead of being constant."""
    if n <= 0:
        return 0
    x = n * rng.uniform(0.7, 1.3)
    k = int(x)
    if rng.random() < x - k:
        k += 1
    return k


def rmac(rng: random.Random) -> str:
    return ":".join(f"{rng.randint(0, 255):02x}" for _ in range(6))


def stable_int(*parts, bits: int = 32) -> int:
    """Process-independent integer hash of arbitrary parts (never use hash())."""
    h = hashlib.md5("|".join(str(p) for p in parts).encode()).hexdigest()
    return int(h[: bits // 4], 16)


def stable_mac(name: str) -> str:
    """Locally-administered, stable MAC address for a host name."""
    h = stable_int("mac", name, bits=40)
    b = [(h >> (8 * i)) & 0xFF for i in range(5)]
    return "02:" + ":".join(f"{x:02x}" for x in b)


def syslog_ts_iso(ts: datetime) -> str:
    """RFC3339 timestamp as rsyslog writes it with the high-precision template."""
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+00:00"


def ds(dataset: str) -> dict:
    return {"type": "logs", "dataset": dataset, "namespace": "default"}


def short(host_name: str) -> str:
    return host_name.split(".")[0]


# (iso, country, city, lat, lon, asn, org) — picked deterministically per IP, so a
# given external IP always geolocates the same way (what a GeoIP/ASN pipeline adds).
_GEO = [
    ("US", "United States", "Mountain View", 37.42, -122.08, 15169, "GOOGLE"),
    ("US", "United States", "Redmond", 47.67, -122.12, 8075, "MICROSOFT-CORP-MSN-AS-BLOCK"),
    ("US", "United States", "San Francisco", 37.77, -122.39, 13335, "CLOUDFLARENET"),
    ("IE", "Ireland", "Dublin", 53.33, -6.25, 16509, "AMAZON-02"),
    ("US", "United States", "Cambridge", 42.36, -71.10, 20940, "AKAMAI-ASN1"),
    ("US", "United States", "Menlo Park", 37.45, -122.18, 32934, "FACEBOOK"),
    ("DE", "Germany", "Frankfurt", 50.11, 8.68, 24940, "HETZNER-AS"),
    ("GB", "United Kingdom", "London", 51.50, -0.12, 2906, "AS-SSI"),
]


def is_private_ip(ip: str) -> bool:
    """RFC1918 / loopback / link-local / IPv6 (we only synthesize internal IPv6)."""
    if not ip or ":" in ip:
        return True
    if ip.startswith(("10.", "192.168.", "127.", "169.254.")):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (IndexError, ValueError):
            return True
    return False


def geo_as(ip: str):
    """(geo, as) ECS objects for an external IP, or (None, None) for private/invalid —
    the enrichment a GeoIP/ASN ingest pipeline would attach."""
    if is_private_ip(ip):
        return None, None
    h = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
    iso, country, city, lat, lon, asn, org = _GEO[h % len(_GEO)]
    geo = {"country_iso_code": iso, "country_name": country, "city_name": city,
           "location": {"lat": lat, "lon": lon}}
    return geo, {"number": asn, "organization": {"name": org}}
