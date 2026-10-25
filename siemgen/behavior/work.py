"""WORK network baseline — the per-minute network telemetry a workstation emits
while actually working, to ROLE-APPROPRIATE business destinations.

Mirrors the leisure motor (Suricata flows + DNS + TLS handshakes + pfSense passes)
but: (a) traffic is spread across MANY business domains (no single dominant "video"
flow), (b) bytes are modest and only mildly asymmetric, (c) destinations depend on
the user's role (finance hits ERP/banking, IT hits GitHub/AWS, …). Calibrated from
published statistics (HTTP Archive, Cisco Umbrella, SIEM sizing) — see
config/work-profiles.yaml. Every event is tagged labels.state: working,
labels.offtask: false, labels.app: work.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from .leisure import _ip_in, _jit, _resolve_domain


def load_work(path: str | None) -> dict | None:
    if not path or not Path(path).exists():
        return None
    data = yaml.safe_load(Path(path).read_text())
    return data if data and data.get("profile") else None


def role_domains(cfg: dict, role_domain: str, dns_domain: str = "acme.local") -> list[str]:
    """Business destinations for a user, by org domain code, + the common set.
    ``{org}`` in a domain name is replaced by the organisation's DNS suffix."""
    by_role = (cfg.get("domains_by_role", {}) or {}).get(role_domain, [])
    out = list(by_role) + list(cfg.get("common_domains", []) or [])
    return [d.replace("{org}", dns_domain) for d in out]


def work_context(user, cfg: dict, rng: random.Random, dns_domain: str = "acme.local") -> dict:
    """Per-user work context: role destinations, a small pool of synthetic
    business IPs, and the per-minute rates (scaled by behavior.work_intensity)."""
    prof = cfg["profile"]
    mult = cfg.get("work_intensity", 1.0)
    pool = role_domains(cfg, user.domain, dns_domain) or [f"intranet.{dns_domain}"]
    prefixes = cfg.get("cdn_prefixes", ["20.190", "142.250"])
    dst_pool = [_ip_in(rng.choice(prefixes), rng) for _ in range(rng.randint(4, 8))]
    return {
        "domains": pool, "dst_pool": dst_pool,
        "transport": "tcp", "quic_fraction": prof.get("quic_fraction", 0.2),
        "mb_per_min": prof.get("mb_per_min", 1.5), "down_up": prof.get("down_up", 4),
        "rates": {
            "flows": prof.get("flows_per_min", 10) * mult,
            "dns": prof.get("dns_per_min", 4) * mult,
            "tls": prof.get("tls_per_min", 6) * mult,
            "pf": prof.get("pfsense_per_min", 5) * mult,
            "pf_block": prof.get("pfsense_block_per_min", 1.0) * mult,
        },
        "labels": {"state": "working", "offtask": False, "app": "work", "category": "business"},
    }


def minute_events(sources: dict, host, base_ts: datetime, ctx: dict, rng: random.Random) -> list:
    """One minute of working network activity: business DNS + TLS handshakes +
    many small/medium flows to business destinations + firewall passes. Each
    connection also produces a pfSense 'pass' (the traffic crosses the firewall)."""
    labels, rates = ctx["labels"], ctx["rates"]
    dns_src, ids, fw = sources.get("dns"), sources.get("suricata"), sources.get("pfsense")
    out = []

    def t():
        return base_ts + timedelta(seconds=rng.randint(0, 59), microseconds=rng.randint(0, 999999))

    def transport():
        return "udp" if rng.random() < ctx["quic_fraction"] else "tcp"

    # DNS lookups for business domains (answer = a session-pool IP -> DNS->flow link)
    for _ in range(_jit(rates["dns"], rng)):
        d = _resolve_domain(rng.choice(ctx["domains"]), rng)
        if dns_src:
            out.append(dns_src.query_event(host, t(), d, rng, labels,
                                           resolved_ip=rng.choice(ctx["dst_pool"])))

    # TLS handshakes (new business connections)
    for _ in range(_jit(rates["tls"], rng)):
        if ids:
            sni = _resolve_domain(rng.choice(ctx["domains"]), rng)
            out.append(ids.handshake_event(host, t(), rng.choice(ctx["dst_pool"]),
                                           transport(), sni, rng, labels, client="browser"))

    # Flow records: many small/medium flows (no dominant video flow), modest bytes.
    # Each connection's 5-tuple is shared with its firewall 'pass' (community_id match);
    # a fraction (pf/flows) of flows are also logged by the firewall.
    nflows = max(1, _jit(rates["flows"], rng))
    total_down = ctx["mb_per_min"] * 1_000_000 * rng.uniform(0.7, 1.3)
    per = total_down / nflows
    pf_ratio = min(1.0, rates.get("pf", 5) / max(1.0, rates.get("flows", 10)))
    for _ in range(nflows):
        down = max(1_000, int(per * rng.uniform(0.4, 1.8)))
        up = int(down / max(1, ctx["down_up"]))
        dst = rng.choice(ctx["dst_pool"]); tr = transport(); sport = rng.randint(1024, 65000)
        sni = _resolve_domain(rng.choice(ctx["domains"]), rng) if rng.random() < 0.6 else None
        if ids:
            out.append(ids.flow_event(host, t(), dst, tr, down, up, sni, rng, labels, src_port=sport))
        if fw and rng.random() < pf_ratio:
            out.append(fw.flow_event(host, t(), dst, tr, rng, labels, src_port=sport))

    # perimeter block noise (inbound scans + blocked egress) — unrelated, no correlation
    if fw:
        for _ in range(_jit(rates.get("pf_block", 1.0), rng)):
            out.append(fw.block_event(host, t(), rng, labels))

    return out
