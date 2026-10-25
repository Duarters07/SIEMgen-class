"""Leisure / off-task network sessions, modelled from REAL packet captures
(see ../../captures/ and config/leisure-profiles.yaml).

During work hours a user may "go off-task" and stream YouTube / Spotify / Instagram
(or browse an adult site). A session is rendered as **flow records** (Suricata eve,
carrying the large byte volumes) + a pfSense "pass" + a burst of DNS queries, all
tagged `labels.activity` / `labels.offtask` for ground truth. Few log lines, large
byte fields — exactly how real flow logs represent streaming.
"""
from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta
from pathlib import Path

import yaml


def load_leisure(path: str | None) -> dict | None:
    if not path or not Path(path).exists():
        return None
    data = yaml.safe_load(Path(path).read_text())
    return data if data and data.get("profiles") else None


def _seed(*parts) -> int:
    h = hashlib.md5("|".join(str(p) for p in parts).encode()).hexdigest()
    return int(h[:8], 16)


def user_offtask(user, cfg: dict, seed: int) -> dict:
    """Stable per-user off-task profile: propensity (expected sessions/work-day) +
    preferred apps. A few users become heavy slackers; adult is restricted to a small
    fraction of users."""
    r = random.Random(_seed(seed, "offtask", user.username))
    profiles = cfg["profiles"]
    base = (cfg.get("propensity_by_domain", {}) or {}).get(user.domain, 0.8)
    propensity = base * r.uniform(0.4, 1.6)
    if r.random() < 0.15:
        propensity *= 2.5
    non_adult = [a for a in profiles if a != "adult"]
    prefs = r.sample(non_adult, k=min(len(non_adult), r.randint(1, 3))) if non_adult else []
    if "adult" in profiles and r.random() < cfg.get("adult_user_fraction", 0.06):
        prefs = prefs + ["adult"]
    return {"propensity": propensity, "apps": prefs}


def _resolve_domain(pattern: str, rng: random.Random) -> str:
    """Turn a wildcard SNI pattern into a concrete hostname, using the naming
    scheme of the CDN it belongs to (as seen in the packet captures)."""
    if "*" not in pattern:
        return pattern
    hexs = "".join(rng.choice("0123456789abcdefghijklmnopqrstuvwxyz") for _ in range(8))
    if "googlevideo" in pattern:                 # rr5---sn-q4flrnss.googlevideo.com
        tok = f"rr{rng.randint(1, 6)}---sn-{hexs[:8]}"
    elif "fbcdn" in pattern or "cdninstagram" in pattern:   # scontent.flis7-1.fna.fbcdn.net
        tok = rng.choice(["scontent.flis7-1.fna", "instagram.flis7-1.fna", "scontent.fopo1-1.fna", "static"])
    elif "spotify" in pattern or "scdn" in pattern:         # gew1-spclient.spotify.com
        tok = rng.choice(["gew1", "gae2", "guc3", "heads-fa-tls13"])
    elif "sharepoint" in pattern or "onedrive" in pattern:  # <tenant>.sharepoint.com
        tok = rng.choice(["acme", "acme-my", "acme-files"])
    elif "amazonaws" in pattern:
        tok = rng.choice(["s3.eu-west-1", "ec2.eu-west-1", "sts.eu-west-1", "lambda.eu-west-1"])
    elif "windowsupdate" in pattern:
        tok = rng.choice(["download", "fe3cr.delivery.mp", "sls.update"])
    else:
        tok = rng.choice(["edge", "cdn", "www", "app", "api", "static", f"node{rng.randint(1, 9)}"])
    return pattern.replace("*", tok, 1)


def _ip_in(prefix: str, rng: random.Random) -> str:
    return f"{prefix}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _labels(app: str, prof: dict) -> dict:
    activity = f"aup_{app}" if prof.get("detection") == "aup" else f"leisure_{app}"
    return {"activity": activity, "offtask": True, "category": prof["category"], "app": app}


def plan_day_sessions(user, off: dict, cfg: dict, rng: random.Random) -> list:
    """Return a list of (app, start_minute_of_day, duration_min) for one working day."""
    p = off["propensity"]
    n = int(p) + (1 if rng.random() < (p - int(p)) else 0)
    n = min(n, 5)
    if n <= 0 or not off["apps"]:
        return []
    out = []
    ws, we = user.work_start, max(user.work_start + 1, user.work_end)
    hours = list(range(ws, we))
    weights = [2 if h >= 13 else 1 for h in hours]   # bias to post-lunch/afternoon
    for _ in range(n):
        app = rng.choice(off["apps"])
        prof = cfg["profiles"][app]
        hour = rng.choices(hours, weights=weights, k=1)[0]
        start_min = hour * 60 + rng.randint(0, 59)
        dur = rng.randint(prof["session_min"][0], prof["session_min"][1])
        out.append((app, start_min, dur))
    return out


def session_context(app: str, prof: dict, cfg: dict, rng: random.Random) -> dict:
    """Stable per-session context: destination pool, SNI, transport, and the
    measured per-minute rates (flows/dns/tls) used to calibrate the volume."""
    pool = [_ip_in(rng.choice(prof["cdn_prefixes"]), rng) for _ in range(rng.randint(3, 6))]
    return {
        "app": app, "prof": prof,
        "transport": "udp" if prof["transport"] == "quic" else "tcp",
        "video_ip": pool[0], "dst_pool": pool,
        "sni": _resolve_domain(prof["domains"][0], rng),
        "noise": cfg.get("browser_noise_domains", []) or [],
        # measured per-minute rates, scaled by an optional global multiplier
        # (set leisure.rate_multiplier < 1 to reduce log volume without losing shape)
        "rates": {"flows": prof.get("flows_per_min", 12) * cfg.get("rate_multiplier", 1.0),
                  "dns": prof.get("dns_per_min", 6) * cfg.get("rate_multiplier", 1.0),
                  "tls": prof.get("tls_per_min", 6) * cfg.get("rate_multiplier", 1.0)},
        "labels": _labels(app, prof),
    }


def _jit(n: float, rng: random.Random) -> int:
    from ..sources._util import jit
    return jit(rng, n)


def minute_events(sources: dict, host, base_ts: datetime, ctx: dict, rng: random.Random) -> list:
    """One minute of an off-task session, at MEASURED rates: DNS queries +
    TLS/QUIC handshakes + flow records (bytes concentrated in the video flows) +
    a sample of pfSense passes. Calibrated so a 5-min video ≈ what a real
    Zeek/Suricata pipeline would log."""
    prof, labels, transport = ctx["prof"], ctx["labels"], ctx["transport"]
    rates = ctx["rates"]
    dns_src, ids, fw = sources.get("dns"), sources.get("suricata"), sources.get("pfsense")
    out = []

    def t():
        return base_ts + timedelta(seconds=rng.randint(0, 59), microseconds=rng.randint(0, 999999))

    client = prof.get("client", "browser")
    # DNS (page resources, re-resolutions, + browser ad/analytics noise). The answer
    # is an IP from the session pool so DNS -> flow share the same destination.
    for _ in range(_jit(rates["dns"], rng)):
        if ctx["noise"] and client == "browser" and rng.random() < 0.4:
            d = rng.choice(ctx["noise"])
        else:
            d = _resolve_domain(rng.choice(prof["domains"]), rng)
        if dns_src:
            out.append(dns_src.query_event(host, t(), d, rng, labels,
                                           resolved_ip=rng.choice(ctx["dst_pool"])))

    # TLS / QUIC handshakes (one per connection opened)
    for _ in range(_jit(rates["tls"], rng)):
        if ids:
            out.append(ids.handshake_event(host, t(), rng.choice(ctx["dst_pool"]),
                                           transport, ctx["sni"], rng, labels, client=client))

    # Flow records: bulk bytes in 1-2 "video" flows, the rest small (ads/analytics).
    # Each connection has a stable 5-tuple shared with its firewall 'pass' (same
    # community_id) so the Suricata flow and the pfSense record correlate.
    nflows = max(1, _jit(rates["flows"], rng))
    total_down = prof["mb_per_min"] * 1_000_000 * rng.uniform(0.7, 1.3)
    big = min(2, nflows)
    big_share = [0.6, 0.3]
    for i in range(nflows):
        if i < big:
            down = total_down * big_share[i] * rng.uniform(0.85, 1.15)
            dst, tr, sni = ctx["video_ip"], transport, ctx["sni"]
        else:
            down = rng.randint(2_000, 80_000)       # small ancillary flow
            dst, tr, sni = rng.choice(ctx["dst_pool"]), rng.choice([transport, "tcp"]), None
        up = down / max(1, prof["down_up"])
        sport = rng.randint(1024, 65000)
        if ids:
            out.append(ids.flow_event(host, t(), dst, tr, int(down), int(up), sni, rng,
                                      labels, src_port=sport))
        if fw and i % 4 == 0:                        # ~1 in 4 connections also hit the FW
            out.append(fw.flow_event(host, t(), dst, tr, rng, labels, src_port=sport))

    return out


def expand_session(sources: dict, user, host, app: str, prof: dict, start_ts: datetime,
                   dur_min: int, cfg: dict, rng: random.Random) -> list:
    """Full off-task session (used by backfill): per-minute calibrated events."""
    ctx = session_context(app, prof, cfg, rng)
    events = []
    for m in range(max(1, dur_min)):
        events += minute_events(sources, host, start_ts + timedelta(minutes=m), ctx, rng)
    return events
