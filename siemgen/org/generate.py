"""Deterministic generation of the simulated organization from config."""
from __future__ import annotations

import hashlib
import random

from faker import Faker

from .model import (
    DOMAIN_HOURS,
    DOMAIN_ROLE,
    DOMAIN_TIER,
    Host,
    Org,
    User,
)

# site -> second IP octet
SITE_OCTET = {"hq": 10, "branch-eu": 20, "remote": 30}
# domain -> third IP octet
DOMAIN_OCTET = {
    "IT": 1, "HR": 2, "FIN": 3, "LEG": 4, "OPS": 5, "EXE": 6, "GENERAL": 7,
}
# Office domains default to Windows workstations; technical domains to Linux.
LINUX_DOMAINS = {"IT", "OPS"}

# server name -> (domain, os, criticality)
SERVER_SPEC = {
    "dc":     ("IT",  "windows", "critical"),
    "web":    ("IT",  "linux",   "high"),
    "mail":   ("OPS", "linux",   "high"),
    "file":   ("OPS", "linux",   "high"),
    "erp":    ("FIN", "linux",   "critical"),
    "dns":    ("IT",  "linux",   "high"),
    "vpn":    ("IT",  "linux",   "high"),
    "backup": ("OPS", "linux",   "medium"),
}

EXTERNAL_BENIGN = [
    "8.8.8.8", "1.1.1.1", "140.82.121.4", "151.101.1.140", "104.16.132.229",
]
# Documented "bad" ranges used by attack scenarios (TEST-NET + known Tor-ish prefixes).
EXTERNAL_MALICIOUS = [
    "185.220.101.45", "185.220.101.46", "45.155.205.233", "193.142.146.35",
    "203.0.113.5", "198.51.100.7",
]


def _counts(weights: dict[str, float], total: int) -> dict[str, int]:
    s = sum(weights.values()) or 1.0
    raw = {k: int(round(v / s * total)) for k, v in weights.items()}
    # fix rounding drift
    diff = total - sum(raw.values())
    if diff and raw:
        first = next(iter(raw))
        raw[first] += diff
    return raw


def generate_org(cfg: dict, seed: int = 1337) -> Org:
    rng = random.Random(seed)
    fake = Faker()
    Faker.seed(seed)

    org_cfg = cfg.get("organization", {})
    name = org_cfg.get("name", "acme-corp")
    short = "".join(ch for ch in name.split("-")[0].lower() if ch.isalnum()) or "acme"
    domain_suffix = org_cfg.get("dns_domain") or f"{short}.local"
    windows_domain = org_cfg.get("windows_domain") or short.upper()
    total = int(org_cfg.get("users", 150))
    sites = org_cfg.get("sites", ["hq"])
    departments = org_cfg.get("departments", {"GENERAL": 1.0})
    counts = _counts(departments, total)

    # stable public egress (NAT) address per organisation: what SaaS providers see
    eh = int(hashlib.md5(name.encode()).hexdigest()[:6], 16)
    egress_ip = f"194.65.{eh % 254 + 1}.{(eh >> 8) % 254 + 1}"

    org = Org(name=name, dns_domain=domain_suffix, windows_domain=windows_domain,
              egress_ip=egress_ip, external_benign=list(EXTERNAL_BENIGN),
              external_malicious=list(EXTERNAL_MALICIOUS))

    used_names: set[str] = set()
    host_counters: dict[str, int] = {}

    for dom, n in counts.items():
        tier = DOMAIN_TIER.get(dom, 4)
        role = DOMAIN_ROLE.get(dom, "employee")
        start, end = DOMAIN_HOURS.get(dom, (9, 17))
        os_name = "linux" if dom in LINUX_DOMAINS else "windows"

        for _ in range(n):
            first = fake.first_name()
            last = fake.last_name()
            base = f"{first}.{last}".lower().replace(" ", "")
            uname = base
            k = 1
            while uname in used_names:
                k += 1
                uname = f"{base}{k}"
            used_names.add(uname)

            site = rng.choice(sites)
            idx = host_counters.get(dom, 0) + 1
            host_counters[dom] = idx
            host_n = 10 + idx
            ip = f"10.{SITE_OCTET.get(site, 10)}.{DOMAIN_OCTET.get(dom, 7)}.{host_n}"
            host_name = f"ws-{dom.lower()}-{idx:03d}.{domain_suffix}"

            org.hosts.append(Host(
                name=host_name, os=os_name, domain=dom, ip=ip,
                criticality="high" if tier <= 2 else "low",
                kind="workstation", owner=uname,
            ))
            org.users.append(User(
                username=uname,
                email=f"{uname}@{domain_suffix}",
                full_name=f"{first} {last}",
                department=dom, domain=dom, tier=tier, role=role,
                work_start=start, work_end=end,
                work_days=(0, 1, 2, 3, 4),
                site=site, primary_host=host_name,
                privileged=(dom == "IT"),
            ))

    # Servers
    for sname in org_cfg.get("servers", []):
        dom, os_name, crit = SERVER_SPEC.get(sname, ("OPS", "linux", "medium"))
        host_name = f"{sname}.{domain_suffix}"
        ip = f"10.{SITE_OCTET.get('hq', 10)}.0.{10 + len(org.servers)}"
        org.hosts.append(Host(
            name=host_name, os=os_name, domain=dom, ip=ip,
            criticality=crit, kind="server", owner=None,
        ))
        org.servers.append(host_name)

    org.index()
    return org
