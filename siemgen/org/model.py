"""Organization model: users, hosts, network — aligned to the SIEM domain taxonomy."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

# Domain -> tier number, mirroring docs/Phases/entity-registry.md
#   Tier 1 = highest-value (executive), Tier 4 = general staff.
DOMAIN_TIER = {
    "EXE": 1,      # Executive
    "IT": 2,       # IT Infrastructure (admins, maintenance windows)
    "FIN": 3,      # Finance & Compliance
    "HR": 3,       # HR & Identity
    "LEG": 3,      # Legal & Data
    "OPS": 3,      # Operations
    "GENERAL": 4,  # everyone else
}

# Default working hours (UTC, [start, end)) per domain.
DOMAIN_HOURS = {
    "EXE": (8, 19),
    "IT": (6, 22),
    "FIN": (9, 17),
    "HR": (9, 17),
    "LEG": (9, 17),
    "OPS": (7, 19),
    "GENERAL": (9, 17),
}

# Role label per domain (used by behavior profiles).
DOMAIN_ROLE = {
    "EXE": "c-level",
    "IT": "it-admin",
    "FIN": "finance",
    "HR": "hr",
    "LEG": "legal",
    "OPS": "ops",
    "GENERAL": "employee",
}


@dataclass
class User:
    username: str
    email: str
    full_name: str
    department: str          # domain code (IT/HR/.../GENERAL)
    domain: str
    tier: int
    role: str
    work_start: int
    work_end: int
    work_days: tuple[int, ...]   # weekday ints 0=Mon..6=Sun
    site: str
    primary_host: str            # hostname
    privileged: bool = False


@dataclass
class Host:
    name: str
    os: str                  # 'linux' | 'windows'
    domain: str
    ip: str
    criticality: str         # 'low' | 'medium' | 'high' | 'critical'
    kind: str                # 'workstation' | 'server'
    owner: Optional[str] = None  # username for workstations


@dataclass
class Org:
    name: str
    dns_domain: str = "acme.local"       # internal DNS suffix (hosts, e-mail)
    windows_domain: str = "ACME"         # NetBIOS / AD short domain name
    egress_ip: str = "194.65.1.1"        # public NAT address seen by cloud services
    users: list[User] = field(default_factory=list)
    hosts: list[Host] = field(default_factory=list)
    servers: list[str] = field(default_factory=list)        # server hostnames
    external_benign: list[str] = field(default_factory=list)
    external_malicious: list[str] = field(default_factory=list)
    _by_name: dict[str, Host] = field(default_factory=dict, repr=False)

    def index(self) -> None:
        self._by_name = {h.name: h for h in self.hosts}

    def host(self, name: str) -> Optional[Host]:
        return self._by_name.get(name)

    def host_for(self, user: User) -> Host:
        return self._by_name[user.primary_host]

    def linux_servers(self) -> list[Host]:
        return [h for h in self.hosts if h.kind == "server" and h.os == "linux"]

    def server(self, role: str) -> Optional[Host]:
        """Server host by its short role name (dc, web, mail, file, erp, dns, vpn, backup)."""
        return self._by_name.get(f"{role}.{self.dns_domain}")

    def server_ip(self, role: str, default: str) -> str:
        h = self.server(role)
        return h.ip if h else default

    def web_host(self) -> str:
        h = self.server("web")
        return h.name if h else f"web.{self.dns_domain}"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "dns_domain": self.dns_domain,
            "windows_domain": self.windows_domain,
            "egress_ip": self.egress_ip,
            "users": [asdict(u) for u in self.users],
            "hosts": [asdict(h) for h in self.hosts],
            "servers": self.servers,
            "external_benign": self.external_benign,
            "external_malicious": self.external_malicious,
        }
