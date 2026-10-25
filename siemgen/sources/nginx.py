"""nginx access log (``combined`` format) — internal users browsing company web apps.

    $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
    "$http_referer" "$http_user_agent"

High-entropy: URLs are templated with random ids/uuids/search terms so lines rarely
repeat; each user has a stable persona (browser, favourite areas of the app)."""
from __future__ import annotations

import random
from datetime import datetime

from .. import ECS_VERSION
from ..org.model import Host, Org, User
from . import _util
from .base import LogEvent, Source

# (template, weight). Placeholders are filled per-request -> near-unique URLs.
_TEMPLATES = [
    ("/", 6), ("/dashboard", 6), ("/profile", 2), ("/settings", 1),
    ("/notifications", 2), ("/help", 1), ("/health", 1),
    ("/intranet/news/{id}", 3), ("/wiki/{slug}", 3), ("/projects/{id}/board", 3),
    ("/api/v1/orders/{id}", 4), ("/api/v1/orders?page={n}", 2),
    ("/api/v1/items/{id}", 4), ("/api/v1/items?cat={cat}", 2),
    ("/api/v1/users/{uid}", 2), ("/api/v1/invoices/{id}", 2),
    ("/api/v1/reports/{year}/{month}", 2),
    ("/search?q={q}", 4), ("/files/{uuid}", 3), ("/files/{uuid}/download", 2),
    ("/static/css/app.{hash}.css", 3), ("/static/js/app.{hash}.js", 3),
    ("/static/img/{asset}.png", 2), ("/favicon.ico", 2),
]
_WORDS = ["invoice", "budget", "contract", "report", "policy", "payroll", "vendor",
          "client", "audit", "roadmap", "ticket", "incident", "backup", "release",
          "onboarding", "expense", "timesheet", "proposal", "compliance"]
_ASSETS = ["logo", "banner", "avatar", "icon-sprite", "hero", "bg", "tile"]
_SLUGS = ["getting-started", "vpn-setup", "expense-policy", "security-awareness",
          "org-chart", "holidays-2026", "printer-setup", "code-of-conduct"]
_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
_UA_FALLBACK = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]


def _render(template: str, rng: random.Random, year: int) -> str:
    out = template
    if "{id}" in out:
        out = out.replace("{id}", str(rng.randint(1, 99999)))
    if "{uid}" in out:
        out = out.replace("{uid}", str(rng.randint(1, 2000)))
    if "{n}" in out:
        out = out.replace("{n}", str(rng.randint(1, 50)))
    if "{q}" in out:
        q = rng.choice(_WORDS) + (("+" + rng.choice(_WORDS)) if rng.random() < 0.3 else "")
        out = out.replace("{q}", q)
    if "{cat}" in out:
        out = out.replace("{cat}", rng.choice(_WORDS))
    if "{slug}" in out:
        out = out.replace("{slug}", rng.choice(_SLUGS))
    if "{asset}" in out:
        out = out.replace("{asset}", rng.choice(_ASSETS))
    if "{uuid}" in out:
        out = out.replace("{uuid}", _util.rhex(rng, 32))
    if "{hash}" in out:
        out = out.replace("{hash}", _util.rhex(rng, 8))
    if "{year}" in out:
        out = out.replace("{year}", str(year))
    if "{month}" in out:
        out = out.replace("{month}", f"{rng.randint(1, 12):02d}")
    return out


class NginxAccess(Source):
    name = "nginx"
    dataset = "nginx.access"

    def daily_volume(self, user: User, rng: random.Random) -> int:
        base = {"c-level": 25, "it-admin": 40, "finance": 60, "hr": 50,
                "legal": 45, "ops": 35, "employee": 55}.get(user.role, 50)
        return max(1, int(rng.gauss(base, base * 0.3)))

    def activity_weight(self, user: User) -> float:
        return 5.0

    # -- favourites (stable per persona) ------------------------------------
    def _favourites(self, persona) -> list[str]:
        fr = random.Random(persona.seed ^ 0x9E3779B9)
        k = fr.randint(8, 14)
        idx = fr.sample(range(len(_TEMPLATES)), min(k, len(_TEMPLATES)))
        return [_TEMPLATES[i][0] for i in idx]

    def _pick_template(self, rng: random.Random, persona) -> str:
        if persona is not None and rng.random() < 0.8:
            return rng.choice(self._favourites(persona))
        templates = [t for t, _ in _TEMPLATES]
        weights = [w for _, w in _TEMPLATES]
        return rng.choices(templates, weights=weights, k=1)[0]

    def _server_name(self, org: Org) -> str:
        return f"intranet.{org.dns_domain}"

    def make_event(self, user: User, host: Host, ts: datetime, org: Org,
                   rng: random.Random, persona=None) -> LogEvent:
        template = self._pick_template(rng, persona)
        url = _render(template, rng, ts.year)
        is_static = url.startswith("/static") or url == "/favicon.ico"
        is_api = url.startswith("/api")
        method = "POST" if (is_api and rng.random() < 0.25) else "GET"
        if is_static:
            status = rng.choices([200, 304], weights=[0.6, 0.4], k=1)[0]
            nbytes = 0 if status == 304 else rng.randint(500, 180000)
        else:
            status = rng.choices([200, 302, 401, 404, 500],
                                 weights=[0.9, 0.04, 0.02, 0.03, 0.01], k=1)[0]
            nbytes = rng.randint(180, 42000) if status != 302 else rng.randint(138, 160)
        ua = persona.ua if persona is not None else rng.choice(_UA_FALLBACK)
        referrer = "-"
        if rng.random() < 0.6:
            referrer = f"https://{self._server_name(org)}" + rng.choice(["/", "/dashboard", "/search", "/projects"])
        return LogEvent(timestamp=ts, source=self.name, fields={
            "src_ip": host.ip, "user": "-", "method": method, "url": url,
            "proto": "HTTP/2.0" if rng.random() < 0.7 else "HTTP/1.1",
            "status": status, "bytes": nbytes, "referrer": referrer, "ua": ua,
            "server": org.web_host(), "vhost": self._server_name(org),
        })

    def login_event(self, user: User, host: Host, ts: datetime, org: Org,
                    rng: random.Random, persona=None) -> LogEvent:
        """A web-app session start (POST /login 302 -> /dashboard) — the user 'arriving'."""
        ua = persona.ua if persona is not None else rng.choice(_UA_FALLBACK)
        return LogEvent(timestamp=ts, source=self.name, fields={
            "src_ip": host.ip, "user": "-", "method": "POST", "url": "/login", "proto": "HTTP/2.0",
            "status": 302, "bytes": 145, "referrer": f"https://{self._server_name(org)}/login",
            "ua": ua, "server": org.web_host(), "vhost": self._server_name(org),
        })

    def _time_local(self, ts: datetime) -> str:
        return f"{ts.day:02d}/{_MONTHS[ts.month - 1]}/{ts.year}:{ts:%H:%M:%S} +0000"

    def render_native(self, ev: LogEvent) -> str:
        f = ev.fields
        return (f'{f["src_ip"]} - {f["user"]} [{self._time_local(ev.timestamp)}] '
                f'"{f["method"]} {f["url"]} {f.get("proto", "HTTP/1.1")}" {f["status"]} {f["bytes"]} '
                f'"{f["referrer"]}" "{f["ua"]}"')

    def render_ecs(self, ev: LogEvent) -> dict:
        f = ev.fields
        doc = {
            "@timestamp": _util.iso(ev.timestamp),
            "ecs": {"version": ECS_VERSION},
            "event": {
                "kind": "event", "category": ["web"], "type": ["access"],
                "action": "http_request",
                "outcome": "success" if f["status"] < 400 else "failure",
                "dataset": self.dataset, "module": "nginx",
            },
            "data_stream": _util.ds(self.dataset),
            "host": {"name": f["server"]},
            "source": {"ip": f["src_ip"]},
            "url": {"original": f["url"], "path": f["url"].split("?")[0],
                    "domain": f.get("vhost")},
            "http": {
                "version": f.get("proto", "HTTP/1.1").split("/")[1],
                "request": {"method": f["method"], "referrer": f["referrer"]},
                "response": {"status_code": f["status"], "body": {"bytes": f["bytes"]}},
            },
            "user_agent": {"original": f["ua"]},
            "related": {"ip": [f["src_ip"]]},
            "message": self.render_native(ev),
        }
        if "?" in f["url"]:
            doc["url"]["query"] = f["url"].split("?", 1)[1]
        if ev.labels:
            doc["labels"] = ev.labels
        return doc
