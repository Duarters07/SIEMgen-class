"""Nextcloud ``admin_audit`` log (audit.log, one JSON object per line) — file and
account activity on the company's private cloud.

``render_native`` follows the real Nextcloud log record: ``reqId``, ``level``,
``time`` (ISO-8601 with offset), ``remoteAddr``, ``user``, ``app: admin_audit``,
``method``, ``url`` (the WebDAV / OCS endpoint), a human ``message`` such as
``File accessed: "/Documents/budget-42.xlsx"``, ``userAgent`` and ``version``. The
action type is only inside ``message`` — extracting it is the parsing exercise.

Mirrors the CLUE-LDS cloud-audit signal studied in the dissertation's SLM-UEBA work."""
from __future__ import annotations

import json
import random
from datetime import datetime

from .. import ECS_VERSION
from ..org.model import Host, Org, User
from . import _util
from .base import LogEvent, Source

# action -> (ecs category, ecs type, http method, message template)
_ACTIONS = {
    "login": ("authentication", "start", "POST", 'Login successful: "{user}"'),
    "logout": ("authentication", "end", "GET", 'Logout occurred'),
    "file_accessed": ("file", "access", "PROPFIND", 'File accessed: "{path}"'),
    "file_created": ("file", "creation", "PUT", 'File created: "{path}"'),
    "file_modified": ("file", "change", "PUT", 'File written: "{path}"'),
    "file_downloaded": ("file", "access", "GET", 'File accessed: "{path}"'),
    "file_shared": ("file", "change", "POST", 'The user "{user}" shared "{path}" with "{target}" (type "user")'),
    "file_deleted": ("file", "deletion", "DELETE", 'File deleted: "{path}"'),
    "file_renamed": ("file", "change", "MOVE", 'File renamed: "{path}" to "{path2}"'),
}
_WEIGHTS = [3, 1, 30, 6, 10, 5, 3, 1, 1]
_DIRS = ["/Documents", "/Reports", "/Shared", "/Finance", "/HR", "/Projects", "/Contracts", "/Photos"]
_NAMES = ["budget", "plan", "memo", "review", "data", "notes", "minutes", "invoice", "forecast", "policy"]
_EXT = ["docx", "xlsx", "pdf", "pptx", "csv", "txt", "md"]
_UA_DESKTOP = "Mozilla/5.0 (Windows) mirall/3.13.2stable-Win64 (build 20240710) (Nextcloud, windows-10.0.19045 ClientArchitecture: x86_64 OsArchitecture: x86_64)"
_UA_DESKTOP_LINUX = "Mozilla/5.0 (Linux) mirall/3.13.2 (Nextcloud, ubuntu-6.8.0 ClientArchitecture: x86_64 OsArchitecture: x86_64)"
_VERSION = "29.0.4.1"


class CloudAudit(Source):
    name = "cloud_audit"
    dataset = "nextcloud.audit"

    def daily_volume(self, user: User, rng: random.Random) -> int:
        return max(1, int(rng.gauss(15, 6)))

    def activity_weight(self, user: User) -> float:
        return 2.0

    def make_event(self, user: User, host: Host, ts: datetime, org: Org,
                   rng: random.Random, persona=None) -> LogEvent:
        action = rng.choices(list(_ACTIONS), weights=_WEIGHTS, k=1)[0]
        d = rng.choice(_DIRS)
        path = f"{d}/{rng.choice(_NAMES)}-{rng.randint(1, 999)}.{rng.choice(_EXT)}"
        path2 = f"{d}/{rng.choice(_NAMES)}-{rng.randint(1, 999)}.{path.rsplit('.', 1)[-1]}"
        target = rng.choice([u.username for u in org.users if u.username != user.username][:50]) if org.users else "-"
        browser = rng.random() < 0.4
        if browser:
            ua = persona.ua if persona is not None else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        else:
            ua = _UA_DESKTOP if host.os == "windows" else _UA_DESKTOP_LINUX
        cat, etype, method, tmpl = _ACTIONS[action]
        if action == "login":
            url = "/index.php/login" if browser else "/index.php/login/v2/poll"
        elif action == "logout":
            url = "/index.php/logout"
        elif action == "file_shared":
            url = "/ocs/v2.php/apps/files_sharing/api/v1/shares"
        elif action in ("file_downloaded", "file_accessed") and browser:
            url = f"/index.php/apps/files/ajax/download.php?dir={d}&files={path.split('/')[-1]}"
            method = "GET"
        else:
            url = f"/remote.php/dav/files/{user.username}{path}"
        return LogEvent(timestamp=ts, source=self.name, fields={
            "user": user.username, "action": action, "path": path, "path2": path2,
            "target": target, "ip": host.ip, "method": method, "url": url, "ua": ua,
            "reqid": _util.rhex(rng, 20).translate(str.maketrans("abcdef", "ABCDEF")) if rng.random() < 0.5 else _util.rhex(rng, 20),
            "message": tmpl.format(user=user.username, path=path, path2=path2, target=target),
        })

    def render_native(self, ev: LogEvent) -> str:
        f = ev.fields
        rec = {"reqId": f["reqid"], "level": 1,
               "time": ev.timestamp.strftime("%Y-%m-%dT%H:%M:%S") + "+00:00",
               "remoteAddr": f["ip"], "user": f["user"], "app": "admin_audit",
               "method": f["method"], "url": f["url"], "message": f["message"],
               "userAgent": f["ua"], "version": _VERSION, "data": {"app": "admin_audit"}}
        return json.dumps(rec, default=str)

    def render_ecs(self, ev: LogEvent) -> dict:
        f = ev.fields
        category, etype, _, _ = _ACTIONS[f["action"]]
        doc = {
            "@timestamp": _util.iso(ev.timestamp),
            "ecs": {"version": ECS_VERSION},
            "event": {"kind": "event", "category": [category], "type": [etype],
                      "action": f["action"], "outcome": "success",
                      "dataset": self.dataset, "module": "nextcloud", "id": f["reqid"]},
            "data_stream": _util.ds(self.dataset),
            "source": {"ip": f["ip"]},
            "user": {"name": f["user"]},
            "user_agent": {"original": f["ua"]},
            "url": {"path": f["url"].split("?")[0], "original": f["url"]},
            "http": {"request": {"method": f["method"]}},
            "related": {"ip": [f["ip"]], "user": [f["user"]]},
            "message": f["message"],
        }
        if f["action"].startswith("file"):
            doc["file"] = {"path": f["path"], "name": f["path"].split("/")[-1],
                           "extension": f["path"].split(".")[-1],
                           "directory": f["path"].rsplit("/", 1)[0]}
        if f["action"] == "file_shared":
            doc["related"]["user"].append(f["target"])
            doc["destination"] = {"user": {"name": f["target"]}}
        if ev.labels:
            doc["labels"] = ev.labels
        return doc
