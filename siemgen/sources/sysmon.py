"""Sysmon (Microsoft-Windows-Sysmon/Operational) — rich endpoint telemetry the native
Security channel lacks: process creation with hashes (EID 1), per-process network
connections (EID 3), file creation (EID 11) and per-process DNS queries (EID 22).

``render_native`` is the raw agent JSON (``winlog.*`` envelope + ``winlog.event_data``
with Sysmon's own field names: Image, CommandLine, DestinationIp, QueryName, ...)
WITHOUT ECS normalisation. ``render_ecs`` maps it to ``process.*`` / ``network.*`` /
``dns.*`` / ``file.*`` and adds community_id and GeoIP."""
from __future__ import annotations

import hashlib
import json
import random
from datetime import datetime, timedelta

from .. import ECS_VERSION
from ..org.model import Host, Org, User
from . import _util
from .base import LogEvent, Source

_IMAGES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
    r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
    r"C:\Users\Public\Teams\current\Teams.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Program Files\Microsoft OneDrive\OneDrive.exe",
    r"C:\Windows\Explorer.EXE",
]
_DEST_DOMS = ["teams.microsoft.com", "outlook.office365.com", "clients4.google.com",
              "graph.microsoft.com", "www.google.com", "login.microsoftonline.com",
              "github.com", "fonts.gstatic.com", "self.events.data.microsoft.com"]
_CDN = ["142.250", "172.217", "20.190", "13.107", "104.16", "52.96", "40.126"]
_FILE_DIRS = [r"C:\Users\{u}\AppData\Local\Temp", r"C:\Users\{u}\Downloads",
              r"C:\Users\{u}\AppData\Roaming\Microsoft\Office\Recent",
              r"C:\ProgramData\Microsoft\Windows"]
_EXTS = ["tmp", "docx", "xlsx", "pdf", "log", "dat", "etl", "json"]
_PROVIDER = "Microsoft-Windows-Sysmon"
_PROVIDER_GUID = "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
_TASKS = {1: "Process Create (rule: ProcessCreate)", 3: "Network connection detected (rule: NetworkConnect)",
          11: "File created (rule: FileCreate)", 22: "Dns query (rule: DnsQuery)"}


def _guid(rng: random.Random) -> str:
    return "{" + "-".join(_util.rhex(rng, n) for n in (8, 4, 4, 4, 12)) + "}"


def _ext_ip(rng: random.Random) -> str:
    return f"{rng.choice(_CDN)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _utc(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S.") + f"{ts.microsecond // 1000:03d}"


class Sysmon(Source):
    name = "sysmon"
    dataset = "windows.sysmon_operational"

    def __init__(self) -> None:
        self.win_domain = "ACME"

    def bind(self, org: Org) -> None:
        super().bind(org)
        self.win_domain = org.windows_domain

    def daily_volume(self, user: User, rng: random.Random) -> int:
        return max(1, int(rng.gauss(30, 10)))

    def applies_to(self, user: User, host: Host) -> bool:
        return host.os == "windows"

    def activity_weight(self, user: User) -> float:
        return 0.0   # driven by the per-minute motor, not the activity lottery

    # -- raw agent envelope -------------------------------------------------
    def _raw(self, eid: int, ts: datetime, host: Host, ed: dict, rng: random.Random) -> dict:
        return {
            "@timestamp": _util.iso(ts),
            "host": {"name": _util.short(host.name).upper()},
            "log": {"level": "information"},
            "event": {"code": str(eid), "kind": "event", "provider": _PROVIDER,
                      "created": _util.iso(ts + timedelta(milliseconds=rng.randint(5, 400)))},
            "winlog": {"api": "wineventlog", "channel": "Microsoft-Windows-Sysmon/Operational",
                       "computer_name": host.name, "event_id": str(eid),
                       "provider_name": _PROVIDER, "provider_guid": _PROVIDER_GUID,
                       "record_id": int(ts.timestamp() * 1000) % 100_000_000,
                       "opcode": "Info", "task": _TASKS[eid], "version": {1: 5, 3: 5, 11: 2, 22: 5}[eid],
                       "process": {"pid": rng.choice([3012, 3140, 2988]), "thread": {"id": rng.randint(800, 9000)}},
                       "user": {"identifier": "S-1-5-18", "name": "SYSTEM", "domain": "NT AUTHORITY", "type": "User"},
                       "event_data": ed},
            "message": "\n".join(f"{k}: {v}" for k, v in ed.items()),
        }

    def _user(self, user: User) -> str:
        return f"{self.win_domain}\\{user.username}"

    # -- event builders -----------------------------------------------------
    def _proc(self, user, host, ts, org, rng):
        img = rng.choice(_IMAGES)
        sha = hashlib.sha256(img.encode()).hexdigest().upper()
        md5 = hashlib.md5(img.encode()).hexdigest().upper()
        ed = {"RuleName": "-", "UtcTime": _utc(ts), "ProcessGuid": _guid(rng),
              "ProcessId": str(rng.randint(1000, 40000)), "Image": img,
              "FileVersion": "-", "Description": "-", "Product": "-", "Company": "-",
              "OriginalFileName": img.split("\\")[-1], "CommandLine": f'"{img}"',
              "CurrentDirectory": f"C:\\Users\\{user.username}\\", "User": self._user(user),
              "LogonGuid": _guid(rng), "LogonId": f"0x{rng.randint(0x10000, 0xFFFFFF):X}",
              "TerminalSessionId": "1", "IntegrityLevel": "Medium",
              "Hashes": f"SHA256={sha},MD5={md5}", "ParentProcessGuid": _guid(rng),
              "ParentProcessId": str(rng.randint(600, 1500)), "ParentImage": r"C:\Windows\explorer.exe",
              "ParentCommandLine": r"C:\Windows\Explorer.EXE", "ParentUser": self._user(user)}
        return LogEvent(timestamp=ts, source=self.name,
                        fields={"eid": 1, "doc": self._raw(1, ts, host, ed, rng), "user": user.username, "host": host})

    def _net(self, user, host, ts, org, rng):
        img = rng.choice(_IMAGES); dom = rng.choice(_DEST_DOMS)
        dip = _ext_ip(rng); sp = rng.randint(49152, 65535)
        dp = rng.choice([443, 443, 80]); tr = rng.choices(["tcp", "udp"], weights=[0.85, 0.15], k=1)[0]
        ed = {"RuleName": "-", "UtcTime": _utc(ts), "ProcessGuid": _guid(rng),
              "ProcessId": str(rng.randint(1000, 40000)), "Image": img, "User": self._user(user),
              "Protocol": tr, "Initiated": "true", "SourceIsIpv6": "false", "SourceIp": host.ip,
              "SourceHostname": host.name, "SourcePort": str(sp), "SourcePortName": "-",
              "DestinationIsIpv6": "false", "DestinationIp": dip, "DestinationHostname": dom,
              "DestinationPort": str(dp), "DestinationPortName": "https" if dp == 443 else "http"}
        return LogEvent(timestamp=ts, source=self.name,
                        fields={"eid": 3, "doc": self._raw(3, ts, host, ed, rng), "user": user.username, "host": host})

    def _file(self, user, host, ts, org, rng):
        img = rng.choice(_IMAGES); ext = rng.choice(_EXTS)
        path = rng.choice(_FILE_DIRS).format(u=user.username) + f"\\{_util.rhex(rng, 6)}.{ext}"
        ed = {"RuleName": "-", "UtcTime": _utc(ts), "ProcessGuid": _guid(rng),
              "ProcessId": str(rng.randint(1000, 40000)), "Image": img, "TargetFilename": path,
              "CreationUtcTime": _utc(ts), "User": self._user(user)}
        return LogEvent(timestamp=ts, source=self.name,
                        fields={"eid": 11, "doc": self._raw(11, ts, host, ed, rng), "user": user.username, "host": host})

    def _dns(self, user, host, ts, org, rng):
        img = rng.choice(_IMAGES); dom = rng.choice(_DEST_DOMS); ip = _ext_ip(rng)
        ed = {"RuleName": "-", "UtcTime": _utc(ts), "ProcessGuid": _guid(rng),
              "ProcessId": str(rng.randint(1000, 40000)), "QueryName": dom, "QueryStatus": "0",
              "QueryResults": f"::ffff:{ip};", "Image": img, "User": self._user(user)}
        return LogEvent(timestamp=ts, source=self.name,
                        fields={"eid": 22, "doc": self._raw(22, ts, host, ed, rng), "user": user.username, "host": host})

    def make_event(self, user, host, ts, org, rng, persona=None):
        return self._proc(user, host, ts, org, rng)

    def minute_events(self, user: User, host: Host, ts: datetime, org: Org,
                      rng: random.Random, rates: dict) -> list[LogEvent]:
        def t():
            return ts + timedelta(seconds=rng.randint(0, 59), microseconds=rng.randint(0, 999999))
        out = []
        for _ in range(_util.jit(rng, rates.get("net_per_min", 4))):
            out.append(self._net(user, host, t(), org, rng))
        for _ in range(_util.jit(rng, rates.get("dns_per_min", 2))):
            out.append(self._dns(user, host, t(), org, rng))
        for _ in range(_util.jit(rng, rates.get("file_per_min", 1.5))):
            out.append(self._file(user, host, t(), org, rng))
        for _ in range(_util.jit(rng, rates.get("proc_per_min", 1))):
            out.append(self._proc(user, host, t(), org, rng))
        return out

    # -- rendering ----------------------------------------------------------
    def render_native(self, ev: LogEvent) -> str:
        return json.dumps(ev.fields["doc"], default=str)

    def render_ecs(self, ev: LogEvent) -> dict:
        raw = ev.fields["doc"]; eid = ev.fields["eid"]; ed = raw["winlog"]["event_data"]
        host: Host = ev.fields["host"]; user = ev.fields["user"]
        doc = json.loads(json.dumps(raw))
        doc["ecs"] = {"version": ECS_VERSION}
        doc["data_stream"] = _util.ds(self.dataset)
        doc["event"].update({"dataset": self.dataset, "module": "sysmon"})
        doc["host"] = {"name": host.name, "os": {"type": "windows"}}
        doc["user"] = {"name": user, "domain": self.win_domain}
        doc["related"] = {"user": [user], "hosts": [host.name]}
        img = ed["Image"]
        doc["process"] = {"executable": img, "name": img.split("\\")[-1],
                          "pid": int(ed["ProcessId"]), "entity_id": ed["ProcessGuid"]}
        if eid == 1:
            doc["event"].update({"action": "Process Create (rule: ProcessCreate)", "category": ["process"], "type": ["start"]})
            hashes = dict(h.split("=") for h in ed["Hashes"].split(","))
            doc["process"].update({"command_line": ed["CommandLine"], "working_directory": ed["CurrentDirectory"],
                                   "hash": {k.lower(): v for k, v in hashes.items()},
                                   "parent": {"executable": ed["ParentImage"], "name": ed["ParentImage"].split("\\")[-1],
                                              "pid": int(ed["ParentProcessId"]), "entity_id": ed["ParentProcessGuid"],
                                              "command_line": ed["ParentCommandLine"]}})
        elif eid == 3:
            doc["event"].update({"action": "Network connection detected (rule: NetworkConnect)",
                                 "category": ["network"], "type": ["connection", "start"]})
            sp, dp, tr, dip = int(ed["SourcePort"]), int(ed["DestinationPort"]), ed["Protocol"], ed["DestinationIp"]
            doc["source"] = {"ip": ed["SourceIp"], "port": sp}
            doc["destination"] = {"ip": dip, "port": dp, "domain": ed["DestinationHostname"]}
            doc["network"] = {"transport": tr, "protocol": ed["DestinationPortName"], "direction": "egress"}
            cid = _util.community_id(ed["SourceIp"], dip, sp, dp, tr)
            if cid:
                doc["network"]["community_id"] = cid
            geo, asd = _util.geo_as(dip)
            if geo:
                doc["destination"]["geo"] = geo; doc["destination"]["as"] = asd
            doc["related"]["ip"] = [ed["SourceIp"], dip]; doc["related"]["hosts"].append(ed["DestinationHostname"])
        elif eid == 11:
            doc["event"].update({"action": "File created (rule: FileCreate)", "category": ["file"], "type": ["creation"]})
            p = ed["TargetFilename"]
            doc["file"] = {"path": p, "name": p.split("\\")[-1], "extension": p.rsplit(".", 1)[-1],
                           "directory": p.rsplit("\\", 1)[0]}
        elif eid == 22:
            doc["event"].update({"action": "Dns query (rule: DnsQuery)", "category": ["network"], "type": ["connection", "protocol"]})
            ip = ed["QueryResults"].replace("::ffff:", "").rstrip(";")
            doc["dns"] = {"question": {"name": ed["QueryName"], "type": "A"}, "resolved_ip": [ip], "type": "answer"}
            doc["related"]["hosts"].append(ed["QueryName"]); doc["related"]["ip"] = [ip]
        if ev.labels:
            doc["labels"] = ev.labels
        return doc
