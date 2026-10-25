"""Windows Security channel — synthesized for fictional Windows hosts.

There is no text file for Windows events on a real host (they live in EVTX). What a
SIEM receives is what a forwarding agent (Winlogbeat / NXLog / WEF) emits: one JSON
object per event carrying the raw ``winlog.*`` envelope (channel, event_id,
provider, record_id, keywords, opcode, task) and the raw ``winlog.event_data.*``
fields with their real names (``SubjectUserName``, ``NewProcessName``,
``LogonType``, ...), plus the human-readable ``message``.

``render_native`` is that raw agent JSON, WITHOUT any ECS normalisation: mapping
``event_data`` to ``user.*`` / ``process.*`` / ``event.action`` is the SIEM's (and
the student's) job. ``render_ecs`` is the normalised document.

Host-heavy ('EDR on'): the per-minute motor ``minute_events()`` emits 4688 process
creations with parent->child chains and command lines, plus periodic 4624 (network
logon), 4769 (Kerberos service ticket), 5140 (file share) and the occasional 4625."""
from __future__ import annotations

import hashlib
import json
import random
from datetime import datetime, timedelta

from .. import ECS_VERSION
from ..org.model import Host, Org, User
from . import _util
from .base import LogEvent, Source

# (executable, parent_executable, command-line suffix) — realistic process chains.
_USER_CHAINS = [
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Windows\explorer.exe", " --type=renderer --no-sandbox"),
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Windows\explorer.exe", ""),
    (r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", r"C:\Windows\explorer.exe", " /recycle"),
    (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", " /n /o"),
    (r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", r"C:\Windows\explorer.exe", ""),
    (r"C:\Users\Public\Teams\current\Teams.exe", r"C:\Windows\explorer.exe", " --type=gpu-process"),
    (r"C:\Program Files\Microsoft OneDrive\OneDrive.exe", r"C:\Windows\explorer.exe", " /background"),
    (r"C:\Windows\System32\notepad.exe", r"C:\Windows\explorer.exe", ""),
]
_SYS_CHAINS = [
    (r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\services.exe", " -k netsvcs -p"),
    (r"C:\Windows\System32\RuntimeBroker.exe", r"C:\Windows\System32\svchost.exe", " -Embedding"),
    (r"C:\Windows\System32\taskhostw.exe", r"C:\Windows\System32\svchost.exe", ""),
    (r"C:\Windows\System32\backgroundTaskHost.exe", r"C:\Windows\System32\svchost.exe", " -ServerName:App.AppX"),
    (r"C:\Windows\System32\SearchProtocolHost.exe", r"C:\Windows\System32\SearchIndexer.exe", ""),
    (r"C:\Windows\System32\MoUsoCoreWorker.exe", r"C:\Windows\System32\services.exe", ""),
]
_ADMIN_CHAINS = [
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"C:\Windows\explorer.exe", " -NoProfile -ExecutionPolicy Bypass"),
    (r"C:\Windows\System32\cmd.exe", r"C:\Windows\explorer.exe", " /c ipconfig /all"),
    (r"C:\Windows\System32\conhost.exe", r"C:\Windows\System32\cmd.exe", " 0xffffffff -ForceV1"),
    (r"C:\Windows\System32\mmc.exe", r"C:\Windows\explorer.exe", " compmgmt.msc"),
]

# event_id -> (action, ecs category, ecs type, outcome, task)
_ACTIONS = {
    4624: ("logged-in", ["authentication"], ["start"], "success", "Logon"),
    4625: ("logon-failed", ["authentication"], ["start"], "failure", "Logon"),
    4634: ("logged-out", ["authentication"], ["end"], "success", "Logoff"),
    4672: ("logged-in-special", ["iam"], ["admin"], "success", "Special Logon"),
    4688: ("created-process", ["process"], ["start"], "success", "Process Creation"),
    4769: ("kerberos-service-ticket-requested", ["authentication"], ["info"], "", "Kerberos Service Ticket Operations"),
    5140: ("network-share-accessed", ["file"], ["access"], "success", "File Share"),
}
_PROVIDER = "Microsoft-Windows-Security-Auditing"
_PROVIDER_GUID = "{54849625-5478-4994-a5ba-3e3b0328c30d}"
_LOGON_TYPES = {2: "Interactive", 3: "Network", 7: "Unlock", 10: "RemoteInteractive", 11: "CachedInteractive"}


def _sid(username: str) -> str:
    """Stable synthetic domain SID for a principal (S-1-5-21-<3 subauth>-<RID>)."""
    h = int(hashlib.md5(username.encode()).hexdigest()[:15], 16)
    return (f"S-1-5-21-{h % 4000000000}-{(h >> 8) % 4000000000}-"
            f"{(h >> 16) % 4000000000}-{1000 + h % 9000}")


def _exe_hash(exe: str) -> str:
    """Stable per-binary SHA-256 (same executable -> same hash across events)."""
    return hashlib.sha256(exe.encode()).hexdigest().upper()


def _logon_id(rng: random.Random) -> str:
    return f"0x{rng.randint(0x10000, 0xFFFFFFF):X}"


def _message(eid: int, ed: dict) -> str:
    """The event text as the Security channel renders it (multi-line, tab-indented)."""
    if eid == 4688:
        return ("A new process has been created.\n\nCreator Subject:\n"
                f"\tSecurity ID:\t\t{ed['SubjectUserSid']}\n\tAccount Name:\t\t{ed['SubjectUserName']}\n"
                f"\tAccount Domain:\t\t{ed['SubjectDomainName']}\n\tLogon ID:\t\t{ed['SubjectLogonId']}\n\n"
                f"Process Information:\n\tNew Process ID:\t\t{ed['NewProcessId']}\n"
                f"\tNew Process Name:\t{ed['NewProcessName']}\n\tToken Elevation Type:\t{ed['TokenElevationType']}\n"
                f"\tMandatory Label:\t\t{ed['MandatoryLabel']}\n\tCreator Process ID:\t{ed['ProcessId']}\n"
                f"\tCreator Process Name:\t{ed['ParentProcessName']}\n\tProcess Command Line:\t{ed['CommandLine']}")
    if eid == 4624:
        return ("An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n"
                "\tAccount Name:\t\tSYSTEM\n\nLogon Information:\n"
                f"\tLogon Type:\t\t{ed['LogonType']}\n\nNew Logon:\n\tSecurity ID:\t\t{ed['TargetUserSid']}\n"
                f"\tAccount Name:\t\t{ed['TargetUserName']}\n\tAccount Domain:\t\t{ed['TargetDomainName']}\n"
                f"\tLogon ID:\t\t{ed['TargetLogonId']}\n\nNetwork Information:\n"
                f"\tWorkstation Name:\t{ed['WorkstationName']}\n\tSource Network Address:\t{ed['IpAddress']}\n"
                f"\tSource Port:\t\t{ed['IpPort']}\n\nDetailed Authentication Information:\n"
                f"\tLogon Process:\t\t{ed['LogonProcessName']}\n\tAuthentication Package:\t{ed['AuthenticationPackageName']}")
    if eid == 4625:
        return ("An account failed to log on.\n\nAccount For Which Logon Failed:\n"
                f"\tAccount Name:\t\t{ed['TargetUserName']}\n\tAccount Domain:\t\t{ed['TargetDomainName']}\n\n"
                f"Failure Information:\n\tFailure Reason:\t\t{ed['FailureReason']}\n\tStatus:\t\t\t{ed['Status']}\n"
                f"\tSub Status:\t\t{ed['SubStatus']}\n\nNetwork Information:\n\tSource Network Address:\t{ed['IpAddress']}\n"
                f"\tSource Port:\t\t{ed['IpPort']}\n\nLogon Type:\t\t{ed['LogonType']}")
    if eid == 4634:
        return (f"An account was logged off.\n\nSubject:\n\tSecurity ID:\t\t{ed['TargetUserSid']}\n"
                f"\tAccount Name:\t\t{ed['TargetUserName']}\n\tAccount Domain:\t\t{ed['TargetDomainName']}\n"
                f"\tLogon ID:\t\t{ed['TargetLogonId']}\n\nLogon Type:\t\t{ed['LogonType']}")
    if eid == 4672:
        return (f"Special privileges assigned to new logon.\n\nSubject:\n\tSecurity ID:\t\t{ed['SubjectUserSid']}\n"
                f"\tAccount Name:\t\t{ed['SubjectUserName']}\n\tAccount Domain:\t\t{ed['SubjectDomainName']}\n"
                f"\tLogon ID:\t\t{ed['SubjectLogonId']}\n\nPrivileges:\t\t{ed['PrivilegeList']}")
    if eid == 4769:
        return ("A Kerberos service ticket was requested.\n\nAccount Information:\n"
                f"\tAccount Name:\t\t{ed['TargetUserName']}\n\tAccount Domain:\t\t{ed['TargetDomainName']}\n\n"
                f"Service Information:\n\tService Name:\t\t{ed['ServiceName']}\n\tService ID:\t\t{ed['ServiceSid']}\n\n"
                f"Network Information:\n\tClient Address:\t\t{ed['IpAddress']}\n\tClient Port:\t\t{ed['IpPort']}\n\n"
                f"Additional Information:\n\tTicket Options:\t\t{ed['TicketOptions']}\n"
                f"\tTicket Encryption Type:\t{ed['TicketEncryptionType']}\n\tFailure Code:\t\t{ed['Status']}")
    if eid == 5140:
        return (f"A network share object was accessed.\n\nSubject:\n\tSecurity ID:\t\t{ed['SubjectUserSid']}\n"
                f"\tAccount Name:\t\t{ed['SubjectUserName']}\n\tAccount Domain:\t\t{ed['SubjectDomainName']}\n\n"
                f"Network Information:\n\tSource Address:\t\t{ed['IpAddress']}\n\tSource Port:\t\t{ed['IpPort']}\n\n"
                f"Share Information:\n\tShare Name:\t\t{ed['ShareName']}\n\tShare Path:\t\t{ed['ShareLocalPath']}\n\n"
                f"Access Request Information:\n\tAccess Mask:\t\t{ed['AccessMask']}")
    return f"Windows Security event {eid}."


class WindowsSecurity(Source):
    name = "windows"
    dataset = "windows.security"

    def __init__(self) -> None:
        self.dns_domain = "acme.local"
        self.win_domain = "ACME"
        self.shares = [r"\\file\Finance", r"\\file\HR", r"\\file\Shared", r"\\dc\SYSVOL", r"\\dc\NETLOGON"]
        self.services = ["host/file.acme.local", "cifs/file.acme.local", "ldap/dc.acme.local",
                         "HTTP/intranet.acme.local", "krbtgt"]

    def bind(self, org: Org) -> None:
        super().bind(org)
        self.dns_domain = org.dns_domain
        self.win_domain = org.windows_domain
        d = org.dns_domain
        self.services = [f"host/file.{d}", f"cifs/file.{d}", f"ldap/dc.{d}", f"HTTP/intranet.{d}", "krbtgt"]

    def daily_volume(self, user: User, rng: random.Random) -> int:
        return max(1, int(rng.gauss(40, 14)))

    def applies_to(self, user: User, host: Host) -> bool:
        return host.os == "windows"

    def activity_weight(self, user: User) -> float:
        return 3.0

    # -- raw agent document (what Winlogbeat/NXLog forwards) -----------------
    def _raw(self, eid: int, ts: datetime, host: Host, event_data: dict,
             rng: random.Random, extra_winlog: dict | None = None) -> dict:
        _, _, _, outcome, task = _ACTIONS[eid]
        doc = {
            "@timestamp": _util.iso(ts),
            "host": {"name": _util.short(host.name).upper()},
            "log": {"level": "information"},
            "event": {"code": str(eid), "kind": "event", "provider": _PROVIDER,
                      "created": _util.iso(ts + timedelta(milliseconds=rng.randint(5, 900)))},
            "winlog": {
                "api": "wineventlog", "channel": "Security",
                "computer_name": host.name, "event_id": str(eid),
                "provider_name": _PROVIDER, "provider_guid": _PROVIDER_GUID,
                "record_id": int(ts.timestamp() * 1000) % 100_000_000,
                "keywords": ["Audit Failure"] if outcome == "failure" else ["Audit Success"],
                "opcode": "Info", "task": task, "version": 2 if eid in (4624, 4688) else 0,
                "process": {"pid": 4 if eid == 5140 else rng.choice([712, 716, 740]),
                            "thread": {"id": rng.randint(800, 9000)}},
                "event_data": event_data,
            },
            "message": _message(eid, event_data),
        }
        if extra_winlog:
            doc["winlog"].update(extra_winlog)
        return doc

    # -- individual event builders ------------------------------------------
    def _process_event(self, user: User, host: Host, ts: datetime, org: Org,
                       rng: random.Random) -> LogEvent:
        pool = _USER_CHAINS + _SYS_CHAINS + (_ADMIN_CHAINS if user.role in ("it-admin", "ops") else [])
        exe, parent, args = rng.choice(pool)
        system = exe.startswith(r"C:\Windows\System32")
        subj = "SYSTEM" if system and rng.random() < 0.6 else user.username
        cmdline = f'"{exe}"{args}'
        pid = rng.randint(0x400, 0x9000)
        ppid = rng.randint(0x200, 0x400)
        ed = {
            "SubjectUserSid": "S-1-5-18" if subj == "SYSTEM" else _sid(user.username),
            "SubjectUserName": f"{_util.short(host.name).upper()}$" if subj == "SYSTEM" else user.username,
            "SubjectDomainName": self.win_domain, "SubjectLogonId": "0x3E7" if subj == "SYSTEM" else _logon_id(rng),
            "NewProcessId": hex(pid), "NewProcessName": exe,
            "TokenElevationType": "%%1938" if subj == "SYSTEM" else "%%1936",
            "ProcessId": hex(ppid), "CommandLine": cmdline,
            "TargetUserSid": "S-1-0-0", "TargetUserName": "-", "TargetDomainName": "-", "TargetLogonId": "0x0",
            "ParentProcessName": parent, "MandatoryLabel": "S-1-16-16384" if subj == "SYSTEM" else "S-1-16-8192",
        }
        return LogEvent(timestamp=ts, source=self.name,
                        fields={"eid": 4688, "doc": self._raw(4688, ts, host, ed, rng), "user": user.username})

    def _logon_4624(self, user: User, host: Host, ts: datetime, org: Org,
                    rng: random.Random, logon_type: int = 3) -> LogEvent:
        pkg = "Kerberos" if logon_type in (3, 10) else "Negotiate"
        ed = {"SubjectUserSid": "S-1-5-18", "SubjectUserName": f"{_util.short(host.name).upper()}$",
              "SubjectDomainName": self.win_domain, "SubjectLogonId": "0x3E7",
              "TargetUserSid": _sid(user.username), "TargetUserName": user.username,
              "TargetDomainName": self.win_domain, "TargetLogonId": _logon_id(rng),
              "LogonType": str(logon_type), "LogonProcessName": "Kerberos" if pkg == "Kerberos" else "User32 ",
              "AuthenticationPackageName": pkg, "WorkstationName": _util.short(host.name).upper(),
              "LogonGuid": "{" + "-".join(_util.rhex(rng, n) for n in (8, 4, 4, 4, 12)) + "}",
              "TransmittedServices": "-", "LmPackageName": "-", "KeyLength": "0",
              "ProcessId": "0x0" if pkg == "Kerberos" else hex(rng.randint(0x200, 0x400)),
              "ProcessName": "-" if pkg == "Kerberos" else r"C:\Windows\System32\svchost.exe",
              "IpAddress": host.ip if logon_type == 3 else "127.0.0.1",
              "IpPort": str(rng.randint(40000, 65000)) if logon_type == 3 else "0",
              "ImpersonationLevel": "%%1833", "RestrictedAdminMode": "-", "TargetOutboundUserName": "-",
              "TargetOutboundDomainName": "-", "VirtualAccount": "%%1843", "TargetLinkedLogonId": "0x0",
              "ElevatedToken": "%%1843"}
        doc = self._raw(4624, ts, host, ed, rng,
                        extra_winlog={"logon": {"id": ed["TargetLogonId"],
                                                "type": _LOGON_TYPES.get(logon_type, "Network")}})
        return LogEvent(timestamp=ts, source=self.name,
                        fields={"eid": 4624, "doc": doc, "user": user.username})

    def _failed_4625(self, user: User, host: Host, ts: datetime, org: Org,
                     rng: random.Random) -> LogEvent:
        sub, reason = rng.choice([("0xC000006A", "%%2313"), ("0xC0000064", "%%2313"),
                                  ("0xC0000234", "%%2307")])
        ed = {"SubjectUserSid": "S-1-5-18", "SubjectUserName": f"{_util.short(host.name).upper()}$",
              "SubjectDomainName": self.win_domain, "SubjectLogonId": "0x3E7",
              "TargetUserSid": "S-1-0-0", "TargetUserName": user.username, "TargetDomainName": self.win_domain,
              "Status": "0xC000006D", "FailureReason": reason, "SubStatus": sub,
              "LogonType": str(rng.choice([2, 3])), "LogonProcessName": "NtLmSsp ",
              "AuthenticationPackageName": "NTLM", "WorkstationName": _util.short(host.name).upper(),
              "TransmittedServices": "-", "LmPackageName": "-", "KeyLength": "0", "ProcessId": "0x0",
              "ProcessName": "-", "IpAddress": host.ip, "IpPort": str(rng.randint(40000, 65000))}
        return LogEvent(timestamp=ts, source=self.name,
                        fields={"eid": 4625, "doc": self._raw(4625, ts, host, ed, rng), "user": user.username})

    def _kerberos_4769(self, user: User, host: Host, ts: datetime, org: Org,
                       rng: random.Random) -> LogEvent:
        svc = rng.choice(self.services)
        ed = {"TargetUserName": f"{user.username}@{self.dns_domain.upper()}",
              "TargetDomainName": self.dns_domain.upper(), "ServiceName": svc.split("/")[-1].split(".")[0].upper() + "$" if "/" in svc else svc,
              "ServiceSid": _sid("svc-" + svc), "TicketOptions": "0x40810000",
              "TicketEncryptionType": "0x12", "IpAddress": f"::ffff:{host.ip}",
              "IpPort": str(rng.randint(40000, 65000)), "Status": "0x0",
              "LogonGuid": "{" + "-".join(_util.rhex(rng, n) for n in (8, 4, 4, 4, 12)) + "}",
              "TransmittedServices": "-"}
        dc = org.server("dc") or host
        return LogEvent(timestamp=ts, source=self.name,
                        fields={"eid": 4769, "doc": self._raw(4769, ts, dc, ed, rng), "user": user.username})

    def _share_5140(self, user: User, host: Host, ts: datetime, org: Org,
                    rng: random.Random) -> LogEvent:
        share = rng.choice(self.shares)
        ed = {"SubjectUserSid": _sid(user.username), "SubjectUserName": user.username,
              "SubjectDomainName": self.win_domain, "SubjectLogonId": _logon_id(rng),
              "ObjectType": "File", "IpAddress": host.ip, "IpPort": str(rng.randint(40000, 65000)),
              "ShareName": share, "ShareLocalPath": r"\??\D:\shares" + "\\" + share.split("\\")[-1],
              "AccessMask": "0x1", "AccessList": "%%4416"}
        target = org.server("file" if share.startswith(r"\\file") else "dc") or host
        return LogEvent(timestamp=ts, source=self.name,
                        fields={"eid": 5140, "doc": self._raw(5140, ts, target, ed, rng), "user": user.username})

    def _logoff_4634(self, user: User, host: Host, ts: datetime, org: Org, rng: random.Random) -> LogEvent:
        ed = {"TargetUserSid": _sid(user.username), "TargetUserName": user.username,
              "TargetDomainName": self.win_domain, "TargetLogonId": _logon_id(rng), "LogonType": "2"}
        return LogEvent(timestamp=ts, source=self.name,
                        fields={"eid": 4634, "doc": self._raw(4634, ts, host, ed, rng), "user": user.username})

    def _special_4672(self, user: User, host: Host, ts: datetime, org: Org, rng: random.Random) -> LogEvent:
        ed = {"SubjectUserSid": _sid(user.username), "SubjectUserName": user.username,
              "SubjectDomainName": self.win_domain, "SubjectLogonId": _logon_id(rng),
              "PrivilegeList": "SeSecurityPrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeLoadDriverPrivilege\n"
                               "\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeDebugPrivilege\n"
                               "\t\t\tSeSystemEnvironmentPrivilege\n\t\t\tSeImpersonatePrivilege"}
        return LogEvent(timestamp=ts, source=self.name,
                        fields={"eid": 4672, "doc": self._raw(4672, ts, host, ed, rng), "user": user.username})

    # -- arrival logon (used by engine._logon_event) ------------------------
    def login_event(self, user: User, host: Host, ts: datetime, org: Org,
                    rng: random.Random, persona=None) -> LogEvent:
        """Interactive console logon (type 2) — how the user 'arrives' for the day."""
        return self._logon_4624(user, host, ts, org, rng, logon_type=2)

    # -- per-minute endpoint motor ('EDR on') -------------------------------
    def minute_events(self, user: User, host: Host, ts: datetime, org: Org,
                      rng: random.Random, rates: dict) -> list[LogEvent]:
        def t() -> datetime:
            return ts + timedelta(seconds=rng.randint(0, 59), microseconds=rng.randint(0, 999999))
        out: list[LogEvent] = []
        for _ in range(_util.jit(rng, rates.get("proc_per_min", 16))):
            out.append(self._process_event(user, host, t(), org, rng))
        if rng.random() < rates.get("logon_per_min", 0.15):
            out.append(self._logon_4624(user, host, t(), org, rng, logon_type=3))
        if rng.random() < rates.get("kerberos_per_min", 0.25):
            out.append(self._kerberos_4769(user, host, t(), org, rng))
        if rng.random() < rates.get("fileshare_per_min", 0.2):
            out.append(self._share_5140(user, host, t(), org, rng))
        if rng.random() < rates.get("failed_logon_per_min", 0.03):
            out.append(self._failed_4625(user, host, t(), org, rng))
        return out

    # -- generic make_event (activity lottery / classic backfill) -----------
    def make_event(self, user: User, host: Host, ts: datetime, org: Org,
                   rng: random.Random, persona=None) -> LogEvent:
        roll = rng.random()
        if roll < 0.72:
            return self._process_event(user, host, ts, org, rng)
        if roll < 0.80 and user.role == "it-admin":
            return self._special_4672(user, host, ts, org, rng)
        if roll < 0.88:
            return self._kerberos_4769(user, host, ts, org, rng)
        if roll < 0.95:
            return self._share_5140(user, host, ts, org, rng)
        return self._logoff_4634(user, host, ts, org, rng)

    # -- rendering ----------------------------------------------------------
    def render_native(self, ev: LogEvent) -> str:
        return json.dumps(ev.fields["doc"], default=str)

    def render_ecs(self, ev: LogEvent) -> dict:
        raw = ev.fields["doc"]
        eid = ev.fields["eid"]
        ed = raw["winlog"]["event_data"]
        action, category, etype, outcome, _ = _ACTIONS[eid]
        doc = json.loads(json.dumps(raw))          # deep copy of the raw envelope
        doc["ecs"] = {"version": ECS_VERSION}
        doc["event"].update({"action": action, "category": category, "type": etype,
                             "dataset": self.dataset, "module": "security"})
        if outcome:
            doc["event"]["outcome"] = outcome
        doc["data_stream"] = _util.ds(self.dataset)
        doc["host"] = {"name": raw["winlog"]["computer_name"], "os": {"type": "windows"}}
        user = ev.fields["user"]
        doc["user"] = {"name": user, "id": _sid(user), "domain": ed.get("TargetDomainName") or ed.get("SubjectDomainName")}
        related = {"user": [user], "hosts": [raw["winlog"]["computer_name"]]}
        ip = (ed.get("IpAddress") or "").replace("::ffff:", "")
        if ip and ip not in ("-", "127.0.0.1"):
            related["ip"] = [ip]
            doc["source"] = {"ip": ip, "port": int(ed.get("IpPort", "0") or 0)}
        doc["related"] = related
        if eid == 4688:
            exe, parent, args = ed["NewProcessName"], ed["ParentProcessName"], ed["CommandLine"]
            doc["process"] = {"executable": exe, "name": exe.split("\\")[-1],
                              "pid": int(ed["NewProcessId"], 16), "command_line": args,
                              "args": [exe] + args[len(exe) + 2:].split(),
                              "hash": {"sha256": _exe_hash(exe)},
                              "parent": {"executable": parent, "name": parent.split("\\")[-1],
                                         "pid": int(ed["ProcessId"], 16), "command_line": f'"{parent}"'}}
        if eid == 5140:
            doc["file"] = {"path": ed["ShareName"], "directory": ed["ShareLocalPath"]}
        if ev.labels:
            doc["labels"] = ev.labels
        return doc
