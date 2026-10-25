"""Azure AD / Entra ID sign-in logs — cloud identity events.

``render_native`` is the record as exported by Azure Monitor diagnostic settings
(Event Hub / Storage / Log Analytics export): top-level ``time``, ``resourceId``,
``operationName``, ``category: SignInLogs``, ``resultType``, ``callerIpAddress`` and
the nested ``properties`` object with ``userPrincipalName``, ``appDisplayName``,
``status.errorCode``, ``deviceDetail``, ``location``, ``conditionalAccessStatus`` ...
No ECS fields: mapping this to ``user.*`` / ``source.*`` / ``event.outcome`` is the
SIEM's job. ``render_ecs`` is that normalised document.

The org talks to M365 all day, so a real tenant emits a steady stream of interactive
and non-interactive (token refresh) sign-ins. Source IP is the corporate egress
(public) address, not the workstation's RFC1918 IP."""
from __future__ import annotations

import hashlib
import json
import random
from datetime import datetime, timedelta

from .. import ECS_VERSION
from ..org.model import Host, Org, User
from . import _util
from .base import LogEvent, Source

# (app display name, app id, resource)
_APPS = [
    ("Office365 Shell WCSS-Client", "89bee1f7-5e6e-4d8a-9f3d-ecd601259da7", "Office 365 Exchange Online"),
    ("Microsoft Teams", "1fec8e78-bce4-4aaf-ab1b-5451cc387264", "Microsoft Graph"),
    ("SharePoint Online", "00000003-0000-0ff1-ce00-000000000000", "Office 365 SharePoint Online"),
    ("Outlook Web App", "00000002-0000-0ff1-ce00-000000000000", "Office 365 Exchange Online"),
    ("OneDrive SyncEngine", "ab9b8c07-8f02-4f72-87fa-80105867a763", "Office 365 SharePoint Online"),
    ("Microsoft Authentication Broker", "29d9ed98-a469-4536-ade2-f981bc1d605e", "Device Registration Service"),
    ("Azure Portal", "c44b4083-3bb0-49c1-b47d-974e53cbdf3c", "Windows Azure Service Management API"),
    ("Microsoft 365 Security and Compliance Center", "80ccca67-54bd-44ab-8625-4b79c4dc7775", "Microsoft Graph"),
]
_BROWSERS = [("Chrome 124.0.0", "Browser"), ("Edge 123.0.0", "Browser"), ("Firefox 125.0", "Browser"),
             ("", "Mobile Apps and Desktop clients"), ("", "Exchange ActiveSync")]
_UA = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
       "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0)"]
# common sign-in error codes (0 = success)
_ERRORS = [(50126, "Error validating credentials due to invalid username or password."),
           (50053, "Account is locked because user tried to sign in too many times with an incorrect user ID or password."),
           (50074, "Strong Authentication is required."),
           (53003, "Access has been blocked by Conditional Access policies. The access policy does not allow token issuance.")]


def _guid(rng: random.Random) -> str:
    return "-".join(_util.rhex(rng, n) for n in (8, 4, 4, 4, 12))


def _stable_guid(*parts) -> str:
    h = hashlib.md5("|".join(str(p) for p in parts).encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


class AzureADSignin(Source):
    name = "azuread"
    dataset = "azure.signinlogs"

    def __init__(self) -> None:
        self.tenant = _stable_guid("tenant", "acme")
        self.egress = "194.65.1.1"
        self.upn_domain = "acme.local"

    def bind(self, org: Org) -> None:
        super().bind(org)
        self.tenant = _stable_guid("tenant", org.name)
        self.egress = org.egress_ip
        self.upn_domain = org.dns_domain

    def daily_volume(self, user: User, rng: random.Random) -> int:
        return max(1, int(rng.gauss(8, 3)))

    def activity_weight(self, user: User) -> float:
        return 0.0   # driven by the per-minute motor

    def _signin(self, user: User, host: Host, ts: datetime, org: Org,
                rng: random.Random) -> LogEvent:
        ok = rng.random() > 0.06
        interactive = rng.random() < 0.5
        app, app_id, resource = rng.choice(_APPS)
        if host.os == "windows":
            browser, client = rng.choice(_BROWSERS)
            ua = rng.choice(_UA)
        else:                                   # Linux workstation: browser sign-ins only
            browser, client = "Firefox 125.0", "Browser"
            ua = "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
        if client != "Browser" and host.os == "windows":
            ua = _UA[2]                         # thick client -> Office user agent
        err_code, err_msg = (0, "Other.") if ok else rng.choice(_ERRORS)
        upn = f"{user.username}@{self.upn_domain}"
        rec = {
            "time": ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z",
            "resourceId": f"/tenants/{self.tenant}/providers/Microsoft.aadiam",
            "operationName": "Sign-in activity", "operationVersion": "1.0",
            "category": "SignInLogs" if interactive else "NonInteractiveUserSignInLogs",
            "tenantId": self.tenant, "resultType": str(err_code),
            "resultSignature": "None", "resultDescription": err_msg if not ok else "",
            "durationMs": 0, "callerIpAddress": self.egress,
            "correlationId": _guid(rng), "identity": user.full_name, "Level": 4,
            "location": "PT",
            "properties": {
                "id": _guid(rng), "createdDateTime": ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z",
                "userDisplayName": user.full_name, "userPrincipalName": upn,
                "userId": _stable_guid("user", upn), "appId": app_id, "appDisplayName": app,
                "ipAddress": self.egress, "status": {"errorCode": err_code, "failureReason": err_msg,
                                                     "additionalDetails": "MFA requirement satisfied by claim in the token" if ok and interactive else None},
                "clientAppUsed": client, "userAgent": ua,
                "deviceDetail": {"deviceId": _stable_guid("dev", host.name) if host.os == "windows" else "",
                                 "displayName": _util.short(host.name).upper() if host.os == "windows" else "",
                                 "operatingSystem": "Windows10" if host.os == "windows" else "Linux",
                                 "browser": browser, "isCompliant": host.os == "windows",
                                 "isManaged": host.os == "windows", "trustType": "Azure AD joined" if host.os == "windows" else ""},
                "location": {"city": "Lisbon", "state": "Lisboa", "countryOrRegion": "PT",
                             "geoCoordinates": {"latitude": 38.72, "longitude": -9.14}},
                "correlationId": _guid(rng), "conditionalAccessStatus": "success" if ok else "failure",
                "appliedConditionalAccessPolicies": [
                    {"id": _stable_guid("ca", "mfa-all"), "displayName": "Require MFA for all users",
                     "enforcedGrantControls": ["Mfa"], "result": "success" if ok else "failure"}],
                "isInteractive": interactive, "riskDetail": "none", "riskLevelAggregated": "none",
                "riskLevelDuringSignIn": "none", "riskState": "none", "riskEventTypes": [],
                "resourceDisplayName": resource, "resourceId": _stable_guid("res", resource),
                "authenticationMethodsUsed": [], "authenticationDetails": [],
                "authenticationRequirement": "multiFactorAuthentication" if interactive else "singleFactorAuthentication",
                "tokenIssuerType": "AzureAD", "tokenIssuerName": "",
                "processingTimeInMilliseconds": rng.randint(40, 400),
                "networkLocationDetails": [{"networkType": "namedNetwork", "networkNames": ["Corporate HQ"]}],
                "userType": "Member", "flaggedForReview": False, "isTenantRestricted": False,
                "crossTenantAccessType": "none", "uniqueTokenIdentifier": _util.rhex(rng, 32),
                "incomingTokenType": "none", "authenticationProtocol": "none",
                "signInEventTypes": ["interactiveUser" if interactive else "nonInteractiveUser"],
            },
        }
        return LogEvent(timestamp=ts, source=self.name,
                        fields={"rec": rec, "ok": ok, "user": user.username, "email": upn,
                                "app": app, "err_msg": err_msg, "interactive": interactive})

    def make_event(self, user, host, ts, org, rng, persona=None):
        return self._signin(user, host, ts, org, rng)

    def minute_events(self, user: User, host: Host, ts: datetime, org: Org,
                      rng: random.Random, rates: dict) -> list[LogEvent]:
        """Cloud sign-ins are OS-independent and low-rate (a handful per user per day)."""
        out = []
        if rng.random() < rates.get("signin_per_min", 0.08):
            tt = ts + timedelta(seconds=rng.randint(0, 59), microseconds=rng.randint(0, 999999))
            out.append(self._signin(user, host, tt, org, rng))
        return out

    def render_native(self, ev: LogEvent) -> str:
        return json.dumps(ev.fields["rec"], default=str)

    def render_ecs(self, ev: LogEvent) -> dict:
        f = ev.fields
        r = f["rec"]; p = r["properties"]
        ok = f["ok"]
        doc = {
            "@timestamp": _util.iso(ev.timestamp),
            "ecs": {"version": ECS_VERSION},
            "event": {"kind": "event", "category": ["authentication"], "type": ["start"],
                      "action": r["operationName"], "outcome": "success" if ok else "failure",
                      "dataset": self.dataset, "module": "azure", "id": p["id"]},
            "data_stream": _util.ds(self.dataset),
            "cloud": {"provider": "azure", "account": {"id": r["tenantId"]}},
            "source": {"ip": r["callerIpAddress"]},
            "user": {"name": f["user"], "email": f["email"], "full_name": p["userDisplayName"],
                     "id": p["userId"], "domain": self.upn_domain},
            "user_agent": {"original": p["userAgent"]},
            "azure": {"tenant_id": r["tenantId"], "correlation_id": r["correlationId"],
                      "signinlogs": {"operation_name": r["operationName"], "category": r["category"],
                                     "result_type": r["resultType"], "identity": r["identity"],
                                     "properties": {
                                         "app_display_name": p["appDisplayName"], "app_id": p["appId"],
                                         "is_interactive": p["isInteractive"],
                                         "conditional_access_status": p["conditionalAccessStatus"],
                                         "status": {"error_code": p["status"]["errorCode"]},
                                         "authentication_requirement": p["authenticationRequirement"],
                                         "client_app_used": p["clientAppUsed"],
                                         "device_detail": p["deviceDetail"], "resource_display_name": p["resourceDisplayName"],
                                         "user_principal_name": p["userPrincipalName"]}}},
            "related": {"ip": [r["callerIpAddress"]], "user": [f["user"]]},
            "message": (f"Sign-in {'succeeded' if ok else 'failed'} for {f['email']} "
                        f"to {f['app']} from {r['callerIpAddress']}" + ("" if ok else f" ({f['err_msg']})")),
        }
        geo, asd = _util.geo_as(r["callerIpAddress"])
        if geo:
            doc["source"]["geo"] = geo
            doc["source"]["as"] = asd
        if not ok:
            doc["azure"]["signinlogs"]["properties"]["status"]["failure_reason"] = f["err_msg"]
        if ev.labels:
            doc["labels"] = ev.labels
        return doc
