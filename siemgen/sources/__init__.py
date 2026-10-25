"""Registry of available log sources."""
from .base import LogEvent, Source
from .nginx import NginxAccess
from .linux_auth import LinuxAuth
from .pfsense import PfSenseFirewall
from .auditd import LinuxAuditd
from .windows import WindowsSecurity
from .dns import DnsQueries
from .vpn import VpnAuth
from .mail import MailGateway
from .dhcp import Dhcp
from .suricata import Suricata
from .cloud_audit import CloudAudit
from .sysmon import Sysmon
from .azuread import AzureADSignin

# name -> Source class.
SOURCES: dict[str, type[Source]] = {
    NginxAccess.name: NginxAccess,
    LinuxAuth.name: LinuxAuth,
    PfSenseFirewall.name: PfSenseFirewall,
    LinuxAuditd.name: LinuxAuditd,
    WindowsSecurity.name: WindowsSecurity,
    DnsQueries.name: DnsQueries,
    VpnAuth.name: VpnAuth,
    MailGateway.name: MailGateway,
    Dhcp.name: Dhcp,
    Suricata.name: Suricata,
    CloudAudit.name: CloudAudit,
    Sysmon.name: Sysmon,
    AzureADSignin.name: AzureADSignin,
}

__all__ = ["Source", "LogEvent", "SOURCES"]
