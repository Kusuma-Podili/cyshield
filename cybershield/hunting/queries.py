"""
Enterprise Threat Hunting Query Library and Templates.
Provides curated queries and patterns for proactively hunting stealthy attacker behaviors.
"""

from typing import Dict, List
from cybershield.hunting.schemas import HuntTemplate


BUILTIN_HUNT_TEMPLATES: List[HuntTemplate] = [
    HuntTemplate(
        id="HUNT-T1059-001",
        name="Suspicious Encoded PowerShell Execution",
        category="Execution",
        description="Detects PowerShell executions with encoded commands, bypass flags, or download cradles commonly used to evade script logging.",
        mitre_technique_id="T1059.001",
        data_sources=["edr_process", "sysmon", "auditd"],
        default_query="process_name =~ /powershell/i AND (command_line =~ /-enc/i OR command_line =~ /-encodedcommand/i OR command_line =~ /downloadstring/i OR command_line =~ /iex/i)",
        severity="HIGH",
    ),
    HuntTemplate(
        id="HUNT-T1218-LOLBAS",
        name="Living Off The Land Binaries and Scripts (LOLBAS)",
        category="Defense Evasion",
        description="Identifies standard signed system binaries (certutil, bitsadmin, mshta, regsvr32, rundll32) invoked with network download or execution parameters.",
        mitre_technique_id="T1218",
        data_sources=["edr_process", "endpoint_telemetry"],
        default_query=r"(process_name =~ /certutil/i AND command_line =~ /-urlcache/i) OR (process_name =~ /bitsadmin/i AND command_line =~ /\/transfer/i) OR (process_name =~ /mshta/i AND command_line =~ /http/i) OR (process_name =~ /regsvr32/i AND command_line =~ /\/s.*http/i)",
        severity="HIGH",
    ),
    HuntTemplate(
        id="HUNT-T1003-001",
        name="LSASS Memory Dumping and Credential Access",
        category="Credential Access",
        description="Hunts for command line references to LSASS process dumping via comsvcs.dll, procdump, or Taskmgr.",
        mitre_technique_id="T1003.001",
        data_sources=["edr_process", "edr_driver"],
        default_query="command_line =~ /comsvcs.*minidump/i OR (process_name =~ /procdump/i AND command_line =~ /lsass/i) OR command_line =~ /dumpcreds/i",
        severity="CRITICAL",
    ),
    HuntTemplate(
        id="HUNT-T1053-005",
        name="Suspicious Scheduled Task Creation via Command Line",
        category="Persistence",
        description="Searches for scheduled tasks created via schtasks.exe pointing to temporary directories, scripts, or non-standard binaries.",
        mitre_technique_id="T1053.005",
        data_sources=["edr_process", "windows_security"],
        default_query=r"process_name =~ /schtasks/i AND command_line =~ /\/create/i AND (command_line =~ /AppData/i OR command_line =~ /Temp/i OR command_line =~ /powershell/i)",
        severity="MEDIUM",
    ),
    HuntTemplate(
        id="HUNT-T1048-DNS-TUNNEL",
        name="DNS Tunneling and Data Exfiltration",
        category="Exfiltration",
        description="Identifies DNS queries with abnormally high label length, numeric ratio, or entropy suggesting covert tunneling.",
        mitre_technique_id="T1048",
        data_sources=["dns_telemetry", "zeek_dns"],
        default_query="query_type == 'TXT' OR query_length > 65 OR subdomain_entropy > 4.2",
        severity="HIGH",
    ),
    HuntTemplate(
        id="HUNT-T1021-LATERAL",
        name="Lateral Movement via WMI and PsExec Services",
        category="Lateral Movement",
        description="Hunts for remote process execution using WMIC or remote service creation across network shares.",
        mitre_technique_id="T1021",
        data_sources=["edr_process", "network_smb"],
        default_query=r"(process_name =~ /wmic/i AND command_line =~ /process.*call.*create/i) OR (process_name =~ /psexec/i OR command_line =~ /ADMIN\$/i)",
        severity="HIGH",
    ),
    HuntTemplate(
        id="HUNT-T1078-STALE-ACCOUNT",
        name="Dormant or Service Account Interactive Logons",
        category="Initial Access",
        description="Detects interactive desktop/console logons (Logon Type 2 or 10) utilizing service accounts or accounts dormant for >90 days.",
        mitre_technique_id="T1078",
        data_sources=["auth_events", "ad_audit"],
        default_query="logon_type IN [2, 10] AND (user_name =~ /svc_/i OR user_name =~ /service/i) AND status == 'SUCCESS'",
        severity="MEDIUM",
    ),
    HuntTemplate(
        id="HUNT-T1547-LINUX-PERSISTENCE",
        name="Linux Stealth Execution and Rootkit Activity",
        category="Persistence",
        description="Hunts for execution of binaries from shared memory (/dev/shm) or modifications to /etc/ld.so.preload.",
        mitre_technique_id="T1547",
        data_sources=["auditd", "edr_linux"],
        default_query=r"file_path =~ /\/dev\/shm/i OR target_path == '/etc/ld.so.preload' OR command_line =~ /insmod/i",
        severity="HIGH",
    ),
]


def get_hunting_template(template_id: str) -> HuntTemplate | None:
    for t in BUILTIN_HUNT_TEMPLATES:
        if t.id == template_id:
            return t
    return None
