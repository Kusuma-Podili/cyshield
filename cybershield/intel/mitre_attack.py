"""MITRE ATT&CK Enterprise Matrix Knowledge Base & Heatmap Navigator.

Contains full taxonomic structure of the 14 Enterprise Tactics and common Techniques.
Calculates real-time attack coverage, tactic progression heatmaps, and mitigation advice.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Any
from collections import defaultdict

from cybershield.core.models import MITRETechnique, Alert

logger = logging.getLogger("cybershield.intel.mitre")


class MITREAttackMatrix:
    """Enterprise MITRE ATT&CK Matrix navigator and heatmap calculator."""

    TACTICS = [
        {"id": "TA0043", "name": "Reconnaissance", "description": "Gathering intelligence to plan future adversary operations."},
        {"id": "TA0042", "name": "Resource Development", "description": "Establishing resources to support operations (infrastructure, accounts)."},
        {"id": "TA0001", "name": "Initial Access", "description": "Techniques used to gain an initial foothold within a network."},
        {"id": "TA0002", "name": "Execution", "description": "Techniques that result in adversary-controlled code running on a system."},
        {"id": "TA0003", "name": "Persistence", "description": "Techniques used to maintain their foothold across restarts/credentials."},
        {"id": "TA0004", "name": "Privilege Escalation", "description": "Techniques used to gain higher-level permissions on a system."},
        {"id": "TA0005", "name": "Defense Evasion", "description": "Techniques used to avoid detection throughout their compromise."},
        {"id": "TA0006", "name": "Credential Access", "description": "Techniques for stealing credentials like passwords and hashes."},
        {"id": "TA0007", "name": "Discovery", "description": "Techniques used to gain knowledge about the system and internal network."},
        {"id": "TA0008", "name": "Lateral Movement", "description": "Techniques used to enter and control remote systems on a network."},
        {"id": "TA0009", "name": "Collection", "description": "Techniques used to gather data of interest to achieve adversary objective."},
        {"id": "TA0011", "name": "Command and Control", "description": "Techniques used to communicate with systems under adversary control."},
        {"id": "TA0010", "name": "Exfiltration", "description": "Techniques used to steal data from your network."},
        {"id": "TA0040", "name": "Impact", "description": "Techniques used to disrupt availability or compromise integrity of systems."},
    ]

    def __init__(self):
        self._techniques: Dict[str, MITRETechnique] = {}
        self._seed_techniques()

    def _seed_techniques(self) -> None:
        """Seed representative MITRE ATT&CK techniques across all phases."""
        tech_data = [
            ("T1595", "Active Scanning", "Reconnaissance", "Scanning IP blocks and services", ["Network flow monitoring"]),
            ("T1583", "Acquire Infrastructure", "Resource Development", "Buying domains and VPS nodes", ["Whois audit"]),
            ("T1190", "Exploit Public-Facing Application", "Initial Access", "Exploiting web apps (SQLi, RCE)", ["Web application firewall"]),
            ("T1566", "Phishing", "Initial Access", "Spearphishing with malicious attachments", ["Email gateway analysis"]),
            ("T1059", "Command and Scripting Interpreter", "Execution", "PowerShell, Bash, CMD execution", ["Sysmon EventID 1"]),
            ("T1203", "Exploitation for Client Execution", "Execution", "Exploiting vulnerable client apps", ["EDR memory inspection"]),
            ("T1053", "Scheduled Task/Job", "Persistence", "Persistence via cron or Task Scheduler", ["Audit task scheduler"]),
            ("T1547", "Boot or Logon Autostart", "Persistence", "Registry run keys or startup folder", ["Sysmon EventID 13"]),
            ("T1548", "Abuse Elevation Control", "Privilege Escalation", "UAC bypass, sudo abuse", ["Process integrity monitoring"]),
            ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", "Kernel or driver exploits", ["Patch management"]),
            ("T1027", "Obfuscated Files or Information", "Defense Evasion", "Base64 encoding, packing, entropy", ["Entropy scanning"]),
            ("T1070", "Indicator Removal on Host", "Defense Evasion", "Clearing event logs, timestomping", ["Log tamper alerting"]),
            ("T1003", "OS Credential Dumping", "Credential Access", "LSASS dumping via Mimikatz", ["LSASS protection"]),
            ("T1110", "Brute Force", "Credential Access", "Password spraying and dictionary attacks", ["Auth failure rate monitoring"]),
            ("T1083", "File and Directory Discovery", "Discovery", "Enumerating sensitive files", ["File access auditing"]),
            ("T1046", "Network Service Discovery", "Discovery", "Scanning internal ports and services", ["Internal flow analysis"]),
            ("T1021", "Remote Services", "Lateral Movement", "RDP, SSH, WinRM, SMB lateral hops", ["Network segmentation"]),
            ("T1570", "Lateral Tool Transfer", "Lateral Movement", "Transferring tools between hosts", ["SMB/RPC file transfer monitoring"]),
            ("T1005", "Data from Local System", "Collection", "Searching drives for confidential data", ["DLP monitoring"]),
            ("T1114", "Email Collection", "Collection", "Exporting mailbox contents", ["Exchange auditing"]),
            ("T1071", "Application Layer Protocol", "Command and Control", "C2 over HTTP/HTTPS/DNS", ["TLS inspection"]),
            ("T1573", "Encrypted Channel", "Command and Control", "Custom encrypted C2 channels", ["High entropy traffic detection"]),
            ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", "Data transfer over DNS, ICMP, FTP", ["DLP / NetFlow monitoring"]),
            ("T1567", "Exfiltration to Cloud Storage", "Exfiltration", "Uploading to Mega, AWS S3, Dropbox", ["Cloud egress monitoring"]),
            ("T1486", "Data Encrypted for Impact", "Impact", "Ransomware file encryption", ["File modification rate heuristics"]),
            ("T1489", "Service Stop", "Impact", "Stopping anti-malware and database services", ["Service status monitoring"]),
        ]

        for tid, name, tactic, desc, strategies in tech_data:
            self._techniques[tid] = MITRETechnique(
                technique_id=tid,
                name=name,
                tactic=tactic,
                description=desc,
                detection_strategies=strategies
            )

    def get_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """Fetch technique metadata by ID."""
        return self._techniques.get(technique_id.upper())

    def get_all_tactics(self) -> List[Dict[str, Any]]:
        """Return list of all 14 tactics."""
        return self.TACTICS

    def get_all_techniques(self) -> List[MITRETechnique]:
        """Return all catalogued techniques."""
        return list(self._techniques.values())

    def calculate_heatmap(self, alerts: List[Alert]) -> Dict[str, Any]:
        """Compute real-time MITRE heatmap data based on active alerts."""
        tactic_counts: Dict[str, int] = defaultdict(int)
        technique_counts: Dict[str, int] = defaultdict(int)

        for alert in alerts:
            for tactic in alert.mitre_tactics:
                tactic_counts[tactic] += 1
            for tech in alert.mitre_techniques:
                # Strip subtechnique if needed: T1059.001 -> T1059
                base_tech = tech.split(".")[0].upper()
                technique_counts[base_tech] += 1

        max_tactic_count = max(tactic_counts.values()) if tactic_counts else 1

        tactic_heat = []
        for t in self.TACTICS:
            count = tactic_counts.get(t["name"], 0)
            intensity = round(count / max_tactic_count, 2) if count > 0 else 0.0
            tactic_heat.append({
                "tactic_id": t["id"],
                "tactic_name": t["name"],
                "alert_count": count,
                "intensity": intensity,
            })

        technique_heat = []
        for tid, tech in self._techniques.items():
            count = technique_counts.get(tid, 0)
            if count > 0:
                technique_heat.append({
                    "technique_id": tid,
                    "name": tech.name,
                    "tactic": tech.tactic,
                    "alert_count": count,
                })
        technique_heat.sort(key=lambda x: x["alert_count"], reverse=True)

        return {
            "tactics": tactic_heat,
            "active_techniques": technique_heat,
            "total_tactic_coverage": len([t for t in tactic_heat if t["alert_count"] > 0]),
        }


# Global singleton MITRE matrix
mitre_matrix = MITREAttackMatrix()
