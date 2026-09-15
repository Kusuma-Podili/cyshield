"""MITRE D3FEND Defensive Countermeasure Knowledge Base.

Contains structured definitions of offensive technique mitigations mapped to
MITRE D3FEND taxonomy (Model, Harden, Detect, Isolate, Deceive, Evict).
"""

from __future__ import annotations

from typing import Dict, List, Optional
from cybershield.mitre.schemas import D3FENDCountermeasure

D3FEND_CATALOG: Dict[str, D3FENDCountermeasure] = {
    "D3-ITF": D3FENDCountermeasure(
        d3fend_id="D3-ITF",
        name="Inbound Traffic Filtering",
        tactic="Harden",
        description="Filter incoming network traffic based on network layer, transport layer, or application layer parameters.",
        implementation_guidance="Enforce stateful firewall policies, restrict administrative ports (22, 3389, 445) to bastion hosts, and block known malicious IP addresses."
    ),
    "D3-PSA": D3FENDCountermeasure(
        d3fend_id="D3-PSA",
        name="Process Spawn Analysis",
        tactic="Detect",
        description="Analyze the creation of new processes and parent-child execution lineages to identify anomalous process invocations.",
        implementation_guidance="Monitor Sysmon EventID 1 or Linux auditd execve logs. Alert when Office applications or web servers spawn cmd.exe, powershell.exe, or bash."
    ),
    "D3-FAA": D3FENDCountermeasure(
        d3fend_id="D3-FAA",
        name="File Access Analysis",
        tactic="Detect",
        description="Monitor filesystem access events, file creation, and modifications to sensitive directories.",
        implementation_guidance="Deploy File Integrity Monitoring (FIM) on system binaries (/usr/bin, C:\\Windows\\System32) and critical registry hives."
    ),
    "D3-AMSI": D3FENDCountermeasure(
        d3fend_id="D3-AMSI",
        name="Script Execution Analysis (AMSI)",
        tactic="Detect",
        description="Inspect dynamic script code and in-memory execution buffers before evaluation by scripting engines.",
        implementation_guidance="Enforce Windows Antimalware Scan Interface (AMSI) and PowerShell Constrained Language Mode with full script block logging (Event ID 4104)."
    ),
    "D3-LSA": D3FENDCountermeasure(
        d3fend_id="D3-LSA",
        name="Local Security Authority Subsystem Hardening",
        tactic="Harden",
        description="Protect the LSASS process from unauthorized memory reading and debugging.",
        implementation_guidance="Enable LSA Protection (RunAsPPL) and Windows Defender Credential Guard via UEFI secure boot and hypervisor-protected code integrity (HVCI)."
    ),
    "D3-DQB": D3FENDCountermeasure(
        d3fend_id="D3-DQB",
        name="Database Query Parameterization & Block",
        tactic="Harden",
        description="Enforce parameterization on database queries to prevent SQL injection payloads.",
        implementation_guidance="Mandate ORM or prepared statements and implement Database Activity Monitoring (DAM) to terminate queries with UNION SELECT or xp_cmdshell."
    ),
    "D3-CR": D3FENDCountermeasure(
        d3fend_id="D3-CR",
        name="Credential Revocation & Invalidation",
        tactic="Evict",
        description="Invalidate active user sessions, tokens, and credentials upon detection of compromise.",
        implementation_guidance="Trigger automated SOAR playbooks to revoke OAuth refresh tokens, reset Kerberos krbtgt account twice, and terminate active VPN sessions."
    ),
    "D3-NI": D3FENDCountermeasure(
        d3fend_id="D3-NI",
        name="Network Isolation",
        tactic="Isolate",
        description="Sever or restrict network communications for a compromised endpoint to contain lateral movement.",
        implementation_guidance="Issue automated EDR host isolation or switch port quarantine commands, allowing only SOC management traffic."
    ),
    "D3-DO": D3FENDCountermeasure(
        d3fend_id="D3-DO",
        name="Decoy Objects & Canaries",
        tactic="Deceive",
        description="Deploy trap credentials, honeyfiles, and fake service ports to detect reconnaissance and unauthorized access.",
        implementation_guidance="Place decoy honeytokens in memory and AWS credentials files; alert SOC immediately upon token query."
    ),
    "D3-PE": D3FENDCountermeasure(
        d3fend_id="D3-PE",
        name="Process Termination / Eviction",
        tactic="Evict",
        description="Terminate adversary processes executing malicious or unauthorized instructions.",
        implementation_guidance="Issue SIGKILL or TerminateProcess API calls via SOAR agent to instantly stop cryptominers, reverse shells, or ransomware threads."
    ),
}


class D3FENDKnowledgeBase:
    """Catalog lookup for MITRE D3FEND countermeasures."""

    @classmethod
    def get(cls, d3fend_id: str) -> Optional[D3FENDCountermeasure]:
        return D3FEND_CATALOG.get(d3fend_id.upper())

    @classmethod
    def list_all(cls) -> List[D3FENDCountermeasure]:
        return list(D3FEND_CATALOG.values())

    @classmethod
    def get_by_tactic(cls, tactic: str) -> List[D3FENDCountermeasure]:
        return [c for c in D3FEND_CATALOG.values() if c.tactic.lower() == tactic.lower()]
