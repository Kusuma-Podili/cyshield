"""MITRE ATT&CK Enterprise Matrix Dataset.

Contains comprehensive structural data for all 14 Enterprise Tactics and foundational
Techniques, Sub-techniques, Platforms, Data Sources, and D3FEND Countermeasure mappings.
"""

from __future__ import annotations

from typing import Dict, List
from cybershield.mitre.d3fend import D3FEND_CATALOG
from cybershield.mitre.schemas import SubTechnique, TechniqueDetail

MITRE_TACTICS: List[Dict[str, str]] = [
    {"id": "TA0043", "name": "Reconnaissance", "description": "Gathering intelligence to plan future adversary operations."},
    {"id": "TA0042", "name": "Resource Development", "description": "Establishing resources to support operations (infrastructure, accounts, tools)."},
    {"id": "TA0001", "name": "Initial Access", "description": "Techniques used to gain an initial foothold within an enterprise network."},
    {"id": "TA0002", "name": "Execution", "description": "Techniques that result in adversary-controlled code running on a local or remote system."},
    {"id": "TA0003", "name": "Persistence", "description": "Techniques used to maintain an operational foothold across restarts and changed credentials."},
    {"id": "TA0004", "name": "Privilege Escalation", "description": "Techniques used to gain higher-level permissions on a system (root, SYSTEM, Domain Admin)."},
    {"id": "TA0005", "name": "Defense Evasion", "description": "Techniques used to avoid detection and disguise malicious activities throughout a compromise."},
    {"id": "TA0006", "name": "Credential Access", "description": "Techniques for stealing credentials like passwords, Kerberos tickets, and private keys."},
    {"id": "TA0007", "name": "Discovery", "description": "Techniques used to gain knowledge about the internal network, host configurations, and active users."},
    {"id": "TA0008", "name": "Lateral Movement", "description": "Techniques used to enter and control remote systems across the internal network perimeter."},
    {"id": "TA0009", "name": "Collection", "description": "Techniques used to gather data of interest (emails, files, database records) to achieve objectives."},
    {"id": "TA0011", "name": "Command and Control", "description": "Techniques used to communicate with systems under adversary control (beacons, tunnels, C2)."},
    {"id": "TA0010", "name": "Exfiltration", "description": "Techniques used to steal and package data out of your enterprise network."},
    {"id": "TA0040", "name": "Impact", "description": "Techniques used to disrupt availability or compromise integrity of business systems (ransomware, wipers)."},
]

TECHNIQUES_DATA: List[TechniqueDetail] = [
    # TA0043 Reconnaissance
    TechniqueDetail(
        id="T1595",
        name="Active Scanning",
        tactic="Reconnaissance",
        tactic_id="TA0043",
        description="Adversaries may execute active reconnaissance scans to gather information on IP ranges, open ports, and vulnerable services.",
        platforms=["Network"],
        data_sources=["Network Traffic: Network Traffic Flow", "Sensor Health: Host Status"],
        detection_strategy="Monitor firewall and NetFlow logs for horizontal or vertical port scan spikes from external IP addresses.",
        sub_techniques=[
            SubTechnique(id="T1595.001", name="Scanning IP Blocks", description="Scanning CIDR blocks for responsive hosts.", platforms=["Network"]),
            SubTechnique(id="T1595.002", name="Vulnerability Scanning", description="Probing public services with automated vulnerability scanners.", platforms=["Network"]),
        ],
        d3fend_countermeasures=[D3FEND_CATALOG["D3-ITF"], D3FEND_CATALOG["D3-DO"]],
    ),
    # TA0001 Initial Access
    TechniqueDetail(
        id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        tactic_id="TA0001",
        description="Adversaries may exploit weaknesses in Internet-facing software (web applications, VPN gateways, SMB) to gain initial access.",
        platforms=["Windows", "Linux", "macOS", "Cloud"],
        data_sources=["Application Log: Application Log Content", "Network Traffic: Network Traffic Content"],
        detection_strategy="Inspect HTTP web server logs and WAF telemetry for SQL injection, Log4j JNDI expressions, path traversal, or command injection strings.",
        sub_techniques=[],
        d3fend_countermeasures=[D3FEND_CATALOG["D3-ITF"], D3FEND_CATALOG["D3-DQB"]],
    ),
    TechniqueDetail(
        id="T1566",
        name="Phishing",
        tactic="Initial Access",
        tactic_id="TA0001",
        description="Adversaries may send phishing messages with malicious attachments or links to compromise recipient credentials and endpoints.",
        platforms=["Windows", "Linux", "macOS", "Cloud"],
        data_sources=["Email: Email Content", "File: File Creation"],
        detection_strategy="Analyze inbound email headers, SPF/DKIM/DMARC records, attachment macros, and URL visual similarity.",
        sub_techniques=[
            SubTechnique(id="T1566.001", name="Spearphishing Attachment", description="Email with weaponized documents (Office, ISO, LNK).", platforms=["Windows", "macOS"]),
            SubTechnique(id="T1566.002", name="Spearphishing Link", description="Email with credential harvesting hyperlink.", platforms=["Windows", "Linux", "macOS"]),
        ],
        d3fend_countermeasures=[D3FEND_CATALOG["D3-FAA"], D3FEND_CATALOG["D3-AMSI"]],
    ),
    # TA0002 Execution
    TechniqueDetail(
        id="T1059",
        name="Command and Scripting Interpreter",
        tactic="Execution",
        tactic_id="TA0002",
        description="Adversaries may abuse command and script interpreters to execute arbitrary commands, download cradles, and interact with systems.",
        platforms=["Windows", "Linux", "macOS", "Containers"],
        data_sources=["Command: Command Execution", "Process: Process Creation"],
        detection_strategy="Audit process creation events for powershell.exe, pwsh, cmd.exe, bash with download string or reverse shell arguments.",
        sub_techniques=[
            SubTechnique(id="T1059.001", name="PowerShell", description="PowerShell interactive shell or encoded command execution.", platforms=["Windows"]),
            SubTechnique(id="T1059.004", name="Unix Shell", description="Linux bash/sh reverse shell or pipe execution.", platforms=["Linux", "macOS"]),
        ],
        d3fend_countermeasures=[D3FEND_CATALOG["D3-PSA"], D3FEND_CATALOG["D3-AMSI"], D3FEND_CATALOG["D3-PE"]],
    ),
    # TA0003 Persistence
    TechniqueDetail(
        id="T1053",
        name="Scheduled Task/Job",
        tactic="Persistence",
        tactic_id="TA0003",
        description="Adversaries may configure tasks or jobs to execute on a recurring schedule to maintain continuous persistence on victim systems.",
        platforms=["Windows", "Linux", "macOS"],
        data_sources=["Command: Command Execution", "Scheduled Job: Scheduled Job Creation"],
        detection_strategy="Monitor Windows EventID 4698 (A scheduled task was created) and Linux /etc/cron.* modifications.",
        sub_techniques=[
            SubTechnique(id="T1053.003", name="Cron", description="Linux cron jobs in crontab or /etc/cron.*.", platforms=["Linux"]),
            SubTechnique(id="T1053.005", name="Scheduled Task", description="Windows Task Scheduler via schtasks or TaskService COM.", platforms=["Windows"]),
        ],
        d3fend_countermeasures=[D3FEND_CATALOG["D3-PSA"], D3FEND_CATALOG["D3-FAA"]],
    ),
    TechniqueDetail(
        id="T1547",
        name="Boot or Logon Autostart Execution",
        tactic="Persistence",
        tactic_id="TA0003",
        description="Adversaries may configure system settings to automatically execute a program during boot or user logon.",
        platforms=["Windows", "Linux", "macOS"],
        data_sources=["Windows Registry: Windows Registry Key Modification", "File: File Creation"],
        detection_strategy="Monitor Registry Run and RunOnce keys and Startup folders for newly written executables or scripts.",
        sub_techniques=[
            SubTechnique(id="T1547.001", name="Registry Run Keys / Startup Folder", description="Autostart execution via registry Run keys.", platforms=["Windows"]),
        ],
        d3fend_countermeasures=[D3FEND_CATALOG["D3-FAA"]],
    ),
    # TA0004 Privilege Escalation
    TechniqueDetail(
        id="T1548",
        name="Abuse Elevation Control Mechanism",
        tactic="Privilege Escalation",
        tactic_id="TA0004",
        description="Adversaries may circumvent mechanisms designed to control elevation of privileges to gain higher system rights.",
        platforms=["Windows", "Linux", "macOS"],
        data_sources=["Process: Process Creation", "Command: Command Execution"],
        detection_strategy="Detect UAC bypass via Fodhelper or Eventvwr registry hijacking, SUID binary abuse, or /etc/sudoers NOPASSWD injection.",
        sub_techniques=[
            SubTechnique(id="T1548.001", name="Setuid and Setgid", description="Abuse of SUID binaries to execute root commands.", platforms=["Linux"]),
            SubTechnique(id="T1548.002", name="Bypass User Account Control", description="Bypassing Windows UAC prompt via auto-elevating binaries.", platforms=["Windows"]),
            SubTechnique(id="T1548.003", name="Sudo and Sudo Caching", description="Abusing sudo privileges or cached credentials.", platforms=["Linux"]),
        ],
        d3fend_countermeasures=[D3FEND_CATALOG["D3-PSA"], D3FEND_CATALOG["D3-FAA"]],
    ),
    TechniqueDetail(
        id="T1611",
        name="Escape to Host",
        tactic="Privilege Escalation",
        tactic_id="TA0004",
        description="Adversaries may break out of a container or hypervisor to access the underlying host node operating system.",
        platforms=["Containers", "Cloud"],
        data_sources=["Process: Process Creation", "Container: Container Enumeration"],
        detection_strategy="Monitor container processes for nsenter target 1, docker.sock mounts, or release_agent cgroup exploits.",
        sub_techniques=[],
        d3fend_countermeasures=[D3FEND_CATALOG["D3-PSA"], D3FEND_CATALOG["D3-PE"]],
    ),
    # TA0005 Defense Evasion
    TechniqueDetail(
        id="T1070",
        name="Indicator Removal",
        tactic="Defense Evasion",
        tactic_id="TA0005",
        description="Adversaries may delete or alter event logs, audit trails, and command histories to hinder digital forensic investigations.",
        platforms=["Windows", "Linux", "macOS", "Cloud"],
        data_sources=["Command: Command Execution", "File: File Deletion"],
        detection_strategy="Alert on wevtutil cl commands, Event ID 1102 (Security audit log cleared), or CloudTrail StopLogging calls.",
        sub_techniques=[
            SubTechnique(id="T1070.001", name="Clear Windows Event Logs", description="Clearing Security or System event logs.", platforms=["Windows"]),
            SubTechnique(id="T1070.003", name="Clear Command History", description="Wiping .bash_history via unset HISTFILE or shred.", platforms=["Linux"]),
        ],
        d3fend_countermeasures=[D3FEND_CATALOG["D3-FAA"]],
    ),
    TechniqueDetail(
        id="T1562",
        name="Impair Defenses",
        tactic="Defense Evasion",
        tactic_id="TA0005",
        description="Adversaries may disable or modify security tools, firewalls, and logging agents to avoid detection.",
        platforms=["Windows", "Linux", "Cloud"],
        data_sources=["Service: Service Modification", "Process: Process Termination"],
        detection_strategy="Monitor Set-MpPreference -DisableRealtimeMonitoring commands or GuardDuty DeleteDetector calls.",
        sub_techniques=[
            SubTechnique(id="T1562.001", name="Disable or Modify Tools", description="Disabling AV or EDR services.", platforms=["Windows", "Linux", "Cloud"]),
        ],
        d3fend_countermeasures=[D3FEND_CATALOG["D3-AMSI"]],
    ),
    # TA0006 Credential Access
    TechniqueDetail(
        id="T1003",
        name="OS Credential Dumping",
        tactic="Credential Access",
        tactic_id="TA0006",
        description="Adversaries may dump credentials from the operating system memory, SAM database, or Active Directory replication stream.",
        platforms=["Windows", "Linux"],
        data_sources=["Process: Process Access", "Command: Command Execution"],
        detection_strategy="Detect OpenProcess calls targeting lsass.exe, comsvcs.dll MiniDump executions, or DCSync Event ID 4662.",
        sub_techniques=[
            SubTechnique(id="T1003.001", name="LSASS Memory", description="Dumping lsass.exe process memory via ProcDump or comsvcs.", platforms=["Windows"]),
            SubTechnique(id="T1003.006", name="DCSync", description="Replicating Active Directory domain hashes via DRSUAPI.", platforms=["Windows"]),
        ],
        d3fend_countermeasures=[D3FEND_CATALOG["D3-LSA"], D3FEND_CATALOG["D3-CR"]],
    ),
    TechniqueDetail(
        id="T1558",
        name="Steal or Forge Kerberos Tickets",
        tactic="Credential Access",
        tactic_id="TA0006",
        description="Adversaries may abuse the Kerberos protocol to request service tickets with weak encryption (Kerberoasting) or forge Golden Tickets.",
        platforms=["Windows"],
        data_sources=["Logon Session: Logon Session Creation", "Network Traffic: Network Traffic Flow"],
        detection_strategy="Monitor Event ID 4769 for TGS requests using RC4 encryption (0x17) and anomalous TGT lifetimes exceeding 10 hours.",
        sub_techniques=[
            SubTechnique(id="T1558.001", name="Golden Ticket", description="Forging Kerberos TGT using krbtgt NTLM hash.", platforms=["Windows"]),
            SubTechnique(id="T1558.003", name="Kerberoasting", description="Requesting TGS tickets for accounts with SPNs to crack offline.", platforms=["Windows"]),
        ],
        d3fend_countermeasures=[D3FEND_CATALOG["D3-CR"]],
    ),
    # TA0007 Discovery
    TechniqueDetail(
        id="T1087",
        name="Account Discovery",
        tactic="Discovery",
        tactic_id="TA0007",
        description="Adversaries may enumerate local system or domain user accounts and group memberships to identify high-value targets.",
        platforms=["Windows", "Linux", "macOS", "Cloud"],
        data_sources=["Command: Command Execution", "Process: Process Creation"],
        detection_strategy="Detect net user /domain commands, SharpHound LDAP queries, or aws iam list-users invocations.",
        sub_techniques=[
            SubTechnique(id="T1087.002", name="Domain Account", description="Enumerating Active Directory domain accounts.", platforms=["Windows"]),
        ],
        d3fend_countermeasures=[D3FEND_CATALOG["D3-PSA"], D3FEND_CATALOG["D3-DO"]],
    ),
    # TA0008 Lateral Movement
    TechniqueDetail(
        id="T1021",
        name="Remote Services",
        tactic="Lateral Movement",
        tactic_id="TA0008",
        description="Adversaries may log into remote systems using valid credentials and remote management protocols (RDP, SMB, SSH).",
        platforms=["Windows", "Linux"],
        data_sources=["Logon Session: Logon Session Creation", "Network Traffic: Network Traffic Flow"],
        detection_strategy="Monitor PsExec service installations on ADMIN$ share or unexpected internal RDP sessions across subnets.",
        sub_techniques=[
            SubTechnique(id="T1021.001", name="Remote Desktop Protocol", description="RDP lateral movement across endpoints.", platforms=["Windows"]),
            SubTechnique(id="T1021.002", name="SMB/Windows Admin Shares", description="PsExec / SMB administrative file execution.", platforms=["Windows"]),
        ],
        d3fend_countermeasures=[D3FEND_CATALOG["D3-ITF"], D3FEND_CATALOG["D3-NI"]],
    ),
    # TA0011 Command and Control
    TechniqueDetail(
        id="T1071",
        name="Application Layer Protocol",
        tactic="Command and Control",
        tactic_id="TA0011",
        description="Adversaries may communicate using application layer protocols (HTTP, HTTPS, DNS) to blend in with legitimate network traffic.",
        platforms=["Windows", "Linux", "macOS", "Network"],
        data_sources=["Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow"],
        detection_strategy="Analyze JA3/JA4 TLS fingerprints, DNS Shannon entropy, and high-frequency beaconing intervals.",
        sub_techniques=[
            SubTechnique(id="T1071.001", name="Web Protocols", description="C2 over HTTP/HTTPS/WebSocket.", platforms=["Windows", "Linux", "macOS"]),
            SubTechnique(id="T1071.004", name="DNS", description="C2 beaconing and exfiltration via DNS tunneling.", platforms=["Network"]),
        ],
        d3fend_countermeasures=[D3FEND_CATALOG["D3-ITF"], D3FEND_CATALOG["D3-NI"]],
    ),
    # TA0040 Impact
    TechniqueDetail(
        id="T1486",
        name="Data Encrypted for Impact",
        tactic="Impact",
        tactic_id="TA0040",
        description="Adversaries may encrypt data on target systems to interrupt availability and extort victims for ransom payments.",
        platforms=["Windows", "Linux", "macOS"],
        data_sources=["File: File Modification", "Process: Process Creation"],
        detection_strategy="Detect high-frequency file renaming/extension changes (.lockbit, .wncry), vssadmin delete shadows commands, and ransom note drops.",
        sub_techniques=[],
        d3fend_countermeasures=[D3FEND_CATALOG["D3-FAA"], D3FEND_CATALOG["D3-PE"], D3FEND_CATALOG["D3-NI"]],
    ),
    TechniqueDetail(
        id="T1496",
        name="Resource Hijacking",
        tactic="Impact",
        tactic_id="TA0040",
        description="Adversaries may hijack enterprise compute resources to mine cryptocurrency or execute unauthorized distributed computations.",
        platforms=["Linux", "Windows", "Containers", "Cloud"],
        data_sources=["Process: Process Creation", "Sensor Health: Host Status"],
        detection_strategy="Detect xmrig/minerd processes, connections to stratum+tcp mining pools, and persistent 100% CPU utilization in containers.",
        sub_techniques=[],
        d3fend_countermeasures=[D3FEND_CATALOG["D3-PSA"], D3FEND_CATALOG["D3-PE"]],
    ),
]
