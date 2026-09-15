# Rule & Playbook Authoring Handbook

This guide details how security engineers can write and deploy custom **Sigma Rules**, **YARA Signatures**, and **SOAR Playbooks** into CyberShield Enterprise.

---

## 1. Authoring Sigma Rules

Sigma rules are located in `rules/sigma/` as `.yml` files.

### Schema Template
```yaml
title: Suspicious PowerShell Web Download Execution
id: 3b3e2b2a-8c8c-4a3e-9c2b-1a2b3c4d5e6f
status: production
description: Detects suspicious PowerShell commands executing web downloads.
author: CyberShield Security Team
level: high # informational | low | medium | high | critical
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - 'powershell.exe'
      - 'pwsh.exe'
    CommandLine|contains:
      - 'DownloadString'
      - 'Net.WebClient'
      - 'IEX'
  condition: selection
falsepositives:
  - Legitimate automated administrative scripts
```

### Supported Modifiers
- `|contains`: Substring search (case-insensitive)
- `|startswith`: Prefix match
- `|endswith`: Suffix match
- `|re`: Regular expression match

### Condition Logic
- `selection`: Matches when all fields in `selection` match.
- `selection and not filter`: Excludes known false positives.
- `1 of selection*`: Matches when any selection block evaluates to true.

---

## 2. Authoring YARA Rules

YARA rules are located in `rules/yara/` as `.yar` files.

### Schema Template
```yara
rule WebShell_Generic_PHP_JSP
{
    meta:
        description = "Detects generic PHP, JSP, or ASPX web shell backdoor components"
        author = "CyberShield Threat Labs"
        severity = "CRITICAL"
        tactic = "Persistence"
        technique = "T1505.003"
        confidence = "0.95"
    strings:
        $php1 = "passthru(" nocase
        $php2 = "shell_exec(" nocase
        $php3 = "system($_GET[" nocase
        $php4 = "eval(base64_decode(" nocase
        $hex1 = { 4D 5A 90 00 03 00 00 00 }
        $re1  = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/shell/i
    condition:
        any of them
}
```

---

## 3. Authoring SOAR Playbooks

SOAR playbooks are declarative JSON workflows placed in `cybershield/soar/playbooks/`.

### Schema Template
```json
{
  "id": "PB-CUSTOM-RESPONSE",
  "name": "Custom Automated Containment Workflow",
  "description": "Quarantines host and severs C2 connections upon high-confidence alert.",
  "trigger_criteria": {
    "severity": "CRITICAL",
    "mitre_technique": "T1486"
  },
  "steps": [
    {
      "name": "1. Isolate Host",
      "action": "ISOLATE_HOST",
      "target": "{{host}}",
      "parameters": {
        "reason": "Automated Response"
      },
      "abort_on_failure": false
    },
    {
      "name": "2. Block Attacker IP",
      "action": "BLOCK_IP",
      "target": "{{source_ip}}",
      "parameters": {
        "direction": "INGRESS_AND_EGRESS",
        "ttl": 86400
      },
      "abort_on_failure": false
    },
    {
      "name": "3. Forcibly Kill Malicious Process",
      "action": "KILL_PROCESS",
      "target": "{{process_name}}",
      "parameters": {
        "signal": "SIGKILL"
      },
      "abort_on_failure": false
    }
  ]
}
```

### Available Actions
| Action Name | Target | Purpose |
|:---|:---|:---|
| `ISOLATE_HOST` | Hostname | Quarantines network interface while preserving SOC telemetry |
| `BLOCK_IP` | IPv4 Address | Drops inbound/outbound packets across perimeter firewalls |
| `KILL_PROCESS` | Process Name / PID | Terminates process execution tree |
| `REVOKE_USER_CREDENTIALS` | Username | Locks account and purges Active Directory / Kerberos tickets |
| `CAPTURE_FORENSIC_SNAPSHOT` | Hostname / Entity | Generates cryptographically sealed memory dump artifact |
| `NOTIFY_SOC` | Channel Name | Dispatches alert message to SOC incident room |
