# CyberShield Enterprise SOC Operator & Incident Responder Guide

Welcome to the **CyberShield Enterprise** Security Operations Center (SOC) manual. This guide equips SOC Analysts, Incident Commanders, and Threat Hunters with operational workflows to monitor, investigate, contain, and remediate threats.

---

## 1. Navigating the SOC Glass Cockpit

Access the web interface at `http://127.0.0.1:8000`.

### 1.1 Status Indicators
- **Connection Badge**: Located top right. Displays `CONNECTED (LIVE STREAM)` when the persistent WebSocket is actively streaming telemetry.
- **DEFCON Posture**:
  - `DEFCON 4 (GUARDED)`: Clean baseline activity.
  - `DEFCON 2 (ELEVATED)`: Medium-to-high severity detections active.
  - `DEFCON 1 (CRITICAL)`: Active critical alerts (ransomware, credential dumping, exfiltration).

---

## 2. Alert Triage Workflow

1. Navigate to **SOC Command Center**.
2. Examine the **Live Security Alerts & Triage Queue**.
3. Click **Inspect** on any alert to open the detailed investigation drawer.
4. Review:
   - Detection Engine (e.g. `SIGMA_RULE`, `ISOLATION_FOREST`, `UEBA_ENGINE`, `INJECTION_CLASSIFIER`).
   - MITRE ATT&CK Tactics and Techniques.
   - Diagnostic metadata and raw indicators.
5. To execute automated containment, click **Execute Immediate SOAR Containment**.
   - The platform will auto-select the matching response playbook (e.g. `PB-RANSOMWARE-01` or `PB-BRUTEFORCE-02`), isolate the host, terminate the process, and update the alert status to `CONTAINED`.

---

## 3. Threat Hunting with CS-QL

Navigate to the **CS-QL Threat Hunter** tab to run structured queries against live memory buffers:

### Common CS-QL Queries
| Objective | CS-QL Query |
|:---|:---|
| Find all Critical alerts | `severity == "CRITICAL"` |
| Inspect PowerShell activity | `process_name contains "powershell" \| stats count by host_name` |
| Filter by specific source IP | `source_ip == "198.51.100.23"` |
| Detect Mimikatz artifacts | `command_line =~ "mimikatz" or command_line =~ "sekurlsa"` |
| HTTP Server Errors | `http_status >= 500 \| stats count by http_url` |
| View top log sources | `* \| stats count by log_source` |

---

## 4. MITRE ATT&CK Matrix Heatmap

Navigate to the **MITRE ATT&CK Heatmap** tab:
- Columns represent the 14 standard Enterprise Tactics in kill-chain progression order.
- Glowing red cards indicate active adversary techniques observed in telemetry.
- Use this view to determine the adversary's current kill-chain depth (e.g. Initial Access vs. Lateral Movement vs. Impact).

---

## 5. Threat Intelligence & CVE Verification

Navigate to the **Threat Intel & CVE Catalog** tab:
- Enter any IP, domain, or SHA-256 hash in the **Rapid IoC Lookup** bar.
- The platform queries its local in-memory Bloom filter and Radix table in under 1 millisecond.
- Review critical CVE mitigation instructions (e.g. CVE-2024-3094, Log4Shell CVE-2021-44228).

---

## 6. Testing with the Cyber Attack Simulator

To train new analysts or verify alert rules:
1. Locate the top simulation strip.
2. Click any of the 5 pre-configured scenarios:
   - **Detonate Ransomware**: Fires shadow copy deletion and ransom note creation, testing automated host isolation.
   - **Spray Brute Force**: Fires authentication bursts, testing Active Directory lockout playbooks.
   - **Inject SQL Exploit**: Tests the NLP Naive Bayes payload classifier.
   - **Execute APT29 Hop**: Simulates impossible travel, Mimikatz dumps, and SMB lateral hops.
   - **Trigger Data Exfiltration**: Injects high-entropy outbound network flows, testing the Isolation Forest engine.
3. Observe real-time alerts appear in the queue without reloading the page.
