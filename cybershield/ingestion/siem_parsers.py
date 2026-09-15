"""
CyberShield Enterprise - Advanced SIEM Telemetry & Log Parsers
Implements enterprise parsers for Suricata EVE JSON, Windows Security Events (XML/JSON),
and NetFlow/IPFIX flow statistics with automatic format detection.
"""

import json
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List

from cybershield.database.models.events_and_alerts import (
    EventType,
    EventSeverity,
    LogSourceType,
)
from cybershield.core.logging import get_logger

logger = get_logger("cybershield.ingestion.siem_parsers")


class SuricataEveParser:
    """Parses Suricata EVE (Extensible Event Format) JSON telemetry."""

    @staticmethod
    def parse(raw_line: str) -> Optional[Dict[str, Any]]:
        """Extract OCSF-normalized dimensions from a Suricata JSON log line."""
        try:
            record = json.loads(raw_line) if isinstance(raw_line, str) else raw_line
        except Exception:
            return None

        event_type_str = record.get("event_type", "flow")
        timestamp_str = record.get("timestamp")
        try:
            ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")) if timestamp_str else datetime.utcnow()
        except Exception:
            ts = datetime.utcnow()

        src_ip = record.get("src_ip")
        dest_ip = record.get("dest_ip")
        src_port = record.get("src_port")
        dest_port = record.get("dest_port")
        proto = record.get("proto", "TCP").upper()

        sev = EventSeverity.INFO
        ev_type = EventType.NETWORK_CONNECTION
        msg = f"Suricata {event_type_str} flow from {src_ip}:{src_port} -> {dest_ip}:{dest_port}"

        # Alert payload processing
        if event_type_str == "alert":
            alert_data = record.get("alert", {})
            signature = alert_data.get("signature", "Generic IDS Alert")
            suricata_sev = alert_data.get("severity", 3)
            # Suricata severity: 1 = High, 2 = Medium, 3 = Low, 4 = Info
            if suricata_sev == 1:
                sev = EventSeverity.HIGH
            elif suricata_sev == 2:
                sev = EventSeverity.MEDIUM
            else:
                sev = EventSeverity.LOW

            ev_type = EventType.NETWORK_CONNECTION
            msg = f"IDS Alert: {signature} ({src_ip}:{src_port} -> {dest_ip}:{dest_port})"

        elif event_type_str == "dns":
            dns_data = record.get("dns", {})
            qname = dns_data.get("rrname", "unknown")
            ev_type = EventType.DNS_QUERY
            msg = f"DNS Query {dns_data.get('type', 'A')} for {qname}"

        elif event_type_str == "http":
            http_data = record.get("http", {})
            ev_type = EventType.WEB_REQUEST
            msg = f"HTTP {http_data.get('http_method', 'GET')} {http_data.get('hostname', '')}{http_data.get('url', '/')}"

        return {
            "id": f"evt-{uuid.uuid4().hex[:12]}",
            "timestamp": ts,
            "event_type": ev_type,
            "severity": sev,
            "source_type": LogSourceType.SURICATA,
            "source_ip": src_ip,
            "destination_ip": dest_ip,
            "source_port": src_port,
            "destination_port": dest_port,
            "protocol": proto,
            "host_name": record.get("host"),
            "user_name": None,
            "process_name": None,
            "message": msg,
            "raw_log": raw_line if isinstance(raw_line, str) else json.dumps(raw_line),
            "parsed_fields": record,
            "is_anomalous": sev in [EventSeverity.HIGH, EventSeverity.CRITICAL],
        }


class WindowsSecurityEventParser:
    """Parses Windows Security Event Log entries (JSON or Sysmon/EventViewer XML)."""

    EVENT_ID_MAP = {
        4624: ("Logon Successful", EventType.AUTHENTICATION_ATTEMPT, EventSeverity.INFO),
        4625: ("Logon Failed", EventType.AUTHENTICATION_ATTEMPT, EventSeverity.MEDIUM),
        4688: ("A new process has been created", EventType.PROCESS_CREATION, EventSeverity.INFO),
        4672: ("Special privileges assigned to new logon", EventType.PRIVILEGE_ESCALATION, EventSeverity.LOW),
        4720: ("A user account was created", EventType.PRIVILEGE_ESCALATION, EventSeverity.MEDIUM),
        4726: ("A user account was deleted", EventType.PRIVILEGE_ESCALATION, EventSeverity.MEDIUM),
        1102: ("The audit log was cleared", EventType.SECURITY_LOG_CLEARED, EventSeverity.CRITICAL),
        7045: ("A new service was installed in the system", EventType.PROCESS_CREATION, EventSeverity.MEDIUM),
    }

    @classmethod
    def parse_json(cls, raw: Dict[str, Any] | str) -> Optional[Dict[str, Any]]:
        """Parse structured Windows Event JSON."""
        if isinstance(raw, str):
            try:
                data = json.loads(raw)
            except Exception:
                return None
        else:
            data = raw

        event_id = int(data.get("EventID", data.get("event_id", 0)))
        event_data = data.get("EventData", data)

        desc, ev_type, sev = cls.EVENT_ID_MAP.get(
            event_id,
            (f"Windows Security Event {event_id}", EventType.NETWORK_CONNECTION, EventSeverity.INFO)
        )

        user = event_data.get("TargetUserName") or event_data.get("SubjectUserName") or event_data.get("user")
        domain = event_data.get("TargetDomainName") or event_data.get("SubjectDomainName")
        proc_name = event_data.get("NewProcessName") or event_data.get("ProcessName") or event_data.get("process")
        cmd_line = event_data.get("CommandLine")
        ip = event_data.get("IpAddress") or event_data.get("SourceNetworkAddress")
        host = data.get("Computer") or data.get("host_name") or "windows-host.corp"

        # If Event 4625 (Failed Logon) with bad password
        if event_id == 4625:
            msg = f"Failed Windows Logon attempt for user '{user}' from IP {ip}"
        elif event_id == 4688:
            msg = f"Process spawned on {host}: {proc_name} ({cmd_line or 'No args'})"
        elif event_id == 1102:
            msg = f"CRITICAL: Windows Security Event Log cleared on {host} by user '{user}'!"
        else:
            msg = f"{desc} on {host} (User: {user or 'SYSTEM'})"

        return {
            "id": f"evt-{uuid.uuid4().hex[:12]}",
            "timestamp": datetime.utcnow(),
            "event_type": ev_type,
            "severity": sev,
            "source_type": LogSourceType.WINDOWS_EVENT,
            "source_ip": ip,
            "destination_ip": None,
            "source_port": None,
            "destination_port": None,
            "protocol": "MSRPC",
            "host_name": host,
            "user_name": user,
            "domain": domain,
            "process_name": proc_name,
            "command_line": cmd_line,
            "message": msg,
            "raw_log": json.dumps(data) if isinstance(data, dict) else str(data),
            "parsed_fields": event_data,
            "is_anomalous": event_id in [1102, 4625],
        }


class NetFlowParser:
    """Parses IPFIX / NetFlow v9 network flow telemetry summaries."""

    @staticmethod
    def parse(flow_record: Dict[str, Any] | str) -> Optional[Dict[str, Any]]:
        if isinstance(flow_record, str):
            try:
                rec = json.loads(flow_record)
            except Exception:
                return None
        else:
            rec = flow_record

        src_ip = rec.get("ipv4_src_addr") or rec.get("src_ip")
        dst_ip = rec.get("ipv4_dst_addr") or rec.get("dest_ip")
        src_port = rec.get("l4_src_port") or rec.get("src_port")
        dst_port = rec.get("l4_dst_port") or rec.get("dest_port")
        proto = rec.get("protocol_str", "TCP")
        bytes_in = rec.get("in_bytes", 0)
        packets = rec.get("in_pkts", 0)

        # Detect anomalous heavy exfiltration flow (>100MB)
        is_exfil = bytes_in > 100 * 1024 * 1024
        sev = EventSeverity.HIGH if is_exfil else EventSeverity.INFO

        msg = f"NetFlow: {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{proto}] {bytes_in} bytes / {packets} packets"
        if is_exfil:
            msg = f"EXFILTRATION SPIKE: {src_ip} uploaded {round(bytes_in / (1024*1024), 1)} MB to {dst_ip}"

        return {
            "id": f"evt-{uuid.uuid4().hex[:12]}",
            "timestamp": datetime.utcnow(),
            "event_type": EventType.FLOW_STATISTICS,
            "severity": sev,
            "source_type": LogSourceType.NETFLOW,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": proto,
            "host_name": None,
            "user_name": None,
            "process_name": None,
            "command_line": None,
            "message": msg,
            "raw_log": json.dumps(rec) if isinstance(rec, dict) else str(rec),
            "parsed_fields": rec,
            "is_anomalous": is_exfil,
        }


class MultiFormatLogIngester:
    """Universal SIEM telemetry ingress router."""

    @staticmethod
    def ingest_line(line: str) -> Optional[Dict[str, Any]]:
        """Auto-detect format and parse into normalized telemetry record."""
        line = line.strip()
        if not line:
            return None

        # 1. JSON-formatted record
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                if "event_type" in data and ("alert" in data or "dns" in data or "http" in data):
                    return SuricataEveParser.parse(line)
                elif "EventID" in data or "event_id" in data:
                    return WindowsSecurityEventParser.parse_json(data)
                elif "in_bytes" in data or "ipv4_src_addr" in data:
                    return NetFlowParser.parse(data)
                elif "Event" in data and "System" in data:
                    # Windows JSON event wrapper
                    return WindowsSecurityEventParser.parse_json(data)
                else:
                    # Generic JSON telemetry
                    return {
                        "id": f"evt-{uuid.uuid4().hex[:12]}",
                        "timestamp": datetime.utcnow(),
                        "event_type": EventType.NETWORK_CONNECTION,
                        "severity": EventSeverity.INFO,
                        "source_type": LogSourceType.API_TELEMETRY,
                        "source_ip": data.get("src_ip", "127.0.0.1"),
                        "destination_ip": data.get("dst_ip"),
                        "source_port": data.get("src_port"),
                        "destination_port": data.get("dst_port"),
                        "protocol": data.get("protocol", "TCP"),
                        "host_name": data.get("hostname", "unknown"),
                        "user_name": data.get("username"),
                        "process_name": data.get("process"),
                        "message": data.get("message", "API telemetry ingested"),
                        "raw_log": line,
                        "parsed_fields": data,
                        "is_anomalous": False,
                    }
            except Exception:
                pass

        # 2. Sysmon / EventViewer XML
        if "<Event" in line:
            # Parse XML event
            try:
                root = ET.fromstring(line)
                event_id_elem = root.find(".//{*}EventID")
                ev_id = int(event_id_elem.text) if event_id_elem is not None else 0
                event_data = {}
                for data_item in root.findall(".//{*}Data"):
                    name = data_item.attrib.get("Name")
                    if name:
                        event_data[name] = data_item.text
                return WindowsSecurityEventParser.parse_json({
                    "EventID": ev_id,
                    "EventData": event_data
                })
            except Exception:
                pass

        # 3. Apache/Nginx Combined Log format
        web_match = re.match(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]+) (\S+)" (\d{3}) (\d+)', line)
        if web_match:
            client_ip, _, method, path, _, status_code, bytes_sent = web_match.groups()
            status_int = int(status_code)
            sev = EventSeverity.HIGH if status_int >= 500 else EventSeverity.MEDIUM if status_int in [401, 403] else EventSeverity.INFO

            return {
                "id": f"evt-{uuid.uuid4().hex[:12]}",
                "timestamp": datetime.utcnow(),
                "event_type": EventType.WEB_REQUEST,
                "severity": sev,
                "source_type": LogSourceType.WEB_ACCESS,
                "source_ip": client_ip,
                "destination_ip": "10.0.2.15",
                "source_port": None,
                "destination_port": 443,
                "protocol": "HTTPS",
                "host_name": "proxy-dmz-01.corp",
                "user_name": None,
                "process_name": "nginx",
                "message": f"Web {method} {path} HTTP {status_code} ({bytes_sent} bytes)",
                "raw_log": line,
                "parsed_fields": {"method": method, "path": path, "status": status_int, "bytes": int(bytes_sent)},
                "is_anomalous": status_int >= 500 or "select" in path.lower() or "union" in path.lower(),
            }

        # 4. Standard RFC 3164 / 5424 Syslog line
        syslog_match = re.match(r'^<(\d+)>([A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+([^\s:]+)\s+([^:]+):\s+(.*)$', line)
        if syslog_match:
            prival, _, host, app_name, log_msg = syslog_match.groups()
            pri = int(prival)
            severity_num = pri & 7
            sev_map = {
                0: EventSeverity.CRITICAL, 1: EventSeverity.CRITICAL,
                2: EventSeverity.CRITICAL, 3: EventSeverity.HIGH,
                4: EventSeverity.MEDIUM, 5: EventSeverity.LOW,
                6: EventSeverity.INFO, 7: EventSeverity.DEBUG
            }
            return {
                "id": f"evt-{uuid.uuid4().hex[:12]}",
                "timestamp": datetime.utcnow(),
                "event_type": EventType.NETWORK_CONNECTION,
                "severity": sev_map.get(severity_num, EventSeverity.INFO),
                "source_type": LogSourceType.SYSLOG,
                "source_ip": None,
                "destination_ip": None,
                "source_port": None,
                "destination_port": None,
                "protocol": "SYSLOG",
                "host_name": host,
                "user_name": None,
                "process_name": app_name,
                "message": log_msg,
                "raw_log": line,
                "parsed_fields": {"facility": pri >> 3, "severity_code": severity_num, "app": app_name},
                "is_anomalous": severity_num <= 3,
            }

        # Fallback generic message
        return {
            "id": f"evt-{uuid.uuid4().hex[:12]}",
            "timestamp": datetime.utcnow(),
            "event_type": EventType.NETWORK_CONNECTION,
            "severity": EventSeverity.INFO,
            "source_type": LogSourceType.SYSLOG,
            "source_ip": "10.0.1.1",
            "destination_ip": "10.0.1.108",
            "source_port": None,
            "destination_port": None,
            "protocol": "RAW",
            "host_name": "unknown-host",
            "user_name": None,
            "process_name": None,
            "message": line,
            "raw_log": line,
            "parsed_fields": {},
            "is_anomalous": False,
        }
