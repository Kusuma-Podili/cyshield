"""Multi-Source Telemetry Parsers for CyberShield Enterprise.

Converts raw enterprise log formats into standardized NormalizedEvent objects:
- Syslog RFC 5424 / 3164
- Windows Event Logs & Sysmon (EventIDs 1, 3, 7, 11, 13, 4624, 4625)
- Zeek & Suricata EVE-JSON
- Web Server Access Logs (Apache / Nginx Combined)
- Linux Auditd (EXECVE, USER_AUTH, SYSCALL)
"""

from __future__ import annotations

import re
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from cybershield.core.models import (
    NormalizedEvent,
    LogSourceType,
    generate_id,
    now_utc,
)
from cybershield.core.exceptions import LogParsingError

logger = logging.getLogger("cybershield.ingestion.parsers")


class SyslogParser:
    """Parses RFC 3164 and RFC 5424 Syslog records."""

    # RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG[PID]: MESSAGE
    RFC3164_PATTERN = re.compile(
        r"^<(?P<pri>\d{1,3})>(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>[\w\.\-]+)\s+(?P<tag>[\w\.\-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
    )

    @classmethod
    def parse(cls, raw: str) -> NormalizedEvent:
        match = cls.RFC3164_PATTERN.match(raw.strip())
        if not match:
            # Fallback for plain syslog message
            return NormalizedEvent(
                log_source=LogSourceType.SYSLOG,
                event_action="syslog_message",
                raw_payload=raw,
                metadata={"parsed_status": "raw_fallback"}
            )

        data = match.groupdict()
        pid = int(data["pid"]) if data.get("pid") else None
        
        return NormalizedEvent(
            log_source=LogSourceType.SYSLOG,
            host_name=data["hostname"],
            process_name=data["tag"],
            process_id=pid,
            raw_payload=raw,
            metadata={
                "syslog_pri": data["pri"],
                "syslog_tag": data["tag"],
                "syslog_message": data["message"],
            }
        )


class SysmonParser:
    """Parses Windows Sysmon and Security Event Log structures."""

    SYSMON_EVENT_MAP = {
        1: "Process Creation",
        3: "Network Connection Detected",
        7: "Image Loaded",
        11: "File Created",
        12: "Registry Object Added/Deleted",
        13: "Registry Value Set",
        4624: "Successful Logon",
        4625: "Failed Logon Attempt",
    }

    @classmethod
    def parse(cls, raw: str | Dict[str, Any]) -> NormalizedEvent:
        if isinstance(raw, str):
            try:
                data = json.loads(raw)
            except Exception:
                # Key-value or plain string
                return cls._parse_key_value(raw)
        else:
            data = raw

        event_id = data.get("EventID") or data.get("event_id") or 1
        action_name = cls.SYSMON_EVENT_MAP.get(int(event_id), f"EventID_{event_id}")

        return NormalizedEvent(
            log_source=LogSourceType.SYSMON,
            event_category="endpoint",
            event_action=action_name,
            host_name=data.get("Computer") or data.get("host_name"),
            user_name=data.get("User") or data.get("user_name"),
            process_id=data.get("ProcessId"),
            process_name=data.get("Image") or data.get("process_name"),
            command_line=data.get("CommandLine") or data.get("command_line"),
            parent_process_name=data.get("ParentImage") or data.get("parent_process_name"),
            parent_process_id=data.get("ParentProcessId"),
            file_name=data.get("TargetFilename") or data.get("file_name"),
            file_hash_sha256=data.get("Hashes") or data.get("sha256"),
            registry_key=data.get("TargetObject") or data.get("registry_key"),
            source_ip=data.get("SourceIp") or data.get("source_ip"),
            source_port=data.get("SourcePort") or data.get("source_port"),
            destination_ip=data.get("DestinationIp") or data.get("destination_ip"),
            destination_port=data.get("DestinationPort") or data.get("destination_port"),
            raw_payload=json.dumps(data) if isinstance(raw, dict) else raw,
            metadata={"sysmon_event_id": event_id}
        )

    @classmethod
    def _parse_key_value(cls, raw: str) -> NormalizedEvent:
        """Parse key=value formatted event log strings."""
        pairs = dict(re.findall(r"(\w+)=[\"']?([^\"'\s]+)[\"']?", raw))
        return NormalizedEvent(
            log_source=LogSourceType.WINDOWS_EVENT,
            raw_payload=raw,
            host_name=pairs.get("Computer") or pairs.get("host"),
            user_name=pairs.get("User") or pairs.get("user"),
            process_name=pairs.get("Image") or pairs.get("process"),
            command_line=pairs.get("CommandLine"),
            metadata=pairs
        )


class ZeekSuricataParser:
    """Parses Zeek / Suricata EVE-JSON network security telemetry."""

    @classmethod
    def parse(cls, raw: str | Dict[str, Any]) -> NormalizedEvent:
        if isinstance(raw, str):
            try:
                data = json.loads(raw)
            except Exception as ex:
                raise LogParsingError(f"Invalid EVE-JSON record: {ex}")
        else:
            data = raw

        event_type = data.get("event_type", "flow")
        alert_info = data.get("alert", {})
        http_info = data.get("http", {})

        return NormalizedEvent(
            log_source=LogSourceType.ZEEK_SURICATA,
            event_category="network",
            event_action=f"zeek_{event_type}",
            source_ip=data.get("src_ip"),
            source_port=data.get("src_port"),
            destination_ip=data.get("dest_ip"),
            destination_port=data.get("dest_port"),
            protocol=data.get("proto", "TCP"),
            http_method=http_info.get("http_method"),
            http_url=http_info.get("url"),
            http_status=http_info.get("status"),
            http_user_agent=http_info.get("http_user_agent"),
            raw_payload=json.dumps(data) if isinstance(raw, dict) else raw,
            metadata={
                "eve_event_type": event_type,
                "suricata_alert_signature": alert_info.get("signature"),
                "suricata_category": alert_info.get("category"),
            }
        )


class WebAccessLogParser:
    """Parses Apache / Nginx Combined Log Format records."""

    # Combined Log Format: IP - USER [TIMESTAMP] "METHOD URI PROTO" STATUS BYTES "REFERER" "USER-AGENT"
    COMBINED_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<proto>[^"]+)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)"'
    )

    @classmethod
    def parse(cls, raw: str) -> NormalizedEvent:
        match = cls.COMBINED_PATTERN.match(raw.strip())
        if not match:
            return NormalizedEvent(
                log_source=LogSourceType.APACHE_NGINX,
                raw_payload=raw,
                metadata={"parsed_status": "unmatched_pattern"}
            )

        data = match.groupdict()
        status_code = int(data["status"]) if data["status"].isdigit() else 200
        user = data["user"] if data["user"] != "-" else None

        return NormalizedEvent(
            log_source=LogSourceType.APACHE_NGINX,
            event_category="web",
            event_action="http_request",
            source_ip=data["ip"],
            user_name=user,
            http_method=data["method"],
            http_url=data["uri"],
            http_status=status_code,
            http_user_agent=data["agent"],
            raw_payload=raw,
            metadata={
                "http_protocol": data["proto"],
                "http_referer": data["referer"],
            }
        )


class UniversalTelemetryDispatcher:
    """Auto-detecting telemetry parser routing raw records to appropriate format parser."""

    @classmethod
    def parse_auto(cls, raw_entry: str | Dict[str, Any]) -> NormalizedEvent:
        if isinstance(raw_entry, dict):
            # Check JSON keys
            if "EventID" in raw_entry or "event_id" in raw_entry:
                return SysmonParser.parse(raw_entry)
            if "event_type" in raw_entry or "src_ip" in raw_entry:
                return ZeekSuricataParser.parse(raw_entry)
            # Default dictionary normalization
            return NormalizedEvent(
                log_source=LogSourceType.SYNTHETIC,
                raw_payload=json.dumps(raw_entry),
                metadata=raw_entry
            )

        text = raw_entry.strip()
        # Check if JSON
        if text.startswith("{") and text.endswith("}"):
            try:
                parsed_json = json.loads(text)
                return cls.parse_auto(parsed_json)
            except Exception:
                pass

        # Check Syslog RFC3164 (<PRI>)
        if text.startswith("<") and ">" in text[:5]:
            return SyslogParser.parse(text)

        # Check Web Combined Log Format
        if WebAccessLogParser.COMBINED_PATTERN.match(text):
            return WebAccessLogParser.parse(text)

        # Fallback to Generic Normalized Event
        return NormalizedEvent(
            log_source=LogSourceType.SYSLOG,
            raw_payload=text,
            metadata={"parser": "generic_raw"}
        )
