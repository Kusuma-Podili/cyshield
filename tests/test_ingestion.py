"""Unit tests for Telemetry Ingestion Parsers and CS-QL Query Engine."""

import pytest
from cybershield.ingestion.parsers import (
    SyslogParser,
    SysmonParser,
    ZeekSuricataParser,
    WebAccessLogParser,
    UniversalTelemetryDispatcher,
)
from cybershield.ingestion.query_engine import CSQLEngine
from cybershield.core.models import NormalizedEvent, LogSourceType


def test_syslog_rfc3164_parser():
    """Verify standard Syslog RFC 3164 record parsing."""
    raw = "<34>Oct 11 22:14:15 mymachine su[1234]: 'su root' failed for lonvick on /dev/pts/8"
    event = SyslogParser.parse(raw)
    assert event.host_name == "mymachine"
    assert event.process_name == "su"
    assert event.process_id == 1234


def test_sysmon_event_parser():
    """Verify Sysmon JSON event parsing."""
    raw_dict = {
        "EventID": 1,
        "Computer": "ws-dev-01.corp",
        "User": "developer_alice",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "ProcessId": 8840,
    }
    event = SysmonParser.parse(raw_dict)
    assert event.host_name == "ws-dev-01.corp"
    assert event.user_name == "developer_alice"
    assert event.process_name == "C:\\Windows\\System32\\cmd.exe"
    assert event.command_line == "cmd.exe /c whoami"


def test_web_combined_log_parser():
    """Verify Apache/Nginx combined log parsing."""
    raw = '198.51.100.44 - jdoe [12/Sep/2026:10:00:00 +0000] "GET /api/v1/data HTTP/1.1" 200 4520 "https://corp.net" "Mozilla/5.0"'
    event = WebAccessLogParser.parse(raw)
    assert event.source_ip == "198.51.100.44"
    assert event.user_name == "jdoe"
    assert event.http_method == "GET"
    assert event.http_url == "/api/v1/data"
    assert event.http_status == 200


def test_csql_query_engine():
    """Verify CS-QL filtering and aggregation over events."""
    events = [
        NormalizedEvent(process_name="powershell.exe", host_name="host-1", http_status=200),
        NormalizedEvent(process_name="cmd.exe", host_name="host-2", http_status=404),
        NormalizedEvent(process_name="powershell.exe", host_name="host-2", http_status=500),
    ]

    # Test filtering
    res1 = CSQLEngine.execute_events(events, 'process_name == "powershell.exe"')
    assert res1["total_matched"] == 2

    # Test stats aggregation
    res2 = CSQLEngine.execute_events(events, '* | stats count by process_name')
    assert res2["aggregation"]["powershell.exe"] == 2
    assert res2["aggregation"]["cmd.exe"] == 1
