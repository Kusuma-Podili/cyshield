"""Automated Tests for Wave 2: Digital Forensics & Incident Response (DFIR)."""

import struct
from datetime import datetime, timezone, timedelta
import pytest
from httpx import AsyncClient, ASGITransport

from cybershield.api.server import app
from cybershield.dfir.schemas import ArtifactType, ArtifactAnalyzeRequest, SuperTimelineRequest
from cybershield.dfir.evtx_parser import EVTXParser
from cybershield.dfir.prefetch_parser import PrefetchParser
from cybershield.dfir.mft_parser import MFTParser
from cybershield.dfir.auditd_parser import AuditdParser
from cybershield.dfir.timeline_engine import TimelineEngine


def test_evtx_binary_and_threat_parsing():
    """Verify EVTX record parsing, LOLBin detection, and log clearing alerts."""
    # Build synthetic binary EVTX record: magic "**\x00\x00", length=120, id=101, FILETIME
    now = datetime.now(timezone.utc)
    ft = int((now - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)

    # XML payload containing event 4688 and vssadmin delete shadows
    xml_data = "<Event><System><EventID>4688</EventID></System><EventData><Data Name='CommandLine'>vssadmin.exe delete shadows /all /quiet</Data></EventData></Event>"
    xml_bytes = xml_data.encode("utf-16le")
    rec_len = 24 + len(xml_bytes) + 16
    rec_hdr = b"**\x00\x00" + struct.pack("<IQI", rec_len, 101, ft & 0xFFFFFFFF) + struct.pack("<I", (ft >> 32) & 0xFFFFFFFF)
    evtx_pkt = rec_hdr + xml_bytes + b"\x00" * 16

    events, findings = EVTXParser.parse_records(evtx_pkt, "Security.evtx")
    assert len(events) >= 1
    assert any(e.entity_name == "vssadmin.exe" for e in events)
    assert len(findings) >= 1
    assert any(f.finding_id == "DFIR-LOLBIN-101" for f in findings)


def test_prefetch_execution_parsing():
    """Verify Windows Prefetch execution artifact parsing and offensive tool alerts."""
    # Version 30 (Win 10), Magic SCCA, Exe Name "MIMIKATZ.EXE", Run count 4
    version = struct.pack("<I", 30)
    magic = b"SCCA"
    file_size = struct.pack("<I", 1024)
    exe_name_bytes = "MIMIKATZ.EXE\x00".encode("utf-16le")
    exe_padding = b"\x00" * (60 - len(exe_name_bytes))
    header_part = version + magic + file_size + b"\x00" * 4 + exe_name_bytes + exe_padding

    # Pad up to offset 128 (where timestamps live)
    pad_to_128 = b"\x00" * (128 - len(header_part))

    # Add 4 timestamps
    now = datetime.now(timezone.utc)
    ft = int((now - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)
    ts_bytes = struct.pack("<Q", ft) * 4 + b"\x00" * (32)

    # Pad to offset 200 (run count)
    pad_to_200 = b"\x00" * (200 - (128 + len(ts_bytes)))
    run_count_bytes = struct.pack("<I", 4)

    pf_raw = header_part + pad_to_128 + ts_bytes + pad_to_200 + run_count_bytes + b"\x00" * 200

    events, findings = PrefetchParser.parse_file(pf_raw, "MIMIKATZ.EXE-B8C9D0E1.pf")
    assert len(events) >= 1
    assert events[0].entity_name == "MIMIKATZ.EXE"
    assert len(findings) >= 1
    assert findings[0].mitre_technique == "T1204.002"
    assert "MIMIKATZ.EXE" in findings[0].iocs


def test_mft_timestomping_detection():
    """Verify NTFS $MFT parsing and anti-forensics timestomping detection."""
    # Construct 1024-byte MFT record with FILE magic
    rec = bytearray(b"FILE" + b"\x00" * 1020)
    # First attribute offset = 56 (0x38)
    struct.pack_into("<H", rec, 20, 56)
    # In-use file flag
    struct.pack_into("<H", rec, 22, 0x01)

    # Attribute 1: $STANDARD_INFORMATION (0x10) at offset 56
    # Type (4B), Length (4B: 72), Non-resident (1B: 0), Content offset (2B: 24)
    struct.pack_into("<II", rec, 56, 0x10, 72)
    rec[64] = 0
    struct.pack_into("<H", rec, 76, 24)
    # Timestamps at 56 + 24 = 80
    # Make $SI created timestamp 3 hours ago (artificially backdated)
    past_time = datetime.now(timezone.utc) - timedelta(hours=3)
    past_ft = int((past_time - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)
    struct.pack_into("<QQQ", rec, 80, past_ft, past_ft, past_ft)

    # Attribute 2: $FILE_NAME (0x30) at offset 56 + 72 = 128
    # Length = 96, Non-resident = 0, Content offset = 24
    struct.pack_into("<II", rec, 128, 0x30, 96)
    rec[136] = 0
    struct.pack_into("<H", rec, 148, 24)
    # $FN content starts at 128 + 24 = 152
    # Timestamps at 152 + 8 = 160
    # $FN created timestamp is NOW (original birth time)
    now = datetime.now(timezone.utc)
    now_ft = int((now - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)
    struct.pack_into("<QQ", rec, 160, now_ft, now_ft)
    # Name length at 152 + 64 = 216
    rec[216] = 8
    name_bytes = "backdoor".encode("utf-16le")
    rec[218 : 218 + len(name_bytes)] = name_bytes

    events, findings = MFTParser.parse_record(bytes(rec), "$MFT")
    assert len(events) >= 1
    assert any(e.entity_name == "backdoor" for e in events)
    assert len(findings) >= 1
    assert any(f.finding_id == "DFIR-TIMESTOMP-1" for f in findings)


def test_auditd_linux_syscall_parsing():
    """Verify Linux auditd journal log parsing and privilege escalation detection."""
    audit_log = (
        'type=SYSCALL msg=audit(1678901234.123:456): arch=c000003e syscall=59 success=yes exit=0 ppid=1200 pid=1234 auid=1001 uid=1001 euid=1001 comm="useradd" exe="/usr/sbin/useradd" key="user_creation"\n'
        'type=USER_CMD msg=audit(1678901235.456:457): pid=1240 uid=1001 auid=1001 euid=0 cmd="cat /etc/shadow"\n'
    )
    events, findings = AuditdParser.parse_log(audit_log)
    assert len(events) == 2
    assert any(e.entity_name == "useradd" for e in events)
    assert len(findings) == 2
    rule_ids = [f.finding_id for f in findings]
    assert "DFIR-AUDITD-1" in rule_ids
    assert "DFIR-AUDITD-PRIV-2" in rule_ids


@pytest.mark.asyncio
async def test_dfir_super_timeline_rest_api():
    """Verify DFIR REST API endpoints for artifact analysis and super-timeline querying."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Login
        login_resp = await ac.post("/api/auth/login", json={"username_or_email": "superadmin", "password": "CyberShield2026!"})
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 1. Get Artifact Capabilities
        res_caps = await ac.get("/api/dfir/artifacts", headers=headers)
        assert res_caps.status_code == 200
        assert "EVTX" in res_caps.json()["supported_artifacts"]

        # 2. Analyze Auditd Artifact via Text
        sample_auditd = 'type=USER_CMD msg=audit(1678901235.456:999): pid=1240 uid=1001 auid=1001 euid=0 cmd="sudo su -"\n'
        res_analyze = await ac.post(
            "/api/dfir/analyze",
            json={
                "artifact_type": "AUDITD",
                "filename": "audit.log",
                "payload_text": sample_auditd,
            },
            headers=headers,
        )
        assert res_analyze.status_code == 200
        data = res_analyze.json()
        assert data["success"] is True
        assert data["parsed_records_count"] >= 1

        # 3. Query Super-Timeline
        res_timeline = await ac.post(
            "/api/dfir/timeline",
            json={"only_suspicious": False},
            headers=headers,
        )
        assert res_timeline.status_code == 200
        tl_data = res_timeline.json()
        assert tl_data["total_events"] >= 1

        # 4. List All Forensic Findings
        res_findings = await ac.get("/api/dfir/findings", headers=headers)
        assert res_findings.status_code == 200
        assert isinstance(res_findings.json(), list)
