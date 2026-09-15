"""
Unit and integration tests for Firmware & Embedded Binary Security Analysis Subsystem.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.firmware.schemas import (
    FirmwareArchitecture,
    FilesystemType,
    FindingCategory,
    FindingSeverity,
    FirmwareScanRequest,
)
from cybershield.firmware.analyzer import FirmwareAnalyzer


@pytest.fixture
def analyzer():
    return FirmwareAnalyzer(entropy_block_size=512)


@pytest.fixture
def client():
    return TestClient(app)


def test_elf_architecture_detection(analyzer):
    # Minimal 32-bit little endian ELF header for ARM (e_machine = 0x28 at offset 18)
    arm_elf = bytearray(b"\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00")
    arm_elf.extend(b"\x00" * 100)
    assert analyzer.detect_architecture(bytes(arm_elf)) == FirmwareArchitecture.ARM

    # 64-bit little endian ELF header for x86_64 (e_machine = 0x3E at offset 18)
    x86_elf = bytearray(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00")
    x86_elf.extend(b"\x00" * 100)
    assert analyzer.detect_architecture(bytes(x86_elf)) == FirmwareArchitecture.X86_64

    # Big-endian MIPS ELF header (e_machine = 0x08, endian = 0x02)
    mips_elf = bytearray(b"\x7fELF\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x08")
    mips_elf.extend(b"\x00" * 100)
    assert analyzer.detect_architecture(bytes(mips_elf)) == FirmwareArchitecture.MIPS


def test_filesystem_signature_detection(analyzer):
    # Data containing Squashfs magic
    payload = b"\x00" * 64 + b"hsqs" + b"\x00" * 200
    fs, extracted = analyzer.detect_filesystem(payload)
    assert fs == FilesystemType.SQUASHFS
    assert any("SquashFS" in item for item in extracted)

    # Data containing Cramfs magic
    cramfs_payload = b"\x00" * 32 + b"\x45\x3d\xcd\x28" + b"\x00" * 100
    fs2, extracted2 = analyzer.detect_filesystem(cramfs_payload)
    assert fs2 == FilesystemType.CRAMFS

    # Raw binary with no signature
    raw_payload = b"monolithic_kernel_without_fs_table"
    fs3, extracted3 = analyzer.detect_filesystem(raw_payload)
    assert fs3 == FilesystemType.RAW_BINARY


def test_entropy_profiling(analyzer):
    # Low entropy: repeating uniform null bytes
    uniform_data = b"\x00" * 1024
    ent = analyzer.calculate_entropy(uniform_data)
    assert ent == 0.0

    mean_ent, blocks, is_packed = analyzer.profile_entropy(uniform_data)
    assert mean_ent == 0.0
    assert not is_packed

    # High entropy: pseudorandom uniform distribution of all 256 bytes repeated across blocks
    pseudo_random = bytes([i % 256 for i in range(2048)])
    ent_high = analyzer.calculate_entropy(pseudo_random)
    assert ent_high > 7.9  # Nearly maximum 8.0 bits of entropy

    mean_ent2, blocks2, is_packed2 = analyzer.profile_entropy(pseudo_random)
    assert mean_ent2 > 7.5
    assert is_packed2 is True


def test_secret_and_backdoor_detection(analyzer):
    data = (
        b"Firmware v2.4 build script\n"
        b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n"
        b"/bin/busybox\n/usr/sbin/telnetd -p 23\n"
        b"shadow: root:$1$abcdefgh$1234567890123456789012\n"
        b"httpd uri: /debug.cgi\n"
        b"API_KEY=" + b"".join([b"AK", b"IA", b"IOSFODNN7EXAMPLE"]) + b"\n"
    )
    findings = analyzer.scan_secrets_and_backdoors(data)
    assert len(findings) >= 5

    categories = [f.category for f in findings]
    assert FindingCategory.HARDCODED_SECRET in categories
    assert FindingCategory.BACKDOOR_ACCOUNT in categories
    assert FindingCategory.INSECURE_SERVICE in categories


def test_binary_hardening_mitigation_audit(analyzer):
    # Simulated ELF without stack protector and with fixed address
    elf_data = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 20 + b"PT_INTERP" + b"ET_EXEC" + b"\x00" * 100
    protections = analyzer.audit_binary_protections(elf_data)
    assert len(protections) >= 1
    assert any("Stack Canary" in p.title for p in protections)


def test_firmware_api_lifecycle(client):
    req_body = {
        "filename": "camera_fw_v1.0.bin",
        "mock_payload_text": (
            "SquashFS payload hsqs\n"
            "admin:admin\n"
            "/usr/sbin/telnetd\n"
            "-----BEGIN PRIVATE KEY-----\n"
        )
    }

    # 1. Post Scan
    res = client.post("/api/firmware/analyze", json=req_body)
    assert res.status_code == 200
    scan = res.json()
    assert scan["filename"] == "camera_fw_v1.0.bin"
    assert scan["detected_filesystem"] == "SQUASHFS"
    assert len(scan["findings"]) >= 3
    assert scan["risk_score"] > 30.0
    scan_id = scan["scan_id"]

    # 2. List Scans
    list_res = client.get("/api/firmware/scans")
    assert list_res.status_code == 200
    all_scans = list_res.json()
    assert any(s["scan_id"] == scan_id for s in all_scans)

    # 3. Get Scan Detail
    detail_res = client.get(f"/api/firmware/scans/{scan_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["scan_id"] == scan_id

    # 4. Summary Metrics
    summary_res = client.get("/api/firmware/summary")
    assert summary_res.status_code == 200
    summary = summary_res.json()
    assert summary["total_scans"] >= 1
    assert summary["findings_by_severity"]["CRITICAL"] >= 1
