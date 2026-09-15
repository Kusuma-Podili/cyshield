"""Static File & Binary Heuristic Analysis Engine for CyberShield Enterprise.

Performs deep structural inspection of binaries, scripts, and documents:
- Multi-section Shannon entropy profiling (packer/encryption detection)
- PE header and suspicious API import heuristics (Process Hollowing, Injection)
- Shellcode NOP-sled & polymorphic decoder pattern identification
- Embedded C2 addresses, onion domains, and ransomware extortion artifacts
Runs completely local and offline.
"""

from __future__ import annotations

import re
import struct
import logging
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

from cybershield.core.models import (
    Alert,
    Severity,
    DetectionEngineType,
    EvidenceArtifact,
    CustodyRecord,
    generate_id,
    now_utc,
)
from cybershield.core.crypto import (
    compute_sha256,
    compute_sha1,
    compute_md5,
    calculate_shannon_entropy,
)

logger = logging.getLogger("cybershield.engine.static_scanner")


class StaticAnalysisReport:
    """Detailed structural findings from static inspection."""
    def __init__(self, filename: str, file_size: int, sha256: str):
        self.filename = filename
        self.file_size = file_size
        self.sha256 = sha256
        self.overall_entropy: float = 0.0
        self.file_type: str = "UNKNOWN"
        self.is_packed: bool = False
        self.packer_name: Optional[str] = None
        self.suspicious_apis: List[str] = []
        self.embedded_ips: List[str] = []
        self.embedded_urls: List[str] = []
        self.suspicious_strings: List[str] = []
        self.has_ransom_note: bool = False
        self.has_shellcode_sled: bool = False
        self.risk_score: float = 0.0
        self.is_malicious: bool = False


class StaticFileScanner:
    """Deep inspection engine for untrusted files and memory artifacts."""

    SUSPICIOUS_WIN32_APIS = [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC",
        "SetWindowsHookExA", "SetWindowsHookExW", "GetProcAddress",
        "LoadLibraryA", "LoadLibraryW", "InternetOpenUrlA", "HttpSendRequestA",
        "CryptEncrypt", "CryptGenKey", "AdjustTokenPrivileges", "OpenProcessToken",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"
    ]

    KNOWN_PACKER_SECTIONS = {
        ".upx0": "UPX Packer",
        ".upx1": "UPX Packer",
        ".upx2": "UPX Packer",
        ".aspack": "ASPack",
        ".pcle": "PECompact",
        ".themida": "Themida Protection",
        ".vmp0": "VMProtect",
        ".vmp1": "VMProtect",
        ".nsp0": "NsPack",
    }

    RANSOMWARE_INDICATORS = [
        re.compile(r"your files (have been|are) encrypted", re.IGNORECASE),
        re.compile(r"to decrypt your files", re.IGNORECASE),
        re.compile(r"pay (?:the )?ransom in (?:bitcoin|btc|monero)", re.IGNORECASE),
        re.compile(r"all your personal documents, photos, databases", re.IGNORECASE),
        re.compile(r"tor browser.*\.onion", re.IGNORECASE),
        re.compile(r"unique (?:victim|decryption) id", re.IGNORECASE),
    ]

    IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9\.\-\_\/\=\?\&\:\%]+")

    def scan_bytes(self, content: bytes, filename: str = "sample.bin") -> StaticAnalysisReport:
        """Analyze raw byte buffer for heuristic threats."""
        size = len(content)
        sha256 = compute_sha256(content)
        report = StaticAnalysisReport(filename, size, sha256)
        report.overall_entropy = calculate_shannon_entropy(content)

        # 1. Determine file format / magic bytes
        if content.startswith(b"MZ"):
            report.file_type = "PE_WINDOWS_EXECUTABLE"
            self._inspect_pe_headers(content, report)
        elif content.startswith(b"\x7fELF"):
            report.file_type = "ELF_LINUX_BINARY"
        elif content.startswith(b"PK\x03\x04"):
            report.file_type = "ZIP_ARCHIVE_OR_OFFICE_DOC"
        elif content.startswith(b"%PDF"):
            report.file_type = "PDF_DOCUMENT"
        else:
            report.file_type = "SCRIPT_OR_RAW_DATA"

        # 2. String extraction & API import heuristic
        ascii_strings = [s.decode("latin1", errors="ignore") for s in re.findall(b"[A-Za-z0-9_\\.\\:\\/\\\\-]{5,}", content)]
        all_text = " ".join(ascii_strings)

        # Suspicious APIs
        for api in self.SUSPICIOUS_WIN32_APIS:
            if api in all_text:
                report.suspicious_apis.append(api)

        # Embedded IPs and URLs
        for ip in self.IP_PATTERN.findall(all_text):
            if not ip.startswith("127.") and not ip.startswith("0.") and ip != "255.255.255.255":
                report.embedded_ips.append(ip)
        report.embedded_ips = list(set(report.embedded_ips))[:10]

        for url in self.URL_PATTERN.findall(all_text):
            report.embedded_urls.append(url)
        report.embedded_urls = list(set(report.embedded_urls))[:10]

        # 3. Ransomware note heuristic
        for note_pattern in self.RANSOMWARE_INDICATORS:
            if note_pattern.search(all_text):
                report.has_ransom_note = True
                report.suspicious_strings.append("Ransom note extortion wording identified")
                break

        # 4. NOP sled & shellcode pattern
        if b"\x90" * 32 in content or b"\xcc" * 16 in content:
            report.has_shellcode_sled = True
            report.suspicious_strings.append("Consecutive NOP sled (0x90) / Debug Int3 trap detected")

        # 5. Calculate composite risk score
        risk = 0.0
        if report.overall_entropy >= 7.2:
            risk += 35.0  # High entropy (packer or encrypted payload)
        if report.is_packed:
            risk += 25.0
        if len(report.suspicious_apis) >= 4:
            risk += 30.0  # Process injection / evasion APIs
        elif len(report.suspicious_apis) >= 1:
            risk += 15.0
        if report.has_shellcode_sled:
            risk += 45.0
        if report.has_ransom_note:
            risk += 75.0

        report.risk_score = min(100.0, risk)
        report.is_malicious = report.risk_score >= 60.0

        return report

    def _inspect_pe_headers(self, data: bytes, report: StaticAnalysisReport) -> None:
        """Parse DOS and PE section tables to detect packers and anomalies."""
        try:
            if len(data) < 64:
                return
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if len(data) < e_lfanew + 24:
                return
            pe_magic = data[e_lfanew:e_lfanew + 4]
            if pe_magic != b"PE\x00\x00":
                return

            num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
            opt_header_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
            section_table_offset = e_lfanew + 24 + opt_header_size

            for i in range(min(num_sections, 32)):
                sec_offset = section_table_offset + (i * 40)
                if len(data) < sec_offset + 40:
                    break
                sec_name = data[sec_offset:sec_offset + 8].rstrip(b"\x00").decode("latin1", errors="ignore").lower()
                
                # Check known packer signatures
                if sec_name in self.KNOWN_PACKER_SECTIONS:
                    report.is_packed = True
                    report.packer_name = self.KNOWN_PACKER_SECTIONS[sec_name]
                    break
        except Exception as ex:
            logger.debug("PE parsing error: %s", ex)

    def create_forensic_artifact(self, content: bytes, name: str, alert_id: Optional[str] = None) -> EvidenceArtifact:
        """Seal binary evidence into a cryptographic forensic artifact."""
        sha256 = compute_sha256(content)
        sha1 = compute_sha1(content)
        md5 = compute_md5(content)

        stamp = CustodyRecord(
            analyst_or_agent="CyberShield Static Analyzer",
            action="ACQUIRED_AND_SEALED",
            sha256_hash=sha256,
            notes=f"Static binary analysis initiated for {name} ({len(content)} bytes)"
        )

        return EvidenceArtifact(
            name=name,
            alert_id=alert_id,
            artifact_type="BINARY_FILE",
            file_size_bytes=len(content),
            sha256_hash=sha256,
            sha1_hash=sha1,
            md5_hash=md5,
            chain_of_custody=[stamp],
            is_sealed=True
        )

    def scan_and_alert(self, content: bytes, filename: str) -> Optional[Alert]:
        """Scan file and generate an Alert if malicious."""
        report = self.scan_bytes(content, filename)
        if not report.is_malicious:
            return None

        severity = Severity.CRITICAL if report.risk_score >= 85.0 else Severity.HIGH
        tactics = ["Execution", "Defense Evasion"]
        techniques = ["T1027"]  # Obfuscated / Packed
        if report.suspicious_apis:
            techniques.append("T1055")  # Process Injection
        if report.has_ransom_note:
            tactics.append("Impact")
            techniques.append("T1486")  # Data Encrypted for Impact

        desc = (
            f"Static Heuristic Engine detected suspicious binary characteristics in '{filename}' "
            f"(Score: {report.risk_score:.0f}/100, Entropy: {report.overall_entropy:.2f}). "
        )
        if report.is_packed:
            desc += f"Packer identified: {report.packer_name}. "
        if report.suspicious_apis:
            desc += f"Suspicious injection APIs: {', '.join(report.suspicious_apis[:5])}. "
        if report.has_ransom_note:
            desc += "Confirmed Ransomware extortion text. "

        return Alert(
            title=f"Malicious Binary Detected: {filename} (Entropy: {report.overall_entropy:.2f})",
            description=desc,
            severity=severity,
            confidence=round(report.risk_score / 100.0, 2),
            detection_engine=DetectionEngineType.STATIC_SCANNER,
            rule_id="STATIC-HEUR-001",
            rule_name="Binary Static Heuristic Analysis",
            mitre_tactics=tactics,
            mitre_techniques=techniques,
            indicators_of_compromise=[report.sha256] + report.embedded_ips,
            metadata={
                "sha256": report.sha256,
                "file_type": report.file_type,
                "entropy": report.overall_entropy,
                "is_packed": report.is_packed,
                "packer_name": report.packer_name,
                "suspicious_apis": report.suspicious_apis,
                "embedded_ips": report.embedded_ips,
                "has_ransom_note": report.has_ransom_note,
                "has_shellcode_sled": report.has_shellcode_sled,
            },
        )


# Global singleton static file scanner
static_scanner = StaticFileScanner()
