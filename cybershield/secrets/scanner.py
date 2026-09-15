"""CyberShield Enterprise - Autonomous Secret Sprawl & Token Entropy Scanner Engine.
Implements multi-algorithm Shannon entropy calculation, high-precision pattern matching,
context proximity heuristics, automated masking, and remediation orchestration.
"""

import re
import math
import uuid
import time
from typing import Dict, List, Optional, Tuple, Set, Any
from datetime import datetime, timezone
from collections import Counter, defaultdict

from .schemas import (
    SecretType,
    SecretSeverity,
    EntropyMetric,
    SecretFinding,
    SecretScanSummary,
    SecretStatsResponse,
)


class SecretEntropyScanner:
    """High-performance secrets & credentials scanner with entropy verification."""

    # Pre-compiled high-confidence deterministic signatures
    PATTERNS: Dict[SecretType, Tuple[re.Pattern, SecretSeverity, str, str]] = {
        SecretType.AWS_ACCESS_KEY: (
            re.compile(r'\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b'),
            SecretSeverity.CRITICAL,
            "aws_access_key_id",
            "revoke_aws_iam_key",
        ),
        SecretType.GITHUB_TOKEN: (
            re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b'),
            SecretSeverity.CRITICAL,
            "github_personal_access_token",
            "revoke_github_token",
        ),
        SecretType.SLACK_TOKEN: (
            re.compile(r'\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}\b'),
            SecretSeverity.HIGH,
            "slack_bot_or_user_token",
            "revoke_slack_app_token",
        ),
        SecretType.SSH_RSA_PRIVATE_KEY: (
            re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
            SecretSeverity.CRITICAL,
            "asymmetric_private_key_header",
            "rotate_ssh_host_keys",
        ),
        SecretType.PGP_PRIVATE_KEY: (
            re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
            SecretSeverity.CRITICAL,
            "pgp_private_key_block",
            "revoke_pgp_key",
        ),
        SecretType.DATABASE_CONNECTION_URI: (
            re.compile(r'\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[a-zA-Z0-9_\-\.]+:[^@\s\r\n]+@[a-zA-Z0-9_\-\.]+:[0-9]{1,5}\/[a-zA-Z0-9_\-\.]*'),
            SecretSeverity.CRITICAL,
            "plaintext_database_connection_uri",
            "rotate_db_service_account",
        ),
        SecretType.JWT_BEARER_TOKEN: (
            re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'),
            SecretSeverity.HIGH,
            "json_web_token_bearer",
            "invalidate_jwt_session",
        ),
        SecretType.GCP_API_KEY: (
            re.compile(r'\bAIza[0-9A-Za-z\\-_]{35}\b'),
            SecretSeverity.HIGH,
            "google_cloud_platform_api_key",
            "revoke_gcp_api_key",
        ),
        SecretType.STRIPE_API_KEY: (
            re.compile(r'\bsk_live_[0-9a-zA-Z]{24}\b'),
            SecretSeverity.CRITICAL,
            "stripe_production_secret_key",
            "roll_stripe_restricted_key",
        ),
    }

    # Proximity keywords that elevate probability of high-entropy strings being genuine credentials
    KEYWORD_PROXIMITY_SET: Set[str] = {
        "password", "secret", "api_key", "apikey", "token", "bearer",
        "credential", "passwd", "auth", "private_key", "conn_str",
        "client_secret", "access_key", "access_token"
    }

    def __init__(self):
        self.findings_store: Dict[str, SecretFinding] = {}

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy in bits per character.
        H(X) = - sum(p_i * log2(p_i))
        """
        if not data:
            return 0.0

        length = len(data)
        counts = Counter(data)
        entropy = 0.0
        for count in counts.values():
            p_i = count / length
            entropy -= p_i * math.log2(p_i)

        return round(entropy, 4)

    @staticmethod
    def calculate_metric_entropy(data: str) -> float:
        """Calculate normalized metric entropy (0.0 to 1.0) relative to string length."""
        if len(data) <= 1:
            return 0.0
        shannon = SecretEntropyScanner.calculate_shannon_entropy(data)
        max_entropy = math.log2(len(data))
        return round(shannon / max_entropy, 4) if max_entropy > 0 else 0.0

    @staticmethod
    def classify_charset(data: str) -> str:
        """Determine whether candidate string is Hexadecimal, Base64, or Alphanumeric."""
        if re.fullmatch(r'^[0-9a-fA-F]+$', data):
            return "hex"
        elif re.search(r'[+/=]', data) and re.fullmatch(r'^[0-9a-zA-Z+/=]+$', data):
            return "base64"
        elif re.fullmatch(r'^[0-9a-zA-Z]+$', data):
            return "alphanumeric"
        return "mixed_symbols"

    @staticmethod
    def mask_secret(secret: str) -> str:
        """Obfuscate secret preserving minor prefix / suffix for safe auditing."""
        length = len(secret)
        if length <= 8:
            return "*" * length
        prefix_len = min(4, length // 4)
        suffix_len = min(4, length // 4)
        masked_core = "*" * (length - prefix_len - suffix_len)
        return f"{secret[:prefix_len]}{masked_core}{secret[-suffix_len:]}"

    def scan_text(
        self,
        text: str,
        source_label: str = "inline_snippet",
        entropy_threshold: float = 4.2,
    ) -> SecretScanSummary:
        """Scan text buffer line-by-line using deterministic regex and entropy analysis."""
        start_time = time.perf_counter()
        findings: List[SecretFinding] = []
        lines = text.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            # 1. Deterministic Signature Detection
            for sec_type, (pat, severity, rule_name, playbook) in self.PATTERNS.items():
                for match in pat.finditer(line_str):
                    val = match.group(0)
                    entropy = self.calculate_shannon_entropy(val)
                    masked = self.mask_secret(val)

                    finding = SecretFinding(
                        finding_id=f"sec-{uuid.uuid4().hex[:10]}",
                        secret_type=sec_type,
                        severity=severity,
                        raw_snippet_masked=masked,
                        file_path=source_label,
                        line_number=line_idx,
                        entropy=entropy,
                        rule_name=rule_name,
                        remediation_playbook=playbook,
                    )
                    findings.append(finding)
                    self.findings_store[finding.finding_id] = finding

            # 2. Heuristic High-Entropy String Detection
            # Look for variable assignments: var_name = "random_high_entropy_token"
            line_lower = line_str.lower()
            matched_keyword = None
            for kw in sorted(self.KEYWORD_PROXIMITY_SET, key=len, reverse=True):
                if kw in line_lower:
                    matched_keyword = kw
                    break

            if matched_keyword:
                # Extract potential tokens enclosed in quotes or whitespace
                candidates = re.findall(r'["\']([^"\'\s]{20,128})["\']', line_str)
                for cand in candidates:
                    # Skip if already detected by deterministic pattern
                    already_flagged = any(
                        cand in f.raw_snippet_masked or f.raw_snippet_masked.startswith(cand[:4])
                        for f in findings
                        if f.line_number == line_idx
                    )
                    if already_flagged:
                        continue

                    entropy = self.calculate_shannon_entropy(cand)
                    if entropy >= entropy_threshold:
                        finding = SecretFinding(
                            finding_id=f"sec-entropy-{uuid.uuid4().hex[:8]}",
                            secret_type=SecretType.HIGH_ENTROPY_STRING,
                            severity=SecretSeverity.HIGH,
                            raw_snippet_masked=self.mask_secret(cand),
                            file_path=source_label,
                            line_number=line_idx,
                            entropy=entropy,
                            rule_name="high_entropy_secret_assignment",
                            proximity_keyword=matched_keyword,
                            remediation_playbook="investigate_and_rotate_credential",
                        )
                        findings.append(finding)
                        self.findings_store[finding.finding_id] = finding

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        critical = sum(1 for f in findings if f.severity == SecretSeverity.CRITICAL)
        high = sum(1 for f in findings if f.severity == SecretSeverity.HIGH)
        medium = sum(1 for f in findings if f.severity == SecretSeverity.MEDIUM)

        return SecretScanSummary(
            total_scanned_items=len(lines),
            findings_count=len(findings),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            findings=findings,
            scan_duration_ms=duration_ms,
        )

    def scan_file(self, file_path: str, entropy_threshold: float = 4.2) -> SecretScanSummary:
        """Read and scan target file from disk."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return self.scan_text(
                text=content,
                source_label=file_path,
                entropy_threshold=entropy_threshold,
            )
        except Exception as e:
            return SecretScanSummary(
                total_scanned_items=0,
                findings_count=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                findings=[],
                scan_duration_ms=0.0,
            )

    def remediate_finding(self, finding_id: str) -> Optional[SecretFinding]:
        """Mark secret finding remediated and record resolution."""
        finding = self.findings_store.get(finding_id)
        if finding:
            finding.is_remediated = True
            return finding
        return None

    def get_statistics(self) -> SecretStatsResponse:
        """Compute platform-wide credential sprawl statistics."""
        total = len(self.findings_store)
        remediated = sum(1 for f in self.findings_store.values() if f.is_remediated)
        unresolved = total - remediated

        type_counts: Dict[str, int] = defaultdict(int)
        for f in self.findings_store.values():
            type_counts[f.secret_type.value] += 1

        return SecretStatsResponse(
            total_findings=total,
            unresolved_findings=unresolved,
            remediated_findings=remediated,
            findings_by_type=dict(type_counts),
        )
