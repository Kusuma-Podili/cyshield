"""
Data Loss Prevention (DLP) Rules and Algorithmic Checksum Validators.
Includes ISO/IEC 7812 Luhn algorithm, US SSN validation, and cloud secret detectors.
"""

import re
from typing import List, Optional, Tuple
from cybershield.dlp.schemas import DLPMatch, DLPRule, DLPSeverity, SensitiveDataType


def validate_luhn(card_number: str) -> bool:
    """Validate number using standard ISO/IEC 7812 Luhn algorithm."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 2:
        return False

    checksum = 0
    reverse_digits = digits[::-1]

    for idx, digit in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = digit * 2
            checksum += doubled if doubled < 10 else doubled - 9
        else:
            checksum += digit

    return (checksum % 10) == 0


BUILTIN_DLP_RULES: List[DLPRule] = [
    DLPRule(
        id="DLP-PCI-001",
        name="PCI-DSS Payment Card Number",
        data_type=SensitiveDataType.CREDIT_CARD_PCI,
        severity=DLPSeverity.CRITICAL,
        description="Identifies Visa, MasterCard, Amex, and Discover credit card numbers passing Luhn checksum.",
        requires_checksum_validation=True,
    ),
    DLPRule(
        id="DLP-PII-001",
        name="US Social Security Number (SSN)",
        data_type=SensitiveDataType.SSN_PII,
        severity=DLPSeverity.HIGH,
        description="Identifies valid formatted US Social Security Numbers.",
    ),
    DLPRule(
        id="DLP-SECRET-001",
        name="AWS Cloud Access Key",
        data_type=SensitiveDataType.CLOUD_SECRET,
        severity=DLPSeverity.CRITICAL,
        description="Identifies Amazon Web Services Access Key IDs (AKIA...).",
    ),
    DLPRule(
        id="DLP-SECRET-002",
        name="GitHub Personal Access Token",
        data_type=SensitiveDataType.CLOUD_SECRET,
        severity=DLPSeverity.CRITICAL,
        description="Identifies GitHub authentication tokens (ghp_...).",
    ),
    DLPRule(
        id="DLP-KEY-001",
        name="Cryptographic Private Key Block",
        data_type=SensitiveDataType.PRIVATE_KEY,
        severity=DLPSeverity.CRITICAL,
        description="Identifies OpenSSH, RSA, or EC private key headers.",
    ),
    DLPRule(
        id="DLP-MARKER-001",
        name="Document Confidentiality Marker",
        data_type=SensitiveDataType.CONFIDENTIAL_MARKER,
        severity=DLPSeverity.MEDIUM,
        description="Detects corporate confidentiality and export control classification stamps.",
    ),
]


class DLPPatternMatcher:
    """Matches text against sensitive data patterns and applies algorithmic verification."""

    # Regex definitions
    CC_REGEX = re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b|\b\d{15,16}\b")
    SSN_REGEX = re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b")
    AWS_KEY_REGEX = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
    GITHUB_PAT_REGEX = re.compile(r"\bghp_[a-zA-Z0-9]{36}\b")
    PRIV_KEY_REGEX = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
    CONFIDENTIAL_REGEX = re.compile(r"\b(?:CONFIDENTIAL|PROPRIETARY|RESTRICTED|DO NOT DISTRIBUTE)\b", re.IGNORECASE)

    @classmethod
    def scan_text(cls, text: str) -> List[DLPMatch]:
        """Scan text and return identified violations."""
        matches: List[DLPMatch] = []
        counter = 0

        # 1. Credit Cards (Luhn validated)
        for m in cls.CC_REGEX.finditer(text):
            raw = m.group(0)
            cleaned = re.sub(r"[- ]", "", raw)
            if validate_luhn(cleaned):
                counter += 1
                masked = f"************{cleaned[-4:]}"
                matches.append(
                    DLPMatch(
                        match_id=f"M-{counter}",
                        data_type=SensitiveDataType.CREDIT_CARD_PCI,
                        severity=DLPSeverity.CRITICAL,
                        rule_name="PCI-DSS Payment Card Number",
                        snippet_masked=masked,
                        confidence=98.0,
                        start_pos=m.start(),
                        end_pos=m.end(),
                    )
                )

        # 2. US SSN
        for m in cls.SSN_REGEX.finditer(text):
            raw = m.group(0)
            counter += 1
            masked = f"***-**-{raw[-4:]}"
            matches.append(
                DLPMatch(
                    match_id=f"M-{counter}",
                    data_type=SensitiveDataType.SSN_PII,
                    severity=DLPSeverity.HIGH,
                    rule_name="US Social Security Number (SSN)",
                    snippet_masked=masked,
                    confidence=95.0,
                    start_pos=m.start(),
                    end_pos=m.end(),
                )
            )

        # 3. AWS Key
        for m in cls.AWS_KEY_REGEX.finditer(text):
            counter += 1
            raw = m.group(0)
            masked = f"AKIA{raw[4:6]}************"
            matches.append(
                DLPMatch(
                    match_id=f"M-{counter}",
                    data_type=SensitiveDataType.CLOUD_SECRET,
                    severity=DLPSeverity.CRITICAL,
                    rule_name="AWS Cloud Access Key",
                    snippet_masked=masked,
                    confidence=99.0,
                    start_pos=m.start(),
                    end_pos=m.end(),
                )
            )

        # 4. GitHub PAT
        for m in cls.GITHUB_PAT_REGEX.finditer(text):
            counter += 1
            masked = "ghp_************************************"
            matches.append(
                DLPMatch(
                    match_id=f"M-{counter}",
                    data_type=SensitiveDataType.CLOUD_SECRET,
                    severity=DLPSeverity.CRITICAL,
                    rule_name="GitHub Personal Access Token",
                    snippet_masked=masked,
                    confidence=99.0,
                    start_pos=m.start(),
                    end_pos=m.end(),
                )
            )

        # 5. Private Keys
        for m in cls.PRIV_KEY_REGEX.finditer(text):
            counter += 1
            matches.append(
                DLPMatch(
                    match_id=f"M-{counter}",
                    data_type=SensitiveDataType.PRIVATE_KEY,
                    severity=DLPSeverity.CRITICAL,
                    rule_name="Cryptographic Private Key Block",
                    snippet_masked="-----BEGIN PRIVATE KEY [REDACTED]-----",
                    confidence=100.0,
                    start_pos=m.start(),
                    end_pos=m.end(),
                )
            )

        # 6. Confidential classification markers
        for m in cls.CONFIDENTIAL_REGEX.finditer(text):
            counter += 1
            matches.append(
                DLPMatch(
                    match_id=f"M-{counter}",
                    data_type=SensitiveDataType.CONFIDENTIAL_MARKER,
                    severity=DLPSeverity.MEDIUM,
                    rule_name="Document Confidentiality Marker",
                    snippet_masked=f"[{m.group(0).upper()}]",
                    confidence=85.0,
                    start_pos=m.start(),
                    end_pos=m.end(),
                )
            )

        return matches

    @classmethod
    def mask_text(cls, text: str) -> str:
        """Replace sensitive patterns with masked placeholders."""
        sanitized = text

        # Replace private keys
        sanitized = cls.PRIV_KEY_REGEX.sub("-----BEGIN PRIVATE KEY [REDACTED]-----", sanitized)

        # Replace AWS keys
        sanitized = cls.AWS_KEY_REGEX.sub(lambda m: f"AKIA{m.group(0)[4:6]}************", sanitized)

        # Replace GitHub tokens
        sanitized = cls.GITHUB_PAT_REGEX.sub("ghp_************************************", sanitized)

        # Replace SSN
        sanitized = cls.SSN_REGEX.sub(lambda m: f"***-**-{m.group(0)[-4:]}", sanitized)

        # Replace validated credit cards
        def cc_replacer(match):
            raw = match.group(0)
            cleaned = re.sub(r"[- ]", "", raw)
            if validate_luhn(cleaned):
                return f"************{cleaned[-4:]}"
            return raw

        sanitized = cls.CC_REGEX.sub(cc_replacer, sanitized)
        return sanitized
