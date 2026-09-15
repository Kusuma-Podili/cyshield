"""CyberShield Enterprise - Autonomous Dark Web & Leaked Credential Sentinel Engine.
Indexes dark web breach dumps, provides NIST SP 800-63B k-anonymity prefix lookups,
monitors corporate domain email exposures, and flags infostealer session cookie theft.
"""

import uuid
import hashlib
from typing import Dict, List, Optional, Set, Any
from datetime import datetime, timezone
from collections import defaultdict

from .schemas import (
    BreachSourceType,
    CredentialExposureSeverity,
    IngestBreachRecordRequest,
    HashPrefixLookupRequest,
    HashSuffixMatch,
    HashPrefixLookupResponse,
    CorporateEmailCheckRequest,
    DarkWebExposureAlert,
    DarkWebSentinelMetrics,
)


class DarkWebCredentialSentinel:
    """Enterprise dark web surveillance and k-anonymity credential exposure sentinel."""

    def __init__(self, monitored_domains: Optional[Set[str]] = None):
        self.monitored_domains: Set[str] = monitored_domains or {
            "corp.enterprise.local",
            "enterprise.local",
            "corp.com",
        }

        # K-Anonymity index: 5-char prefix -> dict of (suffix -> prevalence)
        self.k_anonymity_index: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

        # Email exposure index: email.lower() -> list of IngestBreachRecordRequest
        self.email_exposures: Dict[str, List[IngestBreachRecordRequest]] = defaultdict(list)

        # Alerts store
        self.alerts: List[DarkWebExposureAlert] = []

        # Seed realistic known compromised hash suffixes for initial database
        self._seed_default_breach_corpus()

    def _seed_default_breach_corpus(self):
        """Seed a small realistic k-anonymity corpus."""
        sample_passwords = ["Password123!", "Admin2026$", "Summer2025#", "Welcome123!"]
        for p in sample_passwords:
            h = hashlib.sha256(p.encode("utf-8")).hexdigest().upper()
            prefix = h[:5]
            suffix = h[5:]
            self.k_anonymity_index[prefix][suffix] += 1050

    def ingest_breach_record(self, req: IngestBreachRecordRequest) -> Optional[DarkWebExposureAlert]:
        """Ingest credential breach record and alert if corporate domain is affected."""
        email_clean = req.email.strip().lower()
        self.email_exposures[email_clean].append(req)

        # Index password hash for k-anonymity lookup (uppercase)
        h_clean = req.password_hash.strip().upper()
        if len(h_clean) >= 6:
            prefix = h_clean[:5]
            suffix = h_clean[5:]
            self.k_anonymity_index[prefix][suffix] += 1

        # Check if email domain is within monitored enterprise domains
        domain = email_clean.split("@")[-1] if "@" in email_clean else ""
        alert: Optional[DarkWebExposureAlert] = None

        if domain in self.monitored_domains:
            # Determine severity
            if req.has_active_session_cookie or req.plaintext_password:
                sev = CredentialExposureSeverity.CRITICAL
                action = "IMMEDIATE_SESSION_TERMINATION_AND_FORCE_PASSWORD_RESET"
            elif req.hash_algorithm.upper() in {"MD5", "SHA1", "NTLM"}:
                sev = CredentialExposureSeverity.HIGH
                action = "FORCE_PASSWORD_RESET_WITHIN_2_HOURS"
            else:
                sev = CredentialExposureSeverity.MEDIUM
                action = "FORCE_PASSWORD_RESET_AT_NEXT_LOGIN"

            alert = DarkWebExposureAlert(
                alert_id=f"dw-leak-{uuid.uuid4().hex[:8]}",
                email=email_clean,
                domain=domain,
                severity=sev,
                mitre_technique="T1552 - Unsecured Credentials: Dark Web Credential Dump",
                source_breach_name=req.source_breach_name,
                source_type=req.source_type,
                plaintext_exposed=req.plaintext_password is not None,
                recommended_action=action,
                details=(
                    f"Corporate credential '{email_clean}' detected in dark web breach '{req.source_breach_name}'. "
                    f"Source: {req.source_type.value}. Plaintext: {'YES' if req.plaintext_password else 'NO'}. "
                    f"Active Cookie: {'YES' if req.has_active_session_cookie else 'NO'}."
                ),
            )
            self.alerts.append(alert)

        return alert

    def lookup_hash_prefix(self, req: HashPrefixLookupRequest) -> HashPrefixLookupResponse:
        """Query 5-char hash prefix returning matching suffixes and prevalence (NIST k-anonymity)."""
        prefix = req.hash_prefix.strip().upper()
        suffixes = self.k_anonymity_index.get(prefix, {})

        matches = [
            HashSuffixMatch(hash_suffix=s, prevalence_count=cnt)
            for s, cnt in suffixes.items()
        ]

        return HashPrefixLookupResponse(
            hash_prefix=prefix,
            matching_suffixes_count=len(matches),
            matches=matches,
        )

    def check_corporate_email(self, email: str) -> List[DarkWebExposureAlert]:
        """Check if an email has any recorded dark web exposures."""
        clean = email.strip().lower()
        return [a for a in self.alerts if a.email == clean]

    def get_metrics(self) -> DarkWebSentinelMetrics:
        """Compute dark web surveillance statistics."""
        total_creds = sum(len(v) for v in self.email_exposures.values())
        corp_compromised = len({a.email for a in self.alerts})
        cookies_stolen = sum(
            1 for records in self.email_exposures.values()
            for r in records if r.has_active_session_cookie
        )

        return DarkWebSentinelMetrics(
            total_breached_credentials_cataloged=total_creds,
            corporate_accounts_compromised=corp_compromised,
            active_session_cookies_intercepted=cookies_stolen,
            total_alerts_raised=len(self.alerts),
            surveillance_status="CONTINUOUS_AIRGAPPED_MONITORING",
        )
