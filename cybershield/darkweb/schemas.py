"""CyberShield Enterprise - Autonomous Dark Web & Leaked Credential Sentinel Schemas.
Data contracts for breach dump ingestion, k-anonymity hash prefix lookups,
corporate email exposure checks, and stealer log parsing.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class BreachSourceType(str, Enum):
    INFOSTEALER_LOG = "INFOSTEALER_LOG"  # RedLine, Lumma, Vidar, Racoon
    DATABASE_DUMP = "DATABASE_DUMP"
    PASTE_SITE = "PASTE_SITE"
    UNDERGROUND_FORUM = "UNDERGROUND_FORUM"
    TELEGRAM_BREACH_CHANNEL = "TELEGRAM_BREACH_CHANNEL"


class CredentialExposureSeverity(str, Enum):
    CRITICAL = "CRITICAL"  # Plaintext password or active session cookie
    HIGH = "HIGH"          # Reversible/weak hash (MD5, SHA1)
    MEDIUM = "MEDIUM"      # Salted hash (Bcrypt, Argon2)
    LOW = "LOW"           # Email only


class IngestBreachRecordRequest(BaseModel):
    """Single credential exposure record ingested from underground feeds."""
    email: str = Field(..., description="Compromised user email e.g. alice@corp.enterprise.local")
    password_hash: str = Field(..., description="SHA-1, SHA-256, NTLM, or bcrypt hash of password")
    hash_algorithm: str = "SHA256"
    plaintext_password: Optional[str] = None
    source_breach_name: str = "LummaStealer-Global-Dump-2026"
    source_type: BreachSourceType = BreachSourceType.INFOSTEALER_LOG
    has_active_session_cookie: bool = False


class HashPrefixLookupRequest(BaseModel):
    """NIST SP 800-63B k-anonymity 5-character hash prefix query."""
    hash_prefix: str = Field(..., min_length=5, max_length=5, description="First 5 hex characters of uppercase SHA-1 or SHA-256")


class HashSuffixMatch(BaseModel):
    """Matching suffix and exposure frequency returned under k-anonymity."""
    hash_suffix: str
    prevalence_count: int


class HashPrefixLookupResponse(BaseModel):
    """k-Anonymity search results."""
    hash_prefix: str
    matching_suffixes_count: int
    matches: List[HashSuffixMatch]


class CorporateEmailCheckRequest(BaseModel):
    """Request to check corporate email against dark web breaches."""
    email: str


class DarkWebExposureAlert(BaseModel):
    """Security alert raised when an enterprise credential is found on the dark web."""
    alert_id: str
    email: str
    domain: str
    severity: CredentialExposureSeverity
    mitre_technique: str
    source_breach_name: str
    source_type: BreachSourceType
    plaintext_exposed: bool
    recommended_action: str
    details: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DarkWebSentinelMetrics(BaseModel):
    """Overall dark web surveillance metrics."""
    total_breached_credentials_cataloged: int
    corporate_accounts_compromised: int
    active_session_cookies_intercepted: int
    total_alerts_raised: int
    surveillance_status: str = "CONTINUOUS_AIRGAPPED_MONITORING"
