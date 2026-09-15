"""
Identity Threat Detection and Response (ITDR) Schemas and Models.
Defines Active Directory entities, Kerberos ticket telemetry, replication requests, and identity attack alerts.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IdentityAttackType(str, Enum):
    KERBEROASTING = "KERBEROASTING"
    ASREP_ROASTING = "ASREP_ROASTING"
    DCSYNC = "DCSYNC"
    GOLDEN_TICKET = "GOLDEN_TICKET"
    SILVER_TICKET = "SILVER_TICKET"
    SHADOW_ADMIN = "SHADOW_ADMIN"
    PRIVILEGED_GROUP_TAMPERING = "PRIVILEGED_GROUP_TAMPERING"
    PASS_THE_HASH = "PASS_THE_HASH"


class IdentityRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class KerberosEncryptionType(str, Enum):
    AES256_CTS_HMAC_SHA1_96 = "AES256"
    AES128_CTS_HMAC_SHA1_96 = "AES128"
    RC4_HMAC = "RC4"                # Etype 23 (Weak, targeted by Kerberoasting)
    DES_CBC_MD5 = "DES"             # Deprecated / Critical


class ADAccount(BaseModel):
    """Active Directory user or service account."""
    object_sid: str
    sam_account_name: str
    display_name: str
    distinguished_name: str
    is_service_account: bool = False
    service_principal_names: List[str] = Field(default_factory=list)
    preauth_required: bool = True
    admin_count: int = 0
    password_last_set: datetime = Field(default_factory=datetime.utcnow)
    password_never_expires: bool = False
    unconstrained_delegation: bool = False
    groups: List[str] = Field(default_factory=list)


class KerberosTicketTelemetry(BaseModel):
    """Telemetry captured from Kerberos AS-REQ / TGS-REQ packets."""
    ticket_id: str
    request_type: str  # AS_REQ, TGS_REQ
    client_name: str
    client_realm: str = "CORP.LOCAL"
    service_name: str  # krbtgt/CORP.LOCAL or MSSQLSvc/db01.corp.local
    encryption_type: KerberosEncryptionType
    ticket_lifetime_hours: float = 10.0
    client_ip: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class DirectoryReplicationTelemetry(BaseModel):
    """Directory Replication Service (DRS) replication telemetry."""
    request_id: str
    client_ip: str
    requesting_account: str
    naming_context: str = "DC=corp,DC=local"
    extended_rights_requested: List[str] = Field(default_factory=list)
    is_registered_domain_controller: bool = False
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ITDRAlert(BaseModel):
    """Alert raised for identity infrastructure attacks."""
    alert_id: str
    attack_type: IdentityAttackType
    severity: IdentityRiskLevel
    title: str
    description: str
    affected_account: str
    source_ip: str
    mitre_technique_id: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    remediation_steps: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class IdentityPostureOverview(BaseModel):
    """Overall posture score and vulnerability count of Active Directory."""
    domain_name: str
    total_accounts: int
    spn_accounts_at_risk: int
    no_preauth_accounts_count: int
    unconstrained_delegation_count: int
    shadow_admins_count: int
    identity_risk_score: float  # 0 to 100
    active_identity_alerts_count: int
