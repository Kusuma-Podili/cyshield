"""CyberShield Enterprise - Autonomous Active Directory & Kerberos Attack Sentinel Schemas.
Data contracts for Kerberos ticket forgery (Golden/Silver ticket), Kerberoasting,
AS-REP roasting, DCSync replication abuse, and Domain hygiene scoring.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class KerberosTicketType(str, Enum):
    TGT_TICKET_GRANTING_TICKET = "TGT_TICKET_GRANTING_TICKET"
    TGS_SERVICE_TICKET = "TGS_SERVICE_TICKET"


class KerberosEncryptionType(str, Enum):
    AES256_CTS_HMAC_SHA1_96 = "AES256_CTS_HMAC_SHA1_96"
    AES128_CTS_HMAC_SHA1_96 = "AES128_CTS_HMAC_SHA1_96"
    RC4_HMAC_NT = "RC4_HMAC_NT"
    DES_CBC_MD5 = "DES_CBC_MD5"


class ADAttackTechnique(str, Enum):
    GOLDEN_TICKET_FORGERY = "GOLDEN_TICKET_FORGERY"
    SILVER_TICKET_FORGERY = "SILVER_TICKET_FORGERY"
    KERBEROASTING = "KERBEROASTING"
    ASREP_ROASTING = "ASREP_ROASTING"
    DCSYNC_REPLICATION_ABUSE = "DCSYNC_REPLICATION_ABUSE"
    PASSWORD_SPRAYING = "PASSWORD_SPRAYING"


class KerberosTicketInspectionRequest(BaseModel):
    """Kerberos authentication ticket presented to Domain Controller or Service."""
    ticket_id: str
    ticket_type: KerberosTicketType
    client_principal: str = Field(..., description="e.g. jdoe@CORP.LOCAL")
    service_principal: str = Field(..., description="e.g. krbtgt/CORP.LOCAL or MSSQLSvc/db01:1433")
    encryption_type: KerberosEncryptionType
    ticket_lifetime_hours: float = Field(..., ge=0.0)
    pac_groups_rids: List[int] = Field(default_factory=list, description="RIDs in PAC e.g. 512=Domain Admins")
    is_account_privileged: bool = False
    preauth_required: bool = True


class DCSecurityEvent(BaseModel):
    """Windows Domain Controller security audit event."""
    event_id: int = Field(..., description="4624, 4672, 4768, 4769, 4771, 4662")
    source_workstation: str
    source_ip: str
    target_user: str
    service_name: Optional[str] = None
    ticket_encryption_type: Optional[str] = None
    access_mask: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ADThreatAlert(BaseModel):
    """Security alert raised on Active Directory or Kerberos compromise."""
    alert_id: str
    threat_technique: ADAttackTechnique
    mitre_technique: str
    severity: str = "CRITICAL"
    target_principal: str
    source_workstation_or_ip: Optional[str] = None
    details: str
    countermeasure: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ADDomainPostureReport(BaseModel):
    """Enterprise Active Directory hygiene and resilience posture."""
    domain_fqdn: str
    monitored_dcs_count: int
    active_threats_count: int
    krbtgt_last_rotated_days: int
    unconstrained_delegation_accounts_count: int
    preauth_disabled_accounts_count: int
    domain_hygiene_score: float = Field(..., ge=0.0, le=100.0)
    posture_status: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
