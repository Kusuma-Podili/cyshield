"""
CyberShield Enterprise - SaaS Security Posture Management (SSPM) & CASB Schemas
Provides data models for SaaS identity auditing, illicit OAuth grants,
BEC mailbox forwarding rules, MFA fatigue attacks, and CIS SaaS compliance.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class SaaSPlatform(str, Enum):
    M365 = "microsoft_365"
    GOOGLE_WORKSPACE = "google_workspace"
    AWS_IAM = "aws_iam"
    SALESFORCE = "salesforce"
    SLACK = "slack"
    GITHUB_ENTERPRISE = "github_enterprise"


class SSPMSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class OAuthConsentRisk(str, Enum):
    LOW = "LOW"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    MALICIOUS = "MALICIOUS"


class OAuthAppGrant(BaseModel):
    app_id: str = Field(..., description="Unique application ID or Client ID")
    app_name: str = Field(..., description="Display name of application")
    publisher_domain: Optional[str] = Field(None, description="Verified publisher domain")
    is_publisher_verified: bool = Field(False, description="Whether publisher is Microsoft/Google verified")
    consenting_user: str = Field(..., description="User email or principal who granted consent")
    is_admin_consent: bool = Field(False, description="Whether granted tenant-wide via admin consent")
    scopes: List[str] = Field(default_factory=list, description="Granted OAuth scopes")
    grant_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Consent timestamp")


class MailboxForwardingRule(BaseModel):
    rule_id: str = Field(..., description="Unique rule identifier")
    mailbox_owner: str = Field(..., description="Target user mailbox email")
    rule_name: str = Field(..., description="Inbox rule name")
    forward_to_addresses: List[str] = Field(default_factory=list, description="Destination forward email addresses")
    is_external_forward: bool = Field(True, description="Whether forward target is outside enterprise domain")
    action_delete_or_mark_read: bool = Field(False, description="Whether rule deletes or hides incoming mail")
    filter_keywords: List[str] = Field(default_factory=list, description="Trigger keywords (e.g. invoice, wire, otp)")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Rule creation timestamp")


class MFAChallengeEvent(BaseModel):
    event_id: str = Field(..., description="Unique event identifier")
    user_principal: str = Field(..., description="Target user account")
    timestamp: datetime = Field(..., description="Challenge timestamp")
    result: str = Field(..., description="'DENIED', 'APPROVED', 'TIMED_OUT'")
    client_ip: str = Field(..., description="Originating client IP")
    device_location: Optional[str] = Field(None, description="Geographic location string")


class SaaSPostureFinding(BaseModel):
    finding_id: str = Field(..., description="Unique finding ID")
    platform: SaaSPlatform = Field(..., description="SaaS platform affected")
    category: str = Field(..., description="e.g. OAUTH_CONSENT, BEC_FORWARDING, MFA_FATIGUE, PRIVILEGED_GUEST")
    severity: SSPMSeverity = Field(..., description="Severity level")
    target_entity: str = Field(..., description="Target user, app, or configuration entity")
    title: str = Field(..., description="Concise finding headline")
    details: str = Field(..., description="In-depth forensic context and threat narrative")
    cis_benchmark_ref: Optional[str] = Field(None, description="CIS benchmark reference identifier")
    remediation_steps: str = Field(..., description="Prescribed containment and fix")


class SaaSAccountAudit(BaseModel):
    user_principal: str = Field(..., description="User principal name")
    is_guest: bool = Field(False, description="Whether user is an external guest (#EXT#)")
    is_privileged_role: bool = Field(False, description="Whether assigned admin directory roles")
    roles: List[str] = Field(default_factory=list, description="Directory roles assigned")
    mfa_enforced: bool = Field(True, description="Whether MFA is strictly enforced")
    days_inactive: int = Field(0, description="Days since last successful interactive sign-in")
    legacy_auth_enabled: bool = Field(False, description="Whether legacy protocols (POP/IMAP) are permitted")


class SSPMPostureReport(BaseModel):
    report_id: str = Field(..., description="Unique audit report UUID")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Generation timestamp")
    total_accounts_audited: int = Field(0, description="Total SaaS accounts audited")
    total_apps_audited: int = Field(0, description="Total OAuth apps evaluated")
    posture_score: float = Field(..., description="Compliance and posture score (0.0 - 100.0)")
    findings: List[SaaSPostureFinding] = Field(default_factory=list, description="All identified risks")
    critical_findings_count: int = Field(0, description="Number of critical severity findings")
    mfa_coverage_percentage: float = Field(..., description="Percentage of users with MFA enforced")
    legacy_auth_risk_count: int = Field(0, description="Accounts with legacy authentication enabled")
