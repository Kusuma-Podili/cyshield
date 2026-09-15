"""
CyberShield Enterprise - SaaS Security Posture Management (SSPM) & CASB Engine
Audits multi-cloud SaaS configurations, detects illicit OAuth grants, BEC inbox forwarding,
MFA fatigue push bombing, and CIS SaaS compliance.
"""

import uuid
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta

from cybershield.sspm.schemas import (
    SaaSPlatform,
    SSPMSeverity,
    OAuthConsentRisk,
    OAuthAppGrant,
    MailboxForwardingRule,
    MFAChallengeEvent,
    SaaSPostureFinding,
    SaaSAccountAudit,
    SSPMPostureReport,
)


class SaaSSecurityPostureEngine:
    """
    Autonomous SaaS Security Posture Management (SSPM) & CASB Sentinel.
    Evaluates enterprise cloud identities, permissions, and mail flows without external dependencies.
    """

    CRITICAL_OAUTH_SCOPES = {
        "mail.readwrite.all", "files.readwrite.all", "directory.readwrite.all",
        "rolemanagement.readwrite.directory", "user.export.all", "sites.fullcontrol.all",
        "https://mail.google.com/", "https://www.googleapis.com/auth/admin.directory.user",
        "https://www.googleapis.com/auth/drive", "admin"
    }

    SENSITIVE_BEC_KEYWORDS = {
        "invoice", "wire", "transfer", "bank", "payment", "statement",
        "account", "confidential", "payroll", "salary", "otp", "2fa"
    }

    def __init__(self, enterprise_domain: str = "enterprise.corp"):
        self.enterprise_domain = enterprise_domain.lower()

    # --------------------------------------------------------------------------
    # 1. OAuth App Consent & Permissions Auditing
    # --------------------------------------------------------------------------

    def audit_oauth_app(self, grant: OAuthAppGrant) -> List[SaaSPostureFinding]:
        """Audits a granted OAuth application for excessive permissions and risk."""
        findings: List[SaaSPostureFinding] = []
        app_scopes = [s.lower() for s in grant.scopes]

        critical_matches = [s for s in app_scopes if s in self.CRITICAL_OAUTH_SCOPES]

        if critical_matches and not grant.is_publisher_verified:
            # High risk: Unverified publisher possessing tenant-wide or wide write scopes
            findings.append(
                SaaSPostureFinding(
                    finding_id=str(uuid.uuid4()),
                    platform=SaaSPlatform.M365,
                    category="OAUTH_CONSENT_ABUSE",
                    severity=SSPMSeverity.CRITICAL,
                    target_entity=grant.app_name,
                    title=f"Illicit OAuth Grant: Unverified App '{grant.app_name}' Has Sensitive Write Scopes",
                    details=(
                        f"Application {grant.app_id} granted scopes {critical_matches} by {grant.consenting_user}. "
                        f"Publisher domain '{grant.publisher_domain}' is not verified."
                    ),
                    cis_benchmark_ref="CIS-M365-v2.0-5.1.4",
                    remediation_steps=f"Revoke OAuth consent for app ID {grant.app_id} immediately via Entra ID Enterprise Applications.",
                )
            )
        elif critical_matches and grant.is_admin_consent:
            findings.append(
                SaaSPostureFinding(
                    finding_id=str(uuid.uuid4()),
                    platform=SaaSPlatform.M365,
                    category="OAUTH_ADMIN_CONSENT",
                    severity=SSPMSeverity.HIGH,
                    target_entity=grant.app_name,
                    title=f"Tenant-Wide Admin Consent Granted to '{grant.app_name}'",
                    details=f"App granted broad tenant-wide permissions {critical_matches}.",
                    cis_benchmark_ref="CIS-M365-v2.0-5.1.3",
                    remediation_steps="Review necessity of tenant-wide administrative consent and restrict to specific groups.",
                )
            )
        elif len(grant.scopes) > 15:
            findings.append(
                SaaSPostureFinding(
                    finding_id=str(uuid.uuid4()),
                    platform=SaaSPlatform.M365,
                    category="OAUTH_EXCESSIVE_SCOPES",
                    severity=SSPMSeverity.MEDIUM,
                    target_entity=grant.app_name,
                    title=f"Application '{grant.app_name}' Possesses Excessive OAuth Scopes ({len(grant.scopes)})",
                    details="High number of requested scopes suggests over-permissioning.",
                    cis_benchmark_ref="CIS-M365-v2.0-5.1.1",
                    remediation_steps="Perform access review and reduce granted permissions to minimum viable scope.",
                )
            )

        return findings

    # --------------------------------------------------------------------------
    # 2. Mailbox Forwarding & BEC Exfiltration Sentinel
    # --------------------------------------------------------------------------

    def audit_mailbox_rule(self, rule: MailboxForwardingRule) -> List[SaaSPostureFinding]:
        """Audits Exchange/Gmail mailbox rules for covert forwarding and email deletion."""
        findings: List[SaaSPostureFinding] = []

        is_external = False
        external_dests = []
        for addr in rule.forward_to_addresses:
            domain = addr.split("@")[-1].lower() if "@" in addr else ""
            if domain and domain != self.enterprise_domain:
                is_external = True
                external_dests.append(addr)

        if not is_external and not rule.is_external_forward:
            return findings

        # Check for financial/credential keywords in rule
        rule_keywords = [k.lower() for k in rule.filter_keywords]
        sensitive_matches = [k for k in rule_keywords if k in self.SENSITIVE_BEC_KEYWORDS]

        if is_external and rule.action_delete_or_mark_read:
            # Classic BEC: Forward to adversary + silently delete incoming mail
            findings.append(
                SaaSPostureFinding(
                    finding_id=str(uuid.uuid4()),
                    platform=SaaSPlatform.M365,
                    category="BEC_MAILBOX_FORWARDING",
                    severity=SSPMSeverity.CRITICAL,
                    target_entity=rule.mailbox_owner,
                    title=f"Severe BEC Indicator: Mailbox Rule Forwards to External Address and Deletes Incoming Mail",
                    details=(
                        f"Mailbox '{rule.mailbox_owner}' created rule '{rule.rule_name}' forwarding to {external_dests} "
                        f"with delete/mark-as-read action enabled. Target keywords: {sensitive_matches}."
                    ),
                    cis_benchmark_ref="CIS-M365-v2.0-2.1.1",
                    remediation_steps=(
                        f"Disable forwarding rule '{rule.rule_name}' on mailbox '{rule.mailbox_owner}', "
                        "force password reset, revoke active refresh tokens, and initiate compromise assessment."
                    ),
                )
            )
        elif is_external and sensitive_matches:
            findings.append(
                SaaSPostureFinding(
                    finding_id=str(uuid.uuid4()),
                    platform=SaaSPlatform.M365,
                    category="BEC_MAILBOX_FORWARDING",
                    severity=SSPMSeverity.HIGH,
                    target_entity=rule.mailbox_owner,
                    title=f"External Forwarding Rule Filtered on Sensitive Keywords ({sensitive_matches})",
                    details=f"Forwarding to {external_dests} triggered by financial or authentication keywords.",
                    cis_benchmark_ref="CIS-M365-v2.0-2.1.2",
                    remediation_steps="Disable automatic external email forwarding policy at tenant transport layer.",
                )
            )
        elif is_external:
            findings.append(
                SaaSPostureFinding(
                    finding_id=str(uuid.uuid4()),
                    platform=SaaSPlatform.M365,
                    category="EXTERNAL_EMAIL_FORWARDING",
                    severity=SSPMSeverity.MEDIUM,
                    target_entity=rule.mailbox_owner,
                    title=f"External Forwarding Rule Created for User '{rule.mailbox_owner}'",
                    details=f"Emails forwarded to external recipients: {external_dests}.",
                    cis_benchmark_ref="CIS-M365-v2.0-2.1.3",
                    remediation_steps="Enforce remote domain transport policy prohibiting auto-forwarding.",
                )
            )

        return findings

    # --------------------------------------------------------------------------
    # 3. MFA Fatigue / Push Bombing Attack Correlation
    # --------------------------------------------------------------------------

    def detect_mfa_fatigue(
        self, events: List[MFAChallengeEvent], window_minutes: int = 15
    ) -> List[SaaSPostureFinding]:
        """
        Detects MFA push notification spamming where multiple denials/timeouts
        are abruptly followed by an approval within a short window.
        """
        findings: List[SaaSPostureFinding] = []
        events_by_user: Dict[str, List[MFAChallengeEvent]] = {}

        for e in events:
            events_by_user.setdefault(e.user_principal, []).append(e)

        for user, user_events in events_by_user.items():
            # Sort chronologically
            sorted_events = sorted(user_events, key=lambda x: x.timestamp)
            denial_count = 0
            first_denial_time = None

            for ev in sorted_events:
                if ev.result.upper() in ["DENIED", "TIMED_OUT"]:
                    if denial_count == 0:
                        first_denial_time = ev.timestamp
                    denial_count += 1
                elif ev.result.upper() == "APPROVED":
                    if denial_count >= 3 and first_denial_time:
                        time_delta = (ev.timestamp - first_denial_time).total_seconds() / 60.0
                        if time_delta <= window_minutes:
                            findings.append(
                                SaaSPostureFinding(
                                    finding_id=str(uuid.uuid4()),
                                    platform=SaaSPlatform.M365,
                                    category="MFA_FATIGUE_ATTACK",
                                    severity=SSPMSeverity.CRITICAL,
                                    target_entity=user,
                                    title=f"MFA Fatigue (Push Bombing) Account Takeover Detected for '{user}'",
                                    details=(
                                        f"User '{user}' rejected/timed-out {denial_count} consecutive MFA prompts "
                                        f"before approving challenge from IP {ev.client_ip} ({ev.device_location}) "
                                        f"within {round(time_delta, 1)} minutes."
                                    ),
                                    cis_benchmark_ref="CIS-M365-v2.0-1.1.2",
                                    remediation_steps=(
                                        f"Immediately invalidate active sessions for '{user}', require number matching "
                                        "for push approvals, and contact user to verify identity."
                                    ),
                                )
                            )
                    # Reset counter after approval
                    denial_count = 0
                    first_denial_time = None

        return findings

    # --------------------------------------------------------------------------
    # 4. Privileged Guest & Dormant Identity Auditing
    # --------------------------------------------------------------------------

    def audit_accounts(self, accounts: List[SaaSAccountAudit]) -> List[SaaSPostureFinding]:
        """Audits directory accounts for persistence, over-privileged guests, and dormant admins."""
        findings: List[SaaSPostureFinding] = []

        for acc in accounts:
            # 1. External guest with admin role
            if acc.is_guest and acc.is_privileged_role:
                findings.append(
                    SaaSPostureFinding(
                        finding_id=str(uuid.uuid4()),
                        platform=SaaSPlatform.M365,
                        category="PRIVILEGED_EXTERNAL_GUEST",
                        severity=SSPMSeverity.CRITICAL,
                        target_entity=acc.user_principal,
                        title=f"External Guest User Has Administrative Directory Roles",
                        details=f"Guest account '{acc.user_principal}' possesses privileged roles: {acc.roles}.",
                        cis_benchmark_ref="CIS-M365-v2.0-1.1.7",
                        remediation_steps="Revoke administrative roles from external guest accounts. Use Just-In-Time PIM.",
                    )
                )

            # 2. Dormant privileged account
            if acc.is_privileged_role and acc.days_inactive > 90:
                findings.append(
                    SaaSPostureFinding(
                        finding_id=str(uuid.uuid4()),
                        platform=SaaSPlatform.M365,
                        category="DORMANT_ADMIN_ACCOUNT",
                        severity=SSPMSeverity.HIGH,
                        target_entity=acc.user_principal,
                        title=f"Dormant Administrative Account ({acc.days_inactive} Days Inactive)",
                        details=f"Privileged account '{acc.user_principal}' has not authenticated in {acc.days_inactive} days.",
                        cis_benchmark_ref="CIS-M365-v2.0-1.1.9",
                        remediation_steps="Disable or remove dormant administrator accounts to reduce attack surface.",
                    )
                )

            # 3. Missing MFA on admin or standard account
            if not acc.mfa_enforced:
                sev = SSPMSeverity.CRITICAL if acc.is_privileged_role else SSPMSeverity.HIGH
                findings.append(
                    SaaSPostureFinding(
                        finding_id=str(uuid.uuid4()),
                        platform=SaaSPlatform.M365,
                        category="MFA_NOT_ENFORCED",
                        severity=sev,
                        target_entity=acc.user_principal,
                        title=f"MFA Not Enforced for {'Privileged' if acc.is_privileged_role else 'Standard'} User '{acc.user_principal}'",
                        details="Account is vulnerable to single-factor password spray and credential stuffing.",
                        cis_benchmark_ref="CIS-M365-v2.0-1.1.1",
                        remediation_steps="Enforce Conditional Access policy requiring Phishing-Resistant MFA.",
                    )
                )

            # 4. Legacy authentication enabled
            if acc.legacy_auth_enabled:
                findings.append(
                    SaaSPostureFinding(
                        finding_id=str(uuid.uuid4()),
                        platform=SaaSPlatform.M365,
                        category="LEGACY_AUTH_PERMITTED",
                        severity=SSPMSeverity.MEDIUM,
                        target_entity=acc.user_principal,
                        title=f"Legacy Authentication Enabled for User '{acc.user_principal}'",
                        details="Legacy protocols (IMAP/POP/SMTP AUTH) bypass modern Conditional Access and MFA.",
                        cis_benchmark_ref="CIS-M365-v2.0-1.1.3",
                        remediation_steps="Block legacy authentication across tenant via Conditional Access Policy.",
                    )
                )

        return findings

    # --------------------------------------------------------------------------
    # 5. Holistic SaaS Posture Score Evaluation
    # --------------------------------------------------------------------------

    def evaluate_tenant_posture(
        self,
        accounts: List[SaaSAccountAudit],
        apps: Optional[List[OAuthAppGrant]] = None,
        mailbox_rules: Optional[List[MailboxForwardingRule]] = None,
        mfa_events: Optional[List[MFAChallengeEvent]] = None,
    ) -> SSPMPostureReport:
        """Aggregates all SaaS posture signals into an enterprise compliance report."""
        report_id = str(uuid.uuid4())
        all_findings: List[SaaSPostureFinding] = []

        # Audit accounts
        all_findings.extend(self.audit_accounts(accounts))

        # Audit OAuth apps
        for app in apps or []:
            all_findings.extend(self.audit_oauth_app(app))

        # Audit mailbox rules
        for rule in mailbox_rules or []:
            all_findings.extend(self.audit_mailbox_rule(rule))

        # Audit MFA events
        if mfa_events:
            all_findings.extend(self.detect_mfa_fatigue(mfa_events))

        # Calculate metrics
        total_accounts = len(accounts)
        mfa_enforced_count = sum(1 for a in accounts if a.mfa_enforced)
        mfa_coverage = round((mfa_enforced_count / total_accounts * 100.0), 1) if total_accounts > 0 else 100.0
        legacy_auth_count = sum(1 for a in accounts if a.legacy_auth_enabled)

        score = 100.0
        crit_count = 0
        for f in all_findings:
            if f.severity == SSPMSeverity.CRITICAL:
                score -= 20.0
                crit_count += 1
            elif f.severity == SSPMSeverity.HIGH:
                score -= 10.0
            elif f.severity == SSPMSeverity.MEDIUM:
                score -= 4.0
            else:
                score -= 1.0

        final_score = max(0.0, min(100.0, round(score, 1)))

        return SSPMPostureReport(
            report_id=report_id,
            timestamp=datetime.utcnow(),
            total_accounts_audited=total_accounts,
            total_apps_audited=len(apps or []),
            posture_score=final_score,
            findings=all_findings,
            critical_findings_count=crit_count,
            mfa_coverage_percentage=mfa_coverage,
            legacy_auth_risk_count=legacy_auth_count,
        )
