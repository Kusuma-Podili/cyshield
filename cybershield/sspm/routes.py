"""
CyberShield Enterprise - SaaS Security Posture Management (SSPM) REST Routes
Provides endpoints for OAuth permission auditing, mailbox BEC detection,
MFA fatigue analysis, and multi-cloud tenant posture reporting.
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List

from cybershield.sspm.schemas import (
    OAuthAppGrant,
    MailboxForwardingRule,
    MFAChallengeEvent,
    SaaSPostureFinding,
    SaaSAccountAudit,
    SSPMPostureReport,
)
from cybershield.sspm.engine import SaaSSecurityPostureEngine

router = APIRouter(prefix="/api/v1/sspm", tags=["SaaS Security Posture Management (SSPM)"])

_sspm_engine = SaaSSecurityPostureEngine()


def get_sspm_engine() -> SaaSSecurityPostureEngine:
    return _sspm_engine


@router.post("/audit/oauth", response_model=List[SaaSPostureFinding])
def audit_oauth_grant(grant: OAuthAppGrant, engine: SaaSSecurityPostureEngine = Depends(get_sspm_engine)):
    """Evaluate OAuth application grant for risky write permissions and unverified publishers."""
    try:
        return engine.audit_oauth_app(grant)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to audit OAuth application: {str(e)}")


@router.post("/audit/mailbox", response_model=List[SaaSPostureFinding])
def audit_mailbox(rule: MailboxForwardingRule, engine: SaaSSecurityPostureEngine = Depends(get_sspm_engine)):
    """Inspect mailbox inbox forwarding and deletion rules for Business Email Compromise (BEC)."""
    try:
        return engine.audit_mailbox_rule(rule)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to audit mailbox rule: {str(e)}")


@router.post("/detect/mfa-fatigue", response_model=List[SaaSPostureFinding])
def detect_mfa_fatigue(events: List[MFAChallengeEvent], engine: SaaSSecurityPostureEngine = Depends(get_sspm_engine)):
    """Correlate sequence of MFA challenge denials and subsequent approvals to detect push bombing."""
    try:
        return engine.detect_mfa_fatigue(events)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to analyze MFA challenge stream: {str(e)}")


@router.post("/audit/accounts", response_model=List[SaaSPostureFinding])
def audit_accounts(accounts: List[SaaSAccountAudit], engine: SaaSSecurityPostureEngine = Depends(get_sspm_engine)):
    """Audit identity posture for privileged external guests, dormant admins, and missing MFA."""
    try:
        return engine.audit_accounts(accounts)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to audit SaaS accounts: {str(e)}")


@router.post("/evaluate/tenant", response_model=SSPMPostureReport)
def evaluate_tenant(
    accounts: List[SaaSAccountAudit],
    apps: List[OAuthAppGrant] = None,
    rules: List[MailboxForwardingRule] = None,
    mfa_events: List[MFAChallengeEvent] = None,
    engine: SaaSSecurityPostureEngine = Depends(get_sspm_engine),
):
    """Generate holistic SaaS Security Posture Report across all audited identity vectors."""
    try:
        return engine.evaluate_tenant_posture(
            accounts=accounts,
            apps=apps or [],
            mailbox_rules=rules or [],
            mfa_events=mfa_events or [],
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to evaluate tenant posture: {str(e)}")


@router.get("/posture/summary")
def get_posture_summary(engine: SaaSSecurityPostureEngine = Depends(get_sspm_engine)) -> Dict[str, Any]:
    """Retrieve summary of SSPM coverage and monitoring capabilities."""
    return {
        "status": "active",
        "enterprise_domain": engine.enterprise_domain,
        "monitored_platforms": ["microsoft_365", "google_workspace", "aws_iam", "salesforce", "slack"],
        "critical_oauth_scopes_tracked": len(engine.CRITICAL_OAUTH_SCOPES),
        "cis_benchmarks_supported": ["CIS Microsoft 365 v2.0", "CIS Google Workspace v1.1"],
    }


@router.get("/health")
def health():
    return {"status": "healthy", "service": "sspm-engine", "version": "1.0.0"}
