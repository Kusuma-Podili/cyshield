"""
Identity Threat Detection and Response (ITDR) Engine.
Monitors Active Directory and Kerberos infrastructure for Kerberoasting, DCSync,
Golden/Silver tickets, AS-REP roasting, and privilege escalation.
"""

import uuid
from datetime import datetime
from typing import Dict, List, Optional

from cybershield.itdr.schemas import (
    ADAccount,
    DirectoryReplicationTelemetry,
    IdentityAttackType,
    IdentityPostureOverview,
    IdentityRiskLevel,
    ITDRAlert,
    KerberosEncryptionType,
    KerberosTicketTelemetry,
)

KNOWN_DCSYNC_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda5f3c": "DS-Replication-Get-Changes-In-Filtered-Set",
}


class IdentityThreatDetector:
    """Detection engine for identity infrastructure attacks and Active Directory posture."""

    def __init__(self):
        self._accounts: Dict[str, ADAccount] = {}
        self._alerts: List[ITDRAlert] = []
        self._registered_dcs: List[str] = ["10.0.0.1", "10.0.0.2", "DC01$", "DC02$"]
        self._seed_sample_ad_accounts()

    def _seed_sample_ad_accounts(self):
        """Seed representative corporate AD accounts with posture flaws."""
        # 1. High risk service account with SPN
        svc_sql = ADAccount(
            object_sid="S-1-5-21-12345678-1001",
            sam_account_name="svc_mssql_prod",
            display_name="Production MSSQL Service",
            distinguished_name="CN=svc_mssql_prod,OU=Services,DC=corp,DC=local",
            is_service_account=True,
            service_principal_names=["MSSQLSvc/db01.corp.local:1433"],
            preauth_required=True,
            admin_count=0,
            password_never_expires=True,
        )
        self._accounts[svc_sql.sam_account_name] = svc_sql

        # 2. Account vulnerable to AS-REP Roasting (Preauth disabled)
        vuln_preauth = ADAccount(
            object_sid="S-1-5-21-12345678-1002",
            sam_account_name="legacy_backup_user",
            display_name="Legacy Backup System User",
            distinguished_name="CN=legacy_backup_user,OU=Legacy,DC=corp,DC=local",
            is_service_account=True,
            preauth_required=False,  # Vulnerable to AS-REP roasting!
            admin_count=0,
        )
        self._accounts[vuln_preauth.sam_account_name] = vuln_preauth

        # 3. Domain Admin
        da_account = ADAccount(
            object_sid="S-1-5-21-12345678-500",
            sam_account_name="Administrator",
            display_name="Builtin Administrator",
            distinguished_name="CN=Administrator,CN=Users,DC=corp,DC=local",
            admin_count=1,
            groups=["Domain Admins", "Enterprise Admins", "Schema Admins"],
        )
        self._accounts[da_account.sam_account_name] = da_account

    def list_accounts(self) -> List[ADAccount]:
        return list(self._accounts.values())

    def get_account(self, sam_account_name: str) -> Optional[ADAccount]:
        return self._accounts.get(sam_account_name)

    def analyze_kerberos_ticket(self, ticket: KerberosTicketTelemetry) -> Optional[ITDRAlert]:
        """Analyze a Kerberos ticket request for Kerberoasting or Golden/Silver tickets."""
        # 1. Detect Golden / Silver Ticket (Anomalously long lifetime)
        if ticket.ticket_lifetime_hours > 10.5:
            alert = ITDRAlert(
                alert_id=f"ITDR-{uuid.uuid4().hex[:8].upper()}",
                attack_type=IdentityAttackType.GOLDEN_TICKET if "krbtgt" in ticket.service_name.lower() else IdentityAttackType.SILVER_TICKET,
                severity=IdentityRiskLevel.CRITICAL,
                title=f"Forged Kerberos Ticket Detected ({ticket.ticket_lifetime_hours:.1f}h Lifetime)",
                description=f"Ticket presented for service '{ticket.service_name}' has an abnormal lifetime of {ticket.ticket_lifetime_hours} hours, exceeding maximum Kerberos policy.",
                affected_account=ticket.client_name,
                source_ip=ticket.client_ip,
                mitre_technique_id="T1558.001" if "krbtgt" in ticket.service_name.lower() else "T1558.002",
                evidence={
                    "service_name": ticket.service_name,
                    "ticket_lifetime_hours": ticket.ticket_lifetime_hours,
                    "encryption_type": ticket.encryption_type.value,
                },
                remediation_steps=[
                    "Reset the KRBTGT account password twice to invalidate forged Kerberos tickets",
                    "Isolate client endpoint at source IP",
                    "Mandate smart card / MFA authentication for sensitive service accounts",
                ],
            )
            self._alerts.append(alert)
            return alert

        # 2. Detect Kerberoasting (RC4-HMAC TGS request for non-krbtgt SPN service)
        if (
            ticket.request_type == "TGS_REQ"
            and ticket.encryption_type in [KerberosEncryptionType.RC4_HMAC, KerberosEncryptionType.DES_CBC_MD5]
            and "krbtgt" not in ticket.service_name.lower()
        ):
            alert = ITDRAlert(
                alert_id=f"ITDR-{uuid.uuid4().hex[:8].upper()}",
                attack_type=IdentityAttackType.KERBEROASTING,
                severity=IdentityRiskLevel.HIGH,
                title=f"Kerberoasting Attack Detected Targeting '{ticket.service_name}'",
                description=f"Client requested an RC4-encrypted TGS ticket for ServicePrincipalName '{ticket.service_name}'. Attackers use weak RC4 encryption to crack service account hashes offline.",
                affected_account=ticket.client_name,
                source_ip=ticket.client_ip,
                mitre_technique_id="T1558.003",
                evidence={
                    "service_name": ticket.service_name,
                    "encryption_type": ticket.encryption_type.value,
                    "request_type": ticket.request_type,
                },
                remediation_steps=[
                    f"Change password for account associated with {ticket.service_name} to a 25+ character random passphrase",
                    "Enforce AES256 encryption exclusively for all Kerberos SPN service tickets",
                    "Investigate source endpoint for credential dumping tools (Rubeus, Mimikatz)",
                ],
            )
            self._alerts.append(alert)
            return alert

        # 3. Detect AS-REP Roasting (AS-REQ for account with pre-auth disabled)
        if ticket.request_type == "AS_REQ":
            acct = self._accounts.get(ticket.client_name)
            if acct and not acct.preauth_required:
                alert = ITDRAlert(
                    alert_id=f"ITDR-{uuid.uuid4().hex[:8].upper()}",
                    attack_type=IdentityAttackType.ASREP_ROASTING,
                    severity=IdentityRiskLevel.HIGH,
                    title=f"AS-REP Roasting Exploitation Against '{ticket.client_name}'",
                    description=f"Kerberos AS-REQ authentication request issued for account '{ticket.client_name}' which has Kerberos Pre-Authentication disabled.",
                    affected_account=ticket.client_name,
                    source_ip=ticket.client_ip,
                    mitre_technique_id="T1558.004",
                    evidence={
                        "account_name": ticket.client_name,
                        "preauth_required": False,
                    },
                    remediation_steps=[
                        f"Re-enable Kerberos Pre-Authentication on user account '{ticket.client_name}'",
                        "Reset user password to prevent offline hash cracking",
                    ],
                )
                self._alerts.append(alert)
                return alert

        return None

    def analyze_directory_replication(self, rep: DirectoryReplicationTelemetry) -> Optional[ITDRAlert]:
        """Detect DCSync directory replication abuse by unauthorized clients."""
        is_unauthorized = (
            not rep.is_registered_domain_controller
            and rep.client_ip not in self._registered_dcs
            and not rep.requesting_account.endswith("$")
        )

        has_dcsync_rights = any(
            g.lower() in [r.lower() for r in rep.extended_rights_requested]
            or any(name.lower() in [r.lower() for r in rep.extended_rights_requested] for name in KNOWN_DCSYNC_GUIDS.values())
            for g in KNOWN_DCSYNC_GUIDS.keys()
        )

        if is_unauthorized and has_dcsync_rights:
            alert = ITDRAlert(
                alert_id=f"ITDR-{uuid.uuid4().hex[:8].upper()}",
                attack_type=IdentityAttackType.DCSYNC,
                severity=IdentityRiskLevel.CRITICAL,
                title=f"DCSync Attack Detected from Account '{rep.requesting_account}'",
                description=f"Non-domain controller '{rep.client_ip}' ({rep.requesting_account}) requested directory replication rights to pull password hashes via DRS protocol.",
                affected_account=rep.requesting_account,
                source_ip=rep.client_ip,
                mitre_technique_id="T1003.006",
                evidence={
                    "requesting_account": rep.requesting_account,
                    "rights_requested": rep.extended_rights_requested,
                    "target_nc": rep.naming_context,
                },
                remediation_steps=[
                    f"Immediately disable or lock down account '{rep.requesting_account}'",
                    "Isolate source workstation at IP " + rep.client_ip,
                    "Audit domain-level permissions for unauthorized 'Replicating Directory Changes' ACEs",
                ],
            )
            self._alerts.append(alert)
            return alert

        return None

    def analyze_privileged_group_change(self, actor: str, target_user: str, group_name: str) -> Optional[ITDRAlert]:
        """Detect unauthorized promotion to Tier-0 privileged groups."""
        privileged_groups = ["domain admins", "enterprise admins", "schema admins", "administrators"]
        if group_name.lower() in privileged_groups:
            alert = ITDRAlert(
                alert_id=f"ITDR-{uuid.uuid4().hex[:8].upper()}",
                attack_type=IdentityAttackType.PRIVILEGED_GROUP_TAMPERING,
                severity=IdentityRiskLevel.CRITICAL,
                title=f"Privileged Group Escalation: '{target_user}' Added to '{group_name}'",
                description=f"Actor '{actor}' added user '{target_user}' to Tier-0 privileged security group '{group_name}'.",
                affected_account=target_user,
                source_ip="Active Directory DC",
                mitre_technique_id="T1098",
                evidence={"actor": actor, "target_user": target_user, "group": group_name},
                remediation_steps=[
                    f"Verify change ticket authorization for {target_user} addition to {group_name}",
                    "If unauthorized, immediately remove account from group and audit actor session",
                ],
            )
            self._alerts.append(alert)
            return alert
        return None

    def get_alerts(self, limit: int = 50) -> List[ITDRAlert]:
        return list(reversed(self._alerts))[:limit]

    def get_posture_overview(self) -> IdentityPostureOverview:
        """Evaluate Active Directory hygiene and identity risk score."""
        total = len(self._accounts)
        spn_count = sum(1 for a in self._accounts.values() if len(a.service_principal_names) > 0)
        no_preauth = sum(1 for a in self._accounts.values() if not a.preauth_required)
        unconstrained = sum(1 for a in self._accounts.values() if a.unconstrained_delegation)
        active_alerts = len(self._alerts)

        # Posture penalty calculation
        risk_score = 10.0
        risk_score += min(30.0, spn_count * 15.0)
        risk_score += min(30.0, no_preauth * 20.0)
        risk_score += min(20.0, active_alerts * 10.0)

        return IdentityPostureOverview(
            domain_name="corp.local",
            total_accounts=total,
            spn_accounts_at_risk=spn_count,
            no_preauth_accounts_count=no_preauth,
            unconstrained_delegation_count=unconstrained,
            shadow_admins_count=1,
            identity_risk_score=min(100.0, round(risk_score, 1)),
            active_identity_alerts_count=active_alerts,
        )
