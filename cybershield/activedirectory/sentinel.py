"""CyberShield Enterprise - Autonomous Active Directory & Kerberos Attack Sentinel Engine.
Detects Kerberos Golden Tickets, Silver Tickets, Kerberoasting, AS-REP Roasting,
and DCSync privilege abuse, while computing Domain Hygiene Posture.
"""

import uuid
from typing import Dict, List, Optional, Set, Any
from datetime import datetime, timezone
from collections import defaultdict

from .schemas import (
    KerberosTicketType,
    KerberosEncryptionType,
    ADAttackTechnique,
    KerberosTicketInspectionRequest,
    DCSecurityEvent,
    ADThreatAlert,
    ADDomainPostureReport,
)


class ActiveDirectorySentinel:
    """Enterprise domain controller monitor and Kerberos forgery detector."""

    # Well-known privileged RIDs in Active Directory PAC
    PRIVILEGED_RIDS: Set[int] = {
        512,  # Domain Admins
        516,  # Domain Controllers
        518,  # Schema Admins
        519,  # Enterprise Admins
        520,  # Group Policy Creator Owners
    }

    # Authorized Domain Controller machine accounts
    AUTHORIZED_DC_HOSTS: Set[str] = {"DC01$", "DC02$", "CORP-DC-PRIMARY$", "10.0.0.2", "10.0.0.3"}

    def __init__(self, domain_fqdn: str = "CORP.ENTERPRISE.LOCAL"):
        self.domain_fqdn: str = domain_fqdn
        self.alerts: List[ADThreatAlert] = []
        # Tracking TGS requests per source workstation: source -> list of SPN names
        self.tgs_requests_tracker: Dict[str, List[str]] = defaultdict(list)

    def inspect_kerberos_ticket(self, req: KerberosTicketInspectionRequest) -> Optional[ADThreatAlert]:
        """Audit Kerberos TGT / TGS ticket for forgery, lifetime anomalies, and PAC tampering."""
        alert: Optional[ADThreatAlert] = None

        # 1. Golden Ticket Forgery Detection
        # Characteristics: TGT ticket with excessive lifetime (>10h) or non-privileged user claiming Domain Admins RID (512)
        has_privileged_rid = any(rid in self.PRIVILEGED_RIDS for rid in req.pac_groups_rids)

        if req.ticket_type == KerberosTicketType.TGT_TICKET_GRANTING_TICKET:
            is_anomalous_lifetime = req.ticket_lifetime_hours > 10.5
            is_pac_tampered = has_privileged_rid and not req.is_account_privileged

            if is_anomalous_lifetime or is_pac_tampered:
                alert = ADThreatAlert(
                    alert_id=f"ad-golden-{uuid.uuid4().hex[:8]}",
                    threat_technique=ADAttackTechnique.GOLDEN_TICKET_FORGERY,
                    mitre_technique="T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket",
                    severity="CRITICAL",
                    target_principal=req.client_principal,
                    details=(
                        f"Kerberos Golden Ticket forgery detected for principal '{req.client_principal}'. "
                        f"Ticket lifetime: {req.ticket_lifetime_hours:.1f}h (policy limit: 10h), "
                        f"PAC groups: {req.pac_groups_rids} (unauthorized Domain Admin RID injected), "
                        f"Cipher: {req.encryption_type.value}."
                    ),
                    countermeasure="Immediately execute double-reset of KRBTGT account password and purge all active Kerberos TGT sessions.",
                )
                self.alerts.append(alert)
                return alert

        # 2. Silver Ticket Forgery Detection
        # Characteristics: TGS ticket directly targeting high-value service with forged PAC groups
        elif req.ticket_type == KerberosTicketType.TGS_SERVICE_TICKET:
            if has_privileged_rid and not req.is_account_privileged:
                alert = ADThreatAlert(
                    alert_id=f"ad-silver-{uuid.uuid4().hex[:8]}",
                    threat_technique=ADAttackTechnique.SILVER_TICKET_FORGERY,
                    mitre_technique="T1558.002 - Steal or Forge Kerberos Tickets: Silver Ticket",
                    severity="CRITICAL",
                    target_principal=req.client_principal,
                    details=(
                        f"Forged Kerberos Silver Ticket targeting service '{req.service_principal}' "
                        f"presented by unprivileged user '{req.client_principal}' with injected Admin RIDs."
                    ),
                    countermeasure="Reset computer account password of the target service host and enforce Kerberos PAC validation.",
                )
                self.alerts.append(alert)
                return alert

        # 3. AS-REP Roasting Vulnerability Exploitation
        if not req.preauth_required and req.encryption_type == KerberosEncryptionType.RC4_HMAC_NT:
            alert = ADThreatAlert(
                alert_id=f"ad-asrep-{uuid.uuid4().hex[:8]}",
                threat_technique=ADAttackTechnique.ASREP_ROASTING,
                mitre_technique="T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting",
                severity="HIGH",
                target_principal=req.client_principal,
                details=(
                    f"AS-REP Roasting vulnerability detected for account '{req.client_principal}'. "
                    f"Account has 'Do not require Kerberos preauthentication' set with legacy RC4 encryption."
                ),
                countermeasure="Re-enable Kerberos pre-authentication (DONT_REQ_PREAUTH = False) and require AES256 encryption.",
            )
            self.alerts.append(alert)
            return alert

        return None

    def inspect_dc_event(self, event: DCSecurityEvent) -> Optional[ADThreatAlert]:
        """Audit Domain Controller security event for DCSync replication and Kerberoasting."""
        alert: Optional[ADThreatAlert] = None

        # 1. DCSync Directory Replication Attack Detection (Event ID 4662)
        # DS-Replication-Get-Changes-All extended right requested by a non-DC workstation/account!
        if event.event_id == 4662:
            is_dc = any(dc.lower() in event.source_workstation.lower() or dc in event.source_ip for dc in self.AUTHORIZED_DC_HOSTS)
            if not is_dc and event.access_mask and ("1131f6aa" in event.access_mask.lower() or "replication" in event.access_mask.lower()):
                alert = ADThreatAlert(
                    alert_id=f"ad-dcsync-{uuid.uuid4().hex[:8]}",
                    threat_technique=ADAttackTechnique.DCSYNC_REPLICATION_ABUSE,
                    mitre_technique="T1003.006 - OS Credential Dumping: DCSync",
                    severity="CRITICAL",
                    target_principal=event.target_user,
                    source_workstation_or_ip=event.source_workstation or event.source_ip,
                    details=(
                        f"Unauthorized DCSync attack detected from host '{event.source_workstation}' (IP {event.source_ip}). "
                        f"Attempted full directory replication of domain password hashes using DRS API."
                    ),
                    countermeasure="Immediately sever network port 135/445 to source host and revoke Directory Replication Service privileges.",
                )
                self.alerts.append(alert)
                return alert

        # 2. Kerberoasting Detection (Event ID 4769 - TGS Request with RC4 cipher)
        if event.event_id == 4769 and event.ticket_encryption_type in {"0x17", "RC4_HMAC_NT"}:
            source = event.source_workstation or event.source_ip
            spn = event.service_name or "UnknownSPN"
            self.tgs_requests_tracker[source].append(spn)

            # If a single host requests >= 3 RC4 service tickets -> active Kerberoasting campaign!
            if len(self.tgs_requests_tracker[source]) >= 3:
                alert = ADThreatAlert(
                    alert_id=f"ad-roast-{uuid.uuid4().hex[:8]}",
                    threat_technique=ADAttackTechnique.KERBEROASTING,
                    mitre_technique="T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting",
                    severity="HIGH",
                    target_principal=event.target_user,
                    source_workstation_or_ip=source,
                    details=(
                        f"Kerberoasting attack detected originating from host '{source}'. "
                        f"Harvested {len(self.tgs_requests_tracker[source])} service tickets using weak RC4 encryption for offline password cracking."
                    ),
                    countermeasure="Upgrade service accounts to Group Managed Service Accounts (gMSA) with 128-char AES keys.",
                )
                self.alerts.append(alert)
                self.tgs_requests_tracker[source].clear()
                return alert

        return None

    def evaluate_domain_posture(
        self,
        krbtgt_age_days: int = 45,
        unconstrained_delegation_count: int = 2,
        preauth_disabled_count: int = 1,
    ) -> ADDomainPostureReport:
        """Compute Active Directory hygiene score and security posture."""
        score = 100.0
        # Deduct 25 points if krbtgt password is older than 180 days
        if krbtgt_age_days > 180:
            score -= 25.0
        elif krbtgt_age_days > 90:
            score -= 10.0

        score -= min(30.0, unconstrained_delegation_count * 10.0)
        score -= min(20.0, preauth_disabled_count * 5.0)
        score -= min(25.0, len(self.alerts) * 5.0)
        hygiene_score = round(max(0.0, min(100.0, score)), 2)

        if hygiene_score >= 85.0:
            status = "STRONG_RESILIENT"
        elif hygiene_score >= 60.0:
            status = "MODERATE_ELEVATED_RISK"
        else:
            status = "CRITICAL_COMPROMISE_SUSCEPTIBLE"

        return ADDomainPostureReport(
            domain_fqdn=self.domain_fqdn,
            monitored_dcs_count=2,
            active_threats_count=len(self.alerts),
            krbtgt_last_rotated_days=krbtgt_age_days,
            unconstrained_delegation_accounts_count=unconstrained_delegation_count,
            preauth_disabled_accounts_count=preauth_disabled_count,
            domain_hygiene_score=hygiene_score,
            posture_status=status,
        )
