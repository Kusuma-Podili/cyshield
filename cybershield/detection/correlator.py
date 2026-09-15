"""
CyberShield Enterprise - Multi-Stage Attack Chain Correlation Engine
Analyzes streams of security alerts across time windows, evaluates kill-chain progression,
and synthesizes unified incident cases from correlated tactics and techniques.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple

from cybershield.database.models.incidents_and_rules import (
    IncidentModel,
    IncidentTimelineModel,
    IncidentSeverity,
    IncidentStatus,
    IncidentType,
    KillChainPhase,
)
from cybershield.database.models.events_and_alerts import AlertModel

logger = logging.getLogger("cybershield.detection.correlator")


# Kill-chain progression order and relative severity weights
KILL_CHAIN_STAGES = [
    KillChainPhase.RECONNAISSANCE.value,
    KillChainPhase.INITIAL_ACCESS.value,
    KillChainPhase.EXECUTION.value,
    KillChainPhase.PERSISTENCE.value,
    KillChainPhase.PRIVILEGE_ESCALATION.value,
    KillChainPhase.DEFENSE_EVASION.value,
    KillChainPhase.CREDENTIAL_ACCESS.value,
    KillChainPhase.DISCOVERY.value,
    KillChainPhase.LATERAL_MOVEMENT.value,
    KillChainPhase.COLLECTION.value,
    KillChainPhase.COMMAND_AND_CONTROL.value,
    KillChainPhase.EXFILTRATION.value,
    KillChainPhase.IMPACT.value,
]

SEVERITY_WEIGHTS = {
    "CRITICAL": 60,
    "HIGH": 35,
    "MEDIUM": 15,
    "LOW": 5,
    "INFORMATIONAL": 1,
}


class AttackChainCorrelator:
    """
    Evaluates groups of temporal alerts targeting identical host assets or user accounts.
    Detects complex multi-stage intrusion campaigns and synthesizes incident records.
    """

    def __init__(self, correlation_window_minutes: int = 30, risk_threshold: int = 70):
        self.correlation_window = timedelta(minutes=correlation_window_minutes)
        self.risk_threshold = risk_threshold

    def evaluate_alert_cluster(
        self,
        entity_key: str,
        alerts: List[AlertModel]
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluate whether a cluster of alerts on a single entity constitutes an attack chain.
        Returns incident creation attributes if correlation threshold is exceeded, else None.
        """
        if not alerts or len(alerts) < 2:
            # Need at least 2 correlated alerts to form a chain
            return None

        # 1. Calculate cumulative threat score
        total_risk_score = 0
        observed_tactics: Set[str] = set()
        observed_techniques: Set[str] = set()
        alert_ids: List[str] = []
        hosts: Set[str] = set()
        users: Set[str] = set()

        for a in alerts:
            sev_val = a.severity.value if hasattr(a.severity, "value") else str(a.severity)
            weight = SEVERITY_WEIGHTS.get(sev_val, 10)
            total_risk_score += weight
            alert_ids.append(a.id)

            host = getattr(a, "host_name", None) or getattr(a, "impacted_host", None)
            if host:
                hosts.add(host)
            ip = getattr(a, "host_ip", None) or getattr(a, "source_ip", None)
            if ip:
                hosts.add(ip)

            tactics = getattr(a, "mitre_tactics", None) or [getattr(a, "mitre_tactic", None)]
            for t in tactics:
                if t:
                    observed_tactics.add(str(t).upper())

            techniques = getattr(a, "mitre_techniques", None) or [getattr(a, "mitre_technique_id", None)]
            for tc in techniques:
                if tc:
                    observed_techniques.add(str(tc).upper())

        # 2. Check kill-chain diversity
        matching_stages = [
            stage for stage in KILL_CHAIN_STAGES
            if any(stage in tactic or tactic in stage for tactic in observed_tactics)
        ]

        # Trigger if cumulative risk exceeds threshold OR if 2+ distinct kill-chain stages are active
        is_attack_chain = (total_risk_score >= self.risk_threshold) or (len(matching_stages) >= 2)
        if not is_attack_chain:
            return None

        # 3. Determine highest kill-chain phase
        highest_phase = KillChainPhase.EXECUTION.value
        for stage in reversed(KILL_CHAIN_STAGES):
            if stage in matching_stages:
                highest_phase = stage
                break

        # 4. Classify Incident Type
        incident_type = IncidentType.APT_CAMPAIGN.value
        tactics_str = " ".join(observed_tactics).lower()
        if "exfiltration" in tactics_str or any("exfil" in (a.title or "").lower() for a in alerts):
            incident_type = IncidentType.DATA_EXFILTRATION.value
        elif "ransom" in tactics_str or any("ransom" in (a.title or "").lower() for a in alerts):
            incident_type = IncidentType.RANSOMWARE.value
        elif "credential" in tactics_str or "access" in tactics_str:
            incident_type = IncidentType.UNAUTHORIZED_ACCESS.value
        elif "malware" in tactics_str or "execution" in tactics_str:
            incident_type = IncidentType.MALWARE_INFECTION.value

        # 5. Overall Incident Severity
        has_critical = any(a.severity == "CRITICAL" for a in alerts)
        has_high = any(a.severity == "HIGH" for a in alerts)
        if has_critical or total_risk_score >= 120:
            severity = IncidentSeverity.CRITICAL.value
        elif has_high or total_risk_score >= 60:
            severity = IncidentSeverity.HIGH.value
        else:
            severity = IncidentSeverity.MEDIUM.value

        # Suggested playbook
        playbook_map = {
            IncidentType.RANSOMWARE.value: "IR-01: Ransomware Containment & Host Isolation",
            IncidentType.UNAUTHORIZED_ACCESS.value: "IR-02: Account Compromise & Credential Revocation",
            IncidentType.DATA_EXFILTRATION.value: "IR-03: Firewall Block & Data Breach Forensics",
            IncidentType.MALWARE_INFECTION.value: "IR-01: Malware Containment & Host Isolation",
            IncidentType.APT_CAMPAIGN.value: "IR-04: Full Multi-Stage APT Eradication",
        }
        suggested_playbook = playbook_map.get(incident_type, "IR-01: Standard Threat Containment")

        summary = (
            f"Automated correlation detected multi-stage attack progression on entity '{entity_key}'. "
            f"Observed {len(alerts)} alerts spanning stages: {', '.join(matching_stages) or 'Multi-Tactic'}. "
            f"Cumulative threat index: {total_risk_score}. Identified techniques: {', '.join(list(observed_techniques)[:5]) or 'Unknown'}."
        )

        title = f"Multi-Stage {incident_type.replace('_', ' ').title()} on {entity_key}"

        return {
            "title": title,
            "summary": summary,
            "severity": severity,
            "incident_type": incident_type,
            "kill_chain_phase": highest_phase,
            "impacted_hosts": list(hosts),
            "impacted_users": list(users),
            "associated_alert_ids": alert_ids,
            "assigned_playbook": suggested_playbook,
            "risk_score": total_risk_score,
            "observed_stages": matching_stages,
        }


attack_chain_correlator = AttackChainCorrelator()
