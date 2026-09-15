"""Cross-Engine Threat Correlation & MITRE ATT&CK Graph Builder.

Aggregates alerts from Anomaly, UEBA, Payload, Sigma, and YARA engines.
Clusters related events across temporal windows and maps multi-stage kill chains
to construct attack graphs and elevate incidents automatically.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime, timezone, timedelta
from collections import defaultdict

from cybershield.core.models import (
    Alert,
    Incident,
    IncidentStatus,
    Severity,
    generate_id,
    now_utc,
)

logger = logging.getLogger("cybershield.engine.correlation")


# Standard 14 MITRE ATT&CK Enterprise Tactics in sequential kill chain order
MITRE_KILL_CHAIN_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


class AlertCluster:
    """A cluster of related alerts sharing a common threat actor, host, or campaign."""
    def __init__(self, cluster_id: str, pivot_entity: str):
        self.cluster_id = cluster_id
        self.pivot_entity = pivot_entity
        self.alerts: List[Alert] = []
        self.tactics_observed: Set[str] = set()
        self.techniques_observed: Set[str] = set()
        self.affected_hosts: Set[str] = set()
        self.affected_users: Set[str] = set()
        self.first_seen: datetime = now_utc()
        self.last_seen: datetime = now_utc()
        self.promoted_incident_id: Optional[str] = None

    def add_alert(self, alert: Alert) -> None:
        """Incorporate alert into cluster and recalculate state."""
        self.alerts.append(alert)
        self.tactics_observed.update(alert.mitre_tactics)
        self.techniques_observed.update(alert.mitre_techniques)
        if alert.impacted_host:
            self.affected_hosts.add(alert.impacted_host)
        if alert.impacted_user:
            self.affected_users.add(alert.impacted_user)
        if alert.primary_dest_ip:
            self.affected_hosts.add(alert.primary_dest_ip)

        self.last_seen = max(self.last_seen, alert.created_at)
        self.first_seen = min(self.first_seen, alert.created_at)

    @property
    def highest_severity(self) -> Severity:
        severities = [a.severity for a in self.alerts]
        if Severity.CRITICAL in severities:
            return Severity.CRITICAL
        if Severity.HIGH in severities:
            return Severity.HIGH
        if Severity.MEDIUM in severities:
            return Severity.MEDIUM
        return Severity.LOW

    @property
    def kill_chain_breadth(self) -> int:
        """Count how many distinct kill-chain tactics have been observed."""
        return len(self.tactics_observed)

    def should_escalate_to_incident(self) -> bool:
        """Determine if this cluster represents an active multi-stage breach."""
        # 1. Any CRITICAL alert
        if self.highest_severity == Severity.CRITICAL and len(self.alerts) >= 1:
            return True
        # 2. Multi-stage attack progression (2+ distinct tactics observed)
        if self.kill_chain_breadth >= 2 and len(self.alerts) >= 2:
            return True
        # 3. High volume alert burst on a single pivot entity
        if len(self.alerts) >= 5:
            return True
        return False


class ThreatCorrelationEngine:
    """Real-time correlation engine building graph links and elevating incidents."""

    def __init__(self, correlation_window_minutes: int = 30):
        self.window = timedelta(minutes=correlation_window_minutes)
        self._clusters: Dict[str, AlertCluster] = {}
        self._alert_to_cluster: Dict[str, str] = {}
        self._incidents: Dict[str, Incident] = {}

    def correlate_alert(self, alert: Alert) -> Tuple[Optional[AlertCluster], Optional[Incident]]:
        """Process an incoming alert, update clusters, and return created/updated incident."""
        pivot_entities = []
        if alert.primary_source_ip:
            pivot_entities.append(f"ip:{alert.primary_source_ip}")
        if alert.impacted_host:
            pivot_entities.append(f"host:{alert.impacted_host}")
        if alert.impacted_user:
            pivot_entities.append(f"user:{alert.impacted_user}")
        if alert.primary_dest_ip:
            pivot_entities.append(f"dest:{alert.primary_dest_ip}")

        # Default fallback pivot
        pivot_key = pivot_entities[0] if pivot_entities else f"alert:{alert.alert_id}"

        # Check existing active cluster for this pivot
        cluster = self._clusters.get(pivot_key)
        if cluster is None:
            cluster = AlertCluster(cluster_id=generate_id("CLUST"), pivot_entity=pivot_key)
            self._clusters[pivot_key] = cluster

        cluster.add_alert(alert)
        self._alert_to_cluster[alert.alert_id] = cluster.cluster_id

        # Check for incident escalation
        incident = None
        if cluster.should_escalate_to_incident():
            if cluster.promoted_incident_id is None:
                incident = self._create_incident_from_cluster(cluster)
                cluster.promoted_incident_id = incident.incident_id
                self._incidents[incident.incident_id] = incident
                logger.warning("Elevated Alert Cluster %s to Security Incident %s", cluster.cluster_id, incident.incident_id)
            else:
                # Update existing incident with latest alerts
                incident = self._incidents[cluster.promoted_incident_id]
                incident.related_alert_ids = [a.alert_id for a in cluster.alerts]
                incident.affected_hosts = list(cluster.affected_hosts)
                incident.affected_users = list(cluster.affected_users)
                incident.severity = cluster.highest_severity
                incident.updated_at = now_utc()

        return cluster, incident

    def _create_incident_from_cluster(self, cluster: AlertCluster) -> Incident:
        """Transform an escalated AlertCluster into a formal Incident record."""
        # Find latest observed kill-chain phase
        latest_phase = "Initial Access"
        for tactic in reversed(MITRE_KILL_CHAIN_ORDER):
            if tactic in cluster.tactics_observed:
                latest_phase = tactic
                break

        title = f"Correlated Attack Campaign: {cluster.pivot_entity} ({cluster.kill_chain_breadth} MITRE Tactics)"
        summary = (
            f"Automated correlation detected multi-stage threat progression involving {len(cluster.alerts)} alerts. "
            f"Observed tactics: {', '.join(sorted(cluster.tactics_observed))}. "
            f"Observed techniques: {', '.join(sorted(cluster.techniques_observed))}. "
            f"Impacted assets: {', '.join(cluster.affected_hosts or ['N/A'])}."
        )

        return Incident(
            title=title,
            summary=summary,
            severity=cluster.highest_severity,
            status=IncidentStatus.OPEN,
            related_alert_ids=[a.alert_id for a in cluster.alerts],
            affected_hosts=list(cluster.affected_hosts),
            affected_users=list(cluster.affected_users),
            kill_chain_phase=latest_phase,
        )

    def get_attack_graph(self) -> Dict[str, Any]:
        """Generate graph nodes and edges for SOC attack graph visualization."""
        nodes = []
        edges = []
        node_ids = set()

        for cluster in self._clusters.values():
            if not cluster.alerts:
                continue

            # Add Pivot Node
            pivot_node_id = f"pivot_{cluster.cluster_id}"
            if pivot_node_id not in node_ids:
                nodes.append({
                    "id": pivot_node_id,
                    "label": cluster.pivot_entity,
                    "type": "pivot",
                    "severity": cluster.highest_severity.value,
                })
                node_ids.add(pivot_node_id)

            # Add Alert Nodes and connect to Pivot
            for alert in cluster.alerts:
                alert_node_id = f"alert_{alert.alert_id}"
                if alert_node_id not in node_ids:
                    nodes.append({
                        "id": alert_node_id,
                        "label": alert.title[:32] + "...",
                        "type": "alert",
                        "severity": alert.severity.value,
                        "technique": alert.mitre_techniques[0] if alert.mitre_techniques else "N/A"
                    })
                    node_ids.add(alert_node_id)
                    edges.append({
                        "source": pivot_node_id,
                        "target": alert_node_id,
                        "relationship": "TRIGGERS"
                    })

        return {"nodes": nodes, "edges": edges}

    def get_all_incidents(self) -> List[Incident]:
        """Retrieve all escalated incident cases."""
        return list(self._incidents.values())


# Global singleton correlation engine
correlation_engine = ThreatCorrelationEngine()
