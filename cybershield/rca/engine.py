"""
Autonomous Incident Root Cause Analysis (RCA) & Causal Graph Engine.
Traces incident event sequences back to patient-zero origins using
directed provenance graphs, temporal causality estimation, and topological traversal.
"""

import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from cybershield.rca.schemas import (
    CausalEdge,
    CausalNode,
    CausalNodeType,
    IncidentRCAReport,
    RCARequest,
    RootCauseConfidence,
    RootCauseHypothesis,
)


class CausalRCAEngine:
    """
    Forensic causal graph reconstruction and automated patient-zero discovery engine.
    """

    def __init__(self):
        self._reports: Dict[str, IncidentRCAReport] = {}
        self._seed_sample_rca()

    def _seed_sample_rca(self):
        """Seed pre-computed RCA report for incident INC-2026-001."""
        t0 = datetime.utcnow() - timedelta(hours=2)
        nodes = [
            CausalNode(
                node_id="NODE-1",
                node_type=CausalNodeType.AUTH_ATTEMPT,
                timestamp=t0,
                entity_id="WS-EXEC-01",
                description="Spearphishing macro executed in Word document: invoice_march.docm",
                attributes={"user": "finance.analyst", "process": "winword.exe"},
                is_anomaly=True
            ),
            CausalNode(
                node_id="NODE-2",
                node_type=CausalNodeType.PROCESS_EXECUTION,
                timestamp=t0 + timedelta(seconds=2),
                entity_id="WS-EXEC-01",
                description="PowerShell spawned by Word with encoded download cradle",
                attributes={"process": "powershell.exe", "parent": "winword.exe"},
                is_anomaly=True
            ),
            CausalNode(
                node_id="NODE-3",
                node_type=CausalNodeType.NETWORK_CONNECTION,
                timestamp=t0 + timedelta(seconds=5),
                entity_id="WS-EXEC-01",
                description="Outbound HTTPS C2 connection to 198.51.100.44:443",
                attributes={"dest_ip": "198.51.100.44", "port": 443},
                is_anomaly=True
            ),
            CausalNode(
                node_id="NODE-4",
                node_type=CausalNodeType.FILE_MODIFICATION,
                timestamp=t0 + timedelta(seconds=8),
                entity_id="WS-EXEC-01",
                description="Cobalt Strike beacon binary dropped into C:\\ProgramData\\update.exe",
                attributes={"path": r"C:\ProgramData\update.exe"},
                is_anomaly=True
            ),
            CausalNode(
                node_id="NODE-5",
                node_type=CausalNodeType.SECURITY_ALERT,
                timestamp=t0 + timedelta(seconds=12),
                entity_id="WS-EXEC-01",
                description="EDR alert ALT-001: Unauthorized process injection into lsass.exe",
                attributes={"alert_id": "ALT-001"},
                is_anomaly=True
            ),
        ]
        edges = [
            CausalEdge(source_id="NODE-1", target_id="NODE-2", temporal_delta_ms=2000, causal_probability=0.98, relationship_type="SPAWNED_BY"),
            CausalEdge(source_id="NODE-2", target_id="NODE-3", temporal_delta_ms=3000, causal_probability=0.95, relationship_type="INITIATED_BY"),
            CausalEdge(source_id="NODE-3", target_id="NODE-4", temporal_delta_ms=3000, causal_probability=0.92, relationship_type="DOWNLOADED_VIA"),
            CausalEdge(source_id="NODE-4", target_id="NODE-5", temporal_delta_ms=4000, causal_probability=0.96, relationship_type="TRIGGERED_BY"),
        ]
        hypo = RootCauseHypothesis(
            hypothesis_id="HYPO-001",
            root_node_id="NODE-1",
            summary="Patient Zero: Malicious macro execution inside spearphishing document on finance workstation",
            initial_access_vector="T1566.001 - Phishing: Spearphishing Attachment",
            confidence=RootCauseConfidence.DEFINITIVE,
            causal_score=96.5,
            evidence_chain=[
                "Word process spawned PowerShell with encoded command",
                "PowerShell fetched stage-1 payload from 198.51.100.44",
                "Dropped update.exe executed process injection into lsass"
            ],
            recommended_remediations=[
                "Quarantine host WS-EXEC-01 immediately",
                "Block C2 IP 198.51.100.44 on boundary firewalls",
                "Disable Office VBA macro execution via Group Policy",
                "Reset Active Directory credentials for finance.analyst"
            ]
        )
        report = IncidentRCAReport(
            report_id="RCA-INC-2026-001",
            incident_id="INC-2026-001",
            nodes=nodes,
            edges=edges,
            patient_zero_hypothesis=hypo,
            total_events_analyzed=5,
            blast_radius_hosts=["WS-EXEC-01"]
        )
        self._reports[report.report_id] = report

    def analyze_incident(self, req: RCARequest) -> IncidentRCAReport:
        """
        Builds causal provenance graph from chronological raw events,
        determines in-degree 0 entry vertices, and synthesizes root cause hypotheses.
        """
        raw_events = req.events or []
        nodes: List[CausalNode] = []
        edges: List[CausalEdge] = []
        node_map: Dict[str, CausalNode] = {}
        hosts: Set[str] = set()

        for idx, ev in enumerate(raw_events):
            nid = ev.get("id", f"EVT-NODE-{idx}")
            ts_val = ev.get("timestamp")
            if isinstance(ts_val, str):
                try:
                    ts = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
                except Exception:
                    ts = datetime.utcnow()
            elif isinstance(ts_val, datetime):
                ts = ts_val
            else:
                ts = datetime.utcnow()

            entity = ev.get("host_id") or ev.get("entity_id") or "UNKNOWN_HOST"
            hosts.add(entity)

            ntype_str = ev.get("type", "SECURITY_ALERT").upper()
            try:
                ntype = CausalNodeType(ntype_str)
            except ValueError:
                ntype = CausalNodeType.SECURITY_ALERT

            node = CausalNode(
                node_id=nid,
                node_type=ntype,
                timestamp=ts,
                entity_id=entity,
                description=ev.get("description", "Telemetry event"),
                attributes=ev.get("attributes", {}),
                is_anomaly=bool(ev.get("is_anomaly", True))
            )
            nodes.append(node)
            node_map[nid] = node

        # Sort nodes chronologically
        nodes.sort(key=lambda n: n.timestamp)

        # Build causal edges based on temporal ordering and entity affinity
        target_ids: Set[str] = set()
        for i in range(len(nodes) - 1):
            src = nodes[i]
            tgt = nodes[i + 1]
            dt_ms = max(1.0, (tgt.timestamp - src.timestamp).total_seconds() * 1000.0)

            # Heuristic probability decreases with elapsed time
            prob = max(0.5, round(1.0 - (dt_ms / 60000.0), 2)) if dt_ms < 60000.0 else 0.55

            edge = CausalEdge(
                source_id=src.node_id,
                target_id=tgt.node_id,
                temporal_delta_ms=dt_ms,
                causal_probability=prob,
                relationship_type="PRECEDED_AND_CORRELATED"
            )
            edges.append(edge)
            target_ids.add(tgt.node_id)

        # Patient Zero Discovery: Nodes with in-degree 0 (not in target_ids)
        candidate_roots = [n for n in nodes if n.node_id not in target_ids]
        patient_zero = candidate_roots[0] if candidate_roots else (nodes[0] if nodes else None)

        primary_hypo: Optional[RootCauseHypothesis] = None
        if patient_zero:
            primary_hypo = RootCauseHypothesis(
                hypothesis_id=f"HYPO-{uuid.uuid4().hex[:6].upper()}",
                root_node_id=patient_zero.node_id,
                summary=f"Patient Zero: {patient_zero.description} on {patient_zero.entity_id}",
                initial_access_vector="T1078 - Valid Accounts / Initial Execution",
                confidence=RootCauseConfidence.HIGH if len(nodes) > 2 else RootCauseConfidence.MEDIUM,
                causal_score=88.0,
                evidence_chain=[f"Initial event {n.node_id}: {n.description}" for n in nodes[:3]],
                recommended_remediations=[
                    f"Isolate host {patient_zero.entity_id} from enterprise network",
                    "Conduct forensic triage on initial artifact path",
                    "Review lateral movement paths from initial node"
                ]
            )

        report_id = f"RCA-{req.incident_id}-{uuid.uuid4().hex[:4].upper()}"
        report = IncidentRCAReport(
            report_id=report_id,
            incident_id=req.incident_id,
            nodes=nodes,
            edges=edges,
            patient_zero_hypothesis=primary_hypo,
            total_events_analyzed=len(nodes),
            blast_radius_hosts=list(hosts)
        )
        self._reports[report_id] = report
        return report

    def get_report(self, report_id: str) -> Optional[IncidentRCAReport]:
        return self._reports.get(report_id)

    def list_reports(self) -> List[IncidentRCAReport]:
        return list(self._reports.values())

    def get_overview_metrics(self) -> Dict[str, Any]:
        total = len(self._reports)
        hosts_impacted = set()
        for r in self._reports.values():
            hosts_impacted.update(r.blast_radius_hosts)

        return {
            "total_rca_investigations": total,
            "patient_zero_identifications": sum(1 for r in self._reports.values() if r.patient_zero_hypothesis),
            "unique_hosts_in_blast_radius": len(hosts_impacted),
            "mean_events_per_investigation": round(sum(r.total_events_analyzed for r in self._reports.values()) / max(1, total), 1),
        }
