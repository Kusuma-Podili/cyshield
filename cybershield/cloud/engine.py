"""Unified Cloud & Container Security Engine (CSPM / CWPP).

Orchestrates Kubernetes manifest security auditing, AWS CloudTrail anomaly detection,
and container runtime threat detection into a unified cloud defense fabric.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from cybershield.cloud.aws_cloudtrail_parser import CloudTrailParser
from cybershield.cloud.container_runtime import ContainerRuntimeDetector
from cybershield.cloud.k8s_scanner import K8sManifestScanner
from cybershield.cloud.schemas import (
    CloudFindingSeverity,
    CloudPostureResponse,
    CloudProvider,
    CloudSecurityFinding,
    ContainerProcessInspectRequest,
    ContainerRuntimeAlert,
    K8sWorkloadScanResult,
)
from cybershield.tasks.event_bus import global_event_bus

logger = logging.getLogger("cybershield.cloud.engine")


class CloudSecurityEngine:
    """Master coordinator for Cloud Security Posture Management & Workload Protection."""

    def __init__(self) -> None:
        self.k8s_scanner = K8sManifestScanner()
        self.cloudtrail_parser = CloudTrailParser()
        self.runtime_detector = ContainerRuntimeDetector()

        # In-memory historical records
        self.findings_store: List[CloudSecurityFinding] = []
        self.runtime_alerts_store: List[ContainerRuntimeAlert] = []

    def scan_k8s_manifest(self, manifest_raw: str, dispatch_events: bool = True) -> K8sWorkloadScanResult:
        """Scan Kubernetes deployment manifest string."""
        result = self.k8s_scanner.scan_manifest_str(manifest_raw)
        self.findings_store.extend(result.findings)

        if dispatch_events:
            for f in result.findings:
                if f.severity in (CloudFindingSeverity.CRITICAL, CloudFindingSeverity.HIGH):
                    try:
                        global_event_bus.publish_sync(
                            topic="cloud.k8s.violation",
                            data={
                                "finding_id": f.finding_id,
                                "resource": f.resource_id,
                                "title": f.title,
                                "severity": f.severity.value,
                                "mitre": f.mitre_technique,
                            },
                            source="k8s_scanner",
                        )
                    except Exception:
                        pass

        return result

    def audit_cloudtrail_records(
        self, records: List[Dict[str, Any]], dispatch_events: bool = True
    ) -> List[CloudSecurityFinding]:
        """Audit AWS CloudTrail JSON records."""
        findings = self.cloudtrail_parser.parse_and_audit(records)
        self.findings_store.extend(findings)

        if dispatch_events:
            for f in findings:
                if f.severity in (CloudFindingSeverity.CRITICAL, CloudFindingSeverity.HIGH):
                    try:
                        global_event_bus.publish_sync(
                            topic="cloud.aws.cloudtrail_threat",
                            data={
                                "finding_id": f.finding_id,
                                "resource": f.resource_id,
                                "title": f.title,
                                "severity": f.severity.value,
                                "mitre": f.mitre_technique,
                            },
                            source="cloudtrail_audit",
                        )
                    except Exception:
                        pass

        return findings

    def inspect_container_process(
        self, req: ContainerProcessInspectRequest, dispatch_events: bool = True
    ) -> List[ContainerRuntimeAlert]:
        """Inspect a container's runtime process and mounts."""
        alerts = self.runtime_detector.inspect_process(req)
        self.runtime_alerts_store.extend(alerts)

        if dispatch_events:
            for a in alerts:
                try:
                    global_event_bus.publish_sync(
                        topic="container.runtime.threat",
                        data={
                            "alert_id": a.alert_id,
                            "container_id": a.container_id,
                            "image": a.image_name,
                            "title": a.title,
                            "command": req.command_line,
                            "mitre": a.mitre_technique,
                        },
                        source="cwpp_runtime",
                    )
                except Exception:
                    pass

        return alerts

    def get_posture(self, provider: Optional[CloudProvider] = None) -> CloudPostureResponse:
        """Calculate overall cloud posture compliance score (0-100%)."""
        filtered_findings = [
            f for f in self.findings_store if provider is None or f.provider == provider
        ]

        crit_count = sum(1 for f in filtered_findings if f.severity == CloudFindingSeverity.CRITICAL)
        high_count = sum(1 for f in filtered_findings if f.severity == CloudFindingSeverity.HIGH)
        med_count = sum(1 for f in filtered_findings if f.severity == CloudFindingSeverity.MEDIUM)
        low_count = sum(1 for f in filtered_findings if f.severity == CloudFindingSeverity.LOW)

        # Baseline 100%, deduct penalty points per severity
        penalty = (crit_count * 20.0) + (high_count * 10.0) + (med_count * 5.0) + (low_count * 2.0)
        score = max(0.0, round(100.0 - penalty, 2))

        return CloudPostureResponse(
            provider=provider or CloudProvider.KUBERNETES,
            compliance_score=score,
            total_findings=len(filtered_findings),
            critical_findings=crit_count,
            high_findings=high_count,
            findings=filtered_findings,
        )

    def get_all_findings(self) -> List[CloudSecurityFinding]:
        return list(self.findings_store)

    def get_all_runtime_alerts(self) -> List[ContainerRuntimeAlert]:
        return list(self.runtime_alerts_store)

    def clear(self) -> None:
        """Clear findings cache."""
        self.findings_store.clear()
        self.runtime_alerts_store.clear()


# Global singleton instance
cloud_engine = CloudSecurityEngine()
