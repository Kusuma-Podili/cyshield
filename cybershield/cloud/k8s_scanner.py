"""Kubernetes Workload & Admission Controller Security Scanner.

Inspects Pod, Deployment, DaemonSet, and StatefulSet manifests against
Kubernetes Pod Security Standards (PSS) and CIS Kubernetes Benchmark controls.
"""

from __future__ import annotations

import json
import yaml
from typing import Any, Dict, List, Optional

from cybershield.cloud.schemas import (
    CloudProvider,
    CloudFindingSeverity,
    CloudSecurityFinding,
    K8sWorkloadScanResult,
)


class K8sSecurityScanner:
    """Evaluates Kubernetes YAML/JSON manifests for security misconfigurations."""

    @classmethod
    def scan_manifest(cls, manifest_str: str) -> K8sWorkloadScanResult:
        """Parse and evaluate Kubernetes manifest for privilege and container escape vectors."""
        findings: List[CloudSecurityFinding] = []

        try:
            doc = yaml.safe_load(manifest_str)
            if not isinstance(doc, dict):
                doc = json.loads(manifest_str)
        except Exception:
            return K8sWorkloadScanResult(
                resource_kind="Unknown",
                name="invalid-manifest",
                is_compliant=False,
                total_violations=1,
                findings=[
                    CloudSecurityFinding(
                        finding_id="K8S-PARSE-ERROR",
                        provider=CloudProvider.KUBERNETES,
                        severity=CloudFindingSeverity.HIGH,
                        title="Invalid Manifest Syntax",
                        description="Unable to parse input as valid YAML or JSON Kubernetes manifest.",
                        resource_id="manifest",
                        remediation="Ensure valid Kubernetes YAML/JSON syntax.",
                    )
                ],
            )

        kind = doc.get("kind", "Pod")
        metadata = doc.get("metadata", {})
        name = metadata.get("name", "unnamed-workload")
        namespace = metadata.get("namespace", "default")
        res_id = f"{namespace}/{kind}/{name}"

        # Resolve Pod Spec depending on workload kind
        pod_spec: Dict[str, Any] = {}
        if kind == "Pod":
            pod_spec = doc.get("spec", {})
        elif kind in ("Deployment", "DaemonSet", "StatefulSet", "Job"):
            pod_spec = doc.get("spec", {}).get("template", {}).get("spec", {})
        else:
            pod_spec = doc.get("spec", {})

        # --- Rule 1: Host Network Sharing ---
        if pod_spec.get("hostNetwork") is True:
            findings.append(
                CloudSecurityFinding(
                    finding_id="K8S-HOST-NETWORK-001",
                    provider=CloudProvider.KUBERNETES,
                    severity=CloudFindingSeverity.HIGH,
                    title="Workload Shares Host Network Namespace (hostNetwork=true)",
                    description="Pod shares the host node network stack, allowing container processes to sniff host network traffic and bind to node ports.",
                    resource_id=res_id,
                    mitre_technique="T1611",
                    remediation="Set 'hostNetwork: false' in pod spec unless absolutely required by CNI daemonset.",
                )
            )

        # --- Rule 2: Host PID / IPC Sharing ---
        if pod_spec.get("hostPID") is True or pod_spec.get("hostIPC") is True:
            findings.append(
                CloudSecurityFinding(
                    finding_id="K8S-HOST-PID-001",
                    provider=CloudProvider.KUBERNETES,
                    severity=CloudFindingSeverity.CRITICAL,
                    title="Workload Shares Host Process or IPC Namespace",
                    description="Container can inspect, attach debuggers to, and terminate host node processes, enabling container escape.",
                    resource_id=res_id,
                    mitre_technique="T1611",
                    remediation="Disable hostPID and hostIPC in pod spec.",
                )
            )

        # --- Rule 3: HostPath Volume Mounts ---
        volumes = pod_spec.get("volumes", [])
        for v in volumes:
            if "hostPath" in v:
                hp_path = v["hostPath"].get("path", "unknown")
                findings.append(
                    CloudSecurityFinding(
                        finding_id="K8S-HOSTPATH-001",
                        provider=CloudProvider.KUBERNETES,
                        severity=CloudFindingSeverity.CRITICAL,
                        title=f"Dangerous HostPath Volume Mounted: '{hp_path}'",
                        description=f"Volume '{v.get('name')}' mounts host node directory '{hp_path}'. Enables root filesystem compromise or container breakout.",
                        resource_id=res_id,
                        mitre_technique="T1611",
                        remediation="Replace hostPath with PersistentVolumeClaim (PVC), configMap, or secret volume.",
                    )
                )

        # Inspect Containers & InitContainers
        all_containers = pod_spec.get("containers", []) + pod_spec.get("initContainers", [])
        for c in all_containers:
            c_name = c.get("name", "container")
            sec_ctx = c.get("securityContext", {})
            c_res_id = f"{res_id}/container/{c_name}"

            # --- Rule 4: Privileged Mode Execution ---
            if sec_ctx.get("privileged") is True:
                findings.append(
                    CloudSecurityFinding(
                        finding_id="K8S-PRIVILEGED-001",
                        provider=CloudProvider.KUBERNETES,
                        severity=CloudFindingSeverity.CRITICAL,
                        title=f"Privileged Container Execution in '{c_name}'",
                        description="Container runs with 'privileged: true'. Disables all kernel isolation, giving container full device and root capabilities on the host node.",
                        resource_id=c_res_id,
                        mitre_technique="T1611",
                        remediation="Remove 'privileged: true' and grant only explicit least-privilege Linux capabilities.",
                    )
                )

            # --- Rule 5: Running as Root UID 0 ---
            if sec_ctx.get("runAsNonRoot") is not True or sec_ctx.get("runAsUser") == 0:
                findings.append(
                    CloudSecurityFinding(
                        finding_id="K8S-ROOT-USER-001",
                        provider=CloudProvider.KUBERNETES,
                        severity=CloudFindingSeverity.HIGH,
                        title=f"Container Allowed to Run as Root (UID 0) in '{c_name}'",
                        description="Container is configured without 'runAsNonRoot: true' or explicitly declares runAsUser: 0.",
                        resource_id=c_res_id,
                        mitre_technique="T1068",
                        remediation="Set 'securityContext.runAsNonRoot: true' and specify an unprivileged 'runAsUser: 10001'.",
                    )
                )

            # --- Rule 6: Dangerous Linux Capabilities ---
            caps = sec_ctx.get("capabilities", {})
            added_caps = [cap.upper() for cap in caps.get("add", [])]
            dangerous = {"SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE", "SYS_RAWIO"}
            flagged = dangerous.intersection(set(added_caps))
            if flagged:
                findings.append(
                    CloudSecurityFinding(
                        finding_id="K8S-CAPABILITIES-001",
                        provider=CloudProvider.KUBERNETES,
                        severity=CloudFindingSeverity.HIGH,
                        title=f"Dangerous Linux Capabilities Added: {list(flagged)} in '{c_name}'",
                        description=f"Container granted sensitive kernel capabilities {list(flagged)}, which facilitate privilege escalation and container breakout.",
                        resource_id=c_res_id,
                        mitre_technique="T1611",
                        remediation="Drop all capabilities ('drop: [ALL]') and add only required unprivileged capabilities.",
                    )
                )

            # --- Rule 7: Writable Root Filesystem ---
            if sec_ctx.get("readOnlyRootFilesystem") is not True:
                findings.append(
                    CloudSecurityFinding(
                        finding_id="K8S-READONLY-ROOT-001",
                        provider=CloudProvider.KUBERNETES,
                        severity=CloudFindingSeverity.MEDIUM,
                        title=f"Root Filesystem is Mutable (Writable) in '{c_name}'",
                        description="Container root filesystem is writable, allowing attackers to download and persist web shells or backdoors in container image layers.",
                        resource_id=c_res_id,
                        mitre_technique="T1059",
                        remediation="Set 'securityContext.readOnlyRootFilesystem: true' and mount ephemeral emptyDir volumes for scratch data.",
                    )
                )

            # --- Rule 8: Missing Resource Limits ---
            resources = c.get("resources", {})
            limits = resources.get("limits", {})
            if not limits.get("cpu") or not limits.get("memory"):
                findings.append(
                    CloudSecurityFinding(
                        finding_id="K8S-NO-RESOURCE-LIMITS-001",
                        provider=CloudProvider.KUBERNETES,
                        severity=CloudFindingSeverity.LOW,
                        title=f"Missing CPU or Memory Limits in '{c_name}'",
                        description="Container does not declare resource limits, leaving the node vulnerable to resource exhaustion / DoS attacks.",
                        resource_id=c_res_id,
                        mitre_technique="T1499",
                        remediation="Specify 'resources.limits.cpu' and 'resources.limits.memory'.",
                    )
                )

        return K8sWorkloadScanResult(
            resource_kind=kind,
            name=name,
            namespace=namespace,
            is_compliant=len(findings) == 0,
            total_violations=len(findings),
            findings=findings,
        )


class K8sManifestScanner(K8sSecurityScanner):
    """Convenience instance wrapper for K8sSecurityScanner."""

    def scan_manifest_str(self, manifest_str: str) -> K8sWorkloadScanResult:
        return self.scan_manifest(manifest_str)

