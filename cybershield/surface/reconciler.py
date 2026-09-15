"""CyberShield Enterprise - Autonomous Threat Surface Graph & Shadow Cloud Reconciler Engine.
Performs discrepancy reconciliation between CMDB and live telemetry, detects shadow cloud assets,
evaluates dangling DNS subdomain takeovers, and computes Attack Surface Hygiene.
"""

import uuid
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime, timezone

from .schemas import (
    CloudAssetType,
    SurfaceThreatType,
    CloudAsset,
    DNSTakeoverCheckRequest,
    SurfaceThreatAlert,
    ReconciliationRequest,
    ReconciliationReport,
)


class ThreatSurfaceReconciler:
    """Enterprise attack surface graph reconciler and shadow asset discovery engine."""

    # Approved enterprise cloud regions
    APPROVED_REGIONS: Set[str] = {"us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-south-1"}

    # Sensitive management / database ports that must NEVER be public
    SENSITIVE_MANAGEMENT_PORTS: Set[int] = {22, 3389, 5432, 3306, 6379, 27017, 9200}

    # Fingerprints for dangling DNS subdomain takeover
    TAKEOVER_SIGNATURES: Dict[str, Tuple[str, str]] = {
        "s3": ("s3.amazonaws.com", "nosuchbucket"),
        "github": ("github.io", "there isn't a github pages site here"),
        "heroku": ("herokuapp.com", "no such app"),
        "azure": ("azurewebsites.net", "web site not found"),
    }

    def __init__(self):
        self.shadow_assets: Dict[str, CloudAsset] = {}
        self.alerts: List[SurfaceThreatAlert] = []

    def reconcile_assets(self, req: ReconciliationRequest) -> ReconciliationReport:
        """Reconcile sanctioned CMDB assets against live observed telemetry."""
        sanctioned_ids = {a.asset_id for a in req.sanctioned_assets}
        sanctioned_ips = {a.ip_address for a in req.sanctioned_assets if a.ip_address}
        sanctioned_fqdns = {a.fqdn.lower() for a in req.sanctioned_assets if a.fqdn}

        threats: List[SurfaceThreatAlert] = []
        shadow_count = 0

        for live in req.observed_live_assets:
            is_sanctioned = (
                live.asset_id in sanctioned_ids
                or (live.ip_address and live.ip_address in sanctioned_ips)
                or (live.fqdn and live.fqdn.lower() in sanctioned_fqdns)
            )

            # 1. Shadow Cloud Asset Detection
            if not is_sanctioned:
                shadow_count += 1
                self.shadow_assets[live.asset_id] = live
                alert = SurfaceThreatAlert(
                    alert_id=f"surf-shadow-{uuid.uuid4().hex[:8]}",
                    threat_type=SurfaceThreatType.SHADOW_UNMANAGED_ASSET,
                    asset_id=live.asset_id,
                    asset_name=live.asset_name,
                    severity="HIGH",
                    mitre_technique="T1580 - Cloud Infrastructure Discovery: Shadow Cloud Asset",
                    details=(
                        f"Unmanaged shadow {live.asset_type.value} '{live.asset_name}' (ID {live.asset_id}) "
                        f"discovered in region {live.region} with IP {live.ip_address or 'N/A'}. "
                        f"Missing from authorized enterprise CMDB and Terraform IaC state."
                    ),
                    remediation_action="Trigger SOAR playbook to quarantine or decommission unauthorized cloud resource.",
                )
                threats.append(alert)
                self.alerts.append(alert)

            # 2. Exposed Sensitive Management Ports
            exposed_sensitive = set(live.open_ports).intersection(self.SENSITIVE_MANAGEMENT_PORTS)
            if exposed_sensitive:
                alert = SurfaceThreatAlert(
                    alert_id=f"surf-port-{uuid.uuid4().hex[:8]}",
                    threat_type=SurfaceThreatType.EXPOSED_MANAGEMENT_PORT,
                    asset_id=live.asset_id,
                    asset_name=live.asset_name,
                    severity="CRITICAL",
                    mitre_technique="T1046 - Network Service Discovery: Exposed Management Ports",
                    details=(
                        f"Asset '{live.asset_name}' has sensitive management/database ports "
                        f"{sorted(list(exposed_sensitive))} directly exposed to the public internet."
                    ),
                    remediation_action="Update Cloud Security Group / Firewall ACLs to restrict ingress to corporate VPN only.",
                )
                threats.append(alert)
                self.alerts.append(alert)

            # 3. Unauthorized Cloud Region
            if live.region and live.region.lower() not in self.APPROVED_REGIONS:
                alert = SurfaceThreatAlert(
                    alert_id=f"surf-region-{uuid.uuid4().hex[:8]}",
                    threat_type=SurfaceThreatType.UNAUTHORIZED_CLOUD_REGION,
                    asset_id=live.asset_id,
                    asset_name=live.asset_name,
                    severity="MEDIUM",
                    mitre_technique="T1580 - Cloud Infrastructure Discovery: Unauthorized Region",
                    details=(
                        f"Asset '{live.asset_name}' operates in unauthorized cloud region '{live.region}'. "
                        f"Corporate compliance policy restricts deployments to {sorted(list(self.APPROVED_REGIONS))}."
                    ),
                    remediation_action="Enforce AWS SCP / Azure Policy to terminate non-compliant region resources.",
                )
                threats.append(alert)
                self.alerts.append(alert)

            # 4. Public Object Storage Leak
            if live.asset_type == CloudAssetType.OBJECT_STORAGE_BUCKET and live.tags.get("public_access") == "true":
                alert = SurfaceThreatAlert(
                    alert_id=f"surf-bucket-{uuid.uuid4().hex[:8]}",
                    threat_type=SurfaceThreatType.PUBLIC_OBJECT_STORAGE_LEAK,
                    asset_id=live.asset_id,
                    asset_name=live.asset_name,
                    severity="CRITICAL",
                    mitre_technique="T1530 - Data from Cloud Storage Object: Public Bucket",
                    details=f"Object storage bucket '{live.asset_name}' has public read/list ACL permissions enabled.",
                    remediation_action="Invoke S3 Block Public Access (BPA) and enforce bucket policy encryption.",
                )
                threats.append(alert)
                self.alerts.append(alert)

        # Calculate Attack Surface Hygiene Score (0.0 to 100.0)
        score = 100.0 - (shadow_count * 10.0) - (len(threats) * 8.0)
        hygiene_score = round(max(0.0, min(100.0, score)), 2)

        return ReconciliationReport(
            total_sanctioned_assets=len(req.sanctioned_assets),
            total_observed_assets=len(req.observed_live_assets),
            shadow_unmanaged_count=shadow_count,
            threats_detected=threats,
            attack_surface_score=hygiene_score,
        )

    def evaluate_dns_takeover(self, req: DNSTakeoverCheckRequest) -> Optional[SurfaceThreatAlert]:
        """Audit CNAME record for dangling DNS subdomain takeover vulnerability."""
        target_lower = req.cname_target.lower()
        body_lower = (req.target_response_body or "").lower()

        # Check against provider signatures
        is_vulnerable = False
        provider_matched = "Unknown Service"

        for provider, (cname_substr, body_substr) in self.TAKEOVER_SIGNATURES.items():
            if cname_substr in target_lower and (req.target_http_status in {404, 400} and body_substr in body_lower):
                is_vulnerable = True
                provider_matched = provider.upper()
                break

        if is_vulnerable:
            alert = SurfaceThreatAlert(
                alert_id=f"surf-takeover-{uuid.uuid4().hex[:8]}",
                threat_type=SurfaceThreatType.DANGLING_DNS_TAKEOVER_RISK,
                asset_id=f"dns-{req.subdomain}",
                asset_name=req.subdomain,
                severity="CRITICAL",
                mitre_technique="T1584.004 - Compromise Infrastructure: DNS Server / Dangling DNS",
                details=(
                    f"Dangling DNS Subdomain Takeover vulnerability detected on '{req.subdomain}'. "
                    f"CNAME points to defunct {provider_matched} endpoint '{req.cname_target}' "
                    f"which returns HTTP {req.target_http_status} ({req.target_response_body}). "
                    f"An adversary can claim this orphan resource to hijack corporate domain traffic."
                ),
                remediation_action="Immediately delete dangling CNAME record from Route53 / Cloudflare DNS zone.",
            )
            self.alerts.append(alert)
            return alert

        return None
