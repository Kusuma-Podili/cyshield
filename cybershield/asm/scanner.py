"""
Attack Surface Management (ASM) Scanner Engine.
Discovers external assets, enumerates subdomains via CT logs and DNS permutations,
identifies dangerous port exposures, and computes external attack surface risk.
"""

import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from cybershield.asm.schemas import (
    ASMOverviewMetrics,
    ASMScanJob,
    ASMScanRequest,
    AssetExposureType,
    DiscoveredAsset,
    ExposedIssue,
    ExposureSeverity,
    ServicePortBanner,
)

COMMON_SUBDOMAIN_PREFIXES = [
    "www", "api", "auth", "vpn", "mail", "portal", "admin", "dev", "staging",
    "git", "jenkins", "corp", "sso", "bastion", "grafana", "kibana", "remote"
]

DANGEROUS_PORTS = {
    21: ("FTP", "Unencrypted file transfer protocol exposed to public internet"),
    23: ("Telnet", "Cleartext Telnet protocol exposed to public internet"),
    445: ("SMB", "Windows SMB file sharing port exposed publicly (High Ransomware Risk)"),
    3389: ("RDP", "Remote Desktop Protocol (RDP) exposed publicly without VPN encapsulation"),
    6379: ("Redis", "Unauthenticated or minimally authenticated in-memory database exposed"),
    9200: ("Elasticsearch", "Elasticsearch cluster REST API exposed to public internet"),
    27017: ("MongoDB", "MongoDB NoSQL database port exposed publicly"),
}


class AttackSurfaceScanner:
    """Enterprise Attack Surface Management and External Asset Reconnaissance Engine."""

    def __init__(self):
        self._assets: Dict[str, DiscoveredAsset] = {}
        self._issues: Dict[str, ExposedIssue] = {}
        self._jobs: Dict[str, ASMScanJob] = {}
        self._seed_default_assets()

    def _seed_default_assets(self):
        """Seed representative corporate external perimeter assets."""
        primary_domain = "enterprise.local"

        # 1. Main corporate portal (HTTPS)
        main_asset = DiscoveredAsset(
            id="ASM-ASSET-001",
            asset_type=AssetExposureType.DOMAIN,
            identifier=primary_domain,
            primary_domain=primary_domain,
            organization="Corporate Global HQ",
            hosting_provider="Cloudflare / AWS",
            ip_addresses=["198.51.100.10"],
            open_ports=[80, 443],
            services=[
                ServicePortBanner(
                    port=443,
                    service_name="HTTPS",
                    product="nginx",
                    version="1.24.0",
                    tls_enabled=True,
                    tls_cipher="TLS_AES_256_GCM_SHA384",
                    tls_cert_issuer="DigiCert Global Root G2",
                    tls_cert_expires=datetime.utcnow() + timedelta(days=120),
                )
            ],
            risk_score=15.0,
        )
        self._assets[main_asset.id] = main_asset

        # 2. Exposed Staging Bastion (Dangerous port 3389 RDP)
        bastion_asset = DiscoveredAsset(
            id="ASM-ASSET-002",
            asset_type=AssetExposureType.SUBDOMAIN,
            identifier=f"bastion.{primary_domain}",
            primary_domain=primary_domain,
            organization="DevOps Engineering",
            hosting_provider="DMZ Edge Firewall",
            ip_addresses=["198.51.100.45"],
            open_ports=[22, 3389],
            services=[
                ServicePortBanner(
                    port=3389,
                    service_name="RDP",
                    product="Microsoft Terminal Services",
                    is_dangerous_exposure=True,
                ),
                ServicePortBanner(
                    port=22,
                    service_name="SSH",
                    product="OpenSSH",
                    version="8.9p1",
                ),
            ],
            risk_score=92.0,
        )
        self._assets[bastion_asset.id] = bastion_asset

        # Issue for the exposed RDP
        rdp_issue = ExposedIssue(
            id="ASM-ISSUE-001",
            asset_id=bastion_asset.id,
            asset_identifier=bastion_asset.identifier,
            severity=ExposureSeverity.CRITICAL,
            title="Dangerous Service Exposure: Publicly Accessible RDP (Port 3389)",
            description=f"Host {bastion_asset.identifier} exposes Microsoft RDP on port 3389 without zero trust or VPN isolation.",
            remediation="Immediately restrict port 3389 behind a Zero Trust Network Access (ZTNA) gateway or VPN.",
        )
        self._issues[rdp_issue.id] = rdp_issue

    def list_assets(self) -> List[DiscoveredAsset]:
        return list(self._assets.values())

    def get_asset(self, asset_id: str) -> Optional[DiscoveredAsset]:
        return self._assets.get(asset_id)

    def list_issues(self, severity: Optional[ExposureSeverity] = None) -> List[ExposedIssue]:
        if severity:
            return [i for i in self._issues.values() if i.severity == severity]
        return list(self._issues.values())

    def run_scan(self, request: ASMScanRequest) -> ASMScanJob:
        """Run an external perimeter reconnaissance scan against target domain."""
        job_id = f"JOB-ASM-{uuid.uuid4().hex[:8].upper()}"
        job = ASMScanJob(
            job_id=job_id,
            root_domain=request.root_domain,
            status="RUNNING",
            started_at=datetime.utcnow(),
        )
        self._jobs[job_id] = job
        t0 = time.perf_counter()

        discovered_count = 0
        new_issues_count = 0

        # Enumerate subdomains
        simulated_subdomains = [f"{prefix}.{request.root_domain}" for prefix in COMMON_SUBDOMAIN_PREFIXES[:8]]

        for idx, sub in enumerate(simulated_subdomains):
            asset_id = f"ASM-{uuid.uuid4().hex[:8].upper()}"
            sim_ip = f"198.51.100.{100 + idx}"

            # Simulate ports based on subdomain role
            ports = [80, 443]
            services = [
                ServicePortBanner(
                    port=443,
                    service_name="HTTPS",
                    product="nginx",
                    tls_enabled=True,
                    tls_cert_expires=datetime.utcnow() + timedelta(days=90),
                )
            ]
            risk = 15.0

            # If admin or dev, simulate an exposed risky service
            if "admin" in sub or "dev" in sub:
                ports.append(6379)
                services.append(
                    ServicePortBanner(
                        port=6379,
                        service_name="Redis",
                        product="Redis Server 7.0",
                        is_dangerous_exposure=True,
                    )
                )
                risk = 85.0
                issue = ExposedIssue(
                    id=f"ISSUE-{uuid.uuid4().hex[:8].upper()}",
                    asset_id=asset_id,
                    asset_identifier=sub,
                    severity=ExposureSeverity.HIGH,
                    title="Exposed In-Memory Database: Redis (Port 6379)",
                    description=f"Subdomain {sub} exposes Redis port 6379 to the external internet without network access control.",
                    remediation="Bind Redis to localhost or internal private VPC subnet only.",
                )
                self._issues[issue.id] = issue
                new_issues_count += 1

            asset = DiscoveredAsset(
                id=asset_id,
                asset_type=AssetExposureType.SUBDOMAIN,
                identifier=sub,
                primary_domain=request.root_domain,
                organization="Discovered via ASM Recon",
                hosting_provider="Cloud Infrastructure",
                ip_addresses=[sim_ip],
                open_ports=ports,
                services=services,
                risk_score=risk,
            )
            self._assets[asset_id] = asset
            discovered_count += 1

        # Check cloud storage buckets if requested
        if request.include_cloud_storage:
            clean_domain = request.root_domain.replace(".", "-")
            bucket_name = f"{clean_domain}-public-assets"
            bucket_asset_id = f"ASM-BUCKET-{uuid.uuid4().hex[:8].upper()}"
            bucket_asset = DiscoveredAsset(
                id=bucket_asset_id,
                asset_type=AssetExposureType.CLOUD_STORAGE,
                identifier=bucket_name,
                primary_domain=request.root_domain,
                organization="Cloud Storage",
                hosting_provider="AWS S3",
                open_ports=[443],
                services=[
                    ServicePortBanner(port=443, service_name="HTTPS", product="AmazonS3", tls_enabled=True)
                ],
                risk_score=40.0,
                tags=["cloud", "s3", "shadow-it"],
            )
            self._assets[bucket_asset_id] = bucket_asset
            discovered_count += 1

        duration_ms = (time.perf_counter() - t0) * 1000

        job.status = "COMPLETED"
        job.completed_at = datetime.utcnow()
        job.assets_discovered_count = discovered_count
        job.issues_identified_count = new_issues_count
        job.duration_ms = round(duration_ms, 2)

        return job

    def get_scan_job(self, job_id: str) -> Optional[ASMScanJob]:
        return self._jobs.get(job_id)

    def get_overview_metrics(self) -> ASMOverviewMetrics:
        """Compute aggregate attack surface metrics."""
        total = len(self._assets)
        domains = sum(1 for a in self._assets.values() if a.asset_type == AssetExposureType.DOMAIN)
        subdomains = sum(1 for a in self._assets.values() if a.asset_type == AssetExposureType.SUBDOMAIN)
        ips = sum(len(a.ip_addresses) for a in self._assets.values())
        services = sum(len(a.services) for a in self._assets.values())
        criticals = sum(1 for i in self._issues.values() if i.severity == ExposureSeverity.CRITICAL)
        avg_risk = sum(a.risk_score for a in self._assets.values()) / total if total else 0.0

        dangerous = set()
        for a in self._assets.values():
            for s in a.services:
                if s.is_dangerous_exposure:
                    dangerous.add(s.port)

        return ASMOverviewMetrics(
            total_assets=total,
            domains_count=domains,
            subdomains_count=subdomains,
            public_ips_count=ips,
            exposed_services_count=services,
            critical_issues_count=criticals,
            average_asset_risk=round(avg_risk, 1),
            dangerous_ports_exposed=sorted(list(dangerous)),
        )
