"""
CyberShield Enterprise - Vulnerability Management Service
Orchestrates enterprise CVE catalog seeding, automated asset vulnerability discovery,
patch priority scoring, and remediation lifecycle tracking.
"""

from __future__ import annotations

import uuid
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from sqlalchemy import select, func, and_, or_, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from cybershield.database.models.vulnerabilities import (
    VulnerabilityModel,
    AssetVulnerabilityModel,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from cybershield.database.models.network import NetworkDevice, DeviceStatus
from cybershield.vulnerabilities.cvss import CVSSv31Engine

logger = logging.getLogger("cybershield.vulnerabilities.service")


class VulnerabilityService:
    """Enterprise Vulnerability Assessment & Remediation Management Service."""

    async def seed_default_vulnerabilities(self, session: AsyncSession) -> int:
        """Seed high-profile enterprise CVE records and initial asset bindings."""
        existing_count = (await session.execute(select(func.count(VulnerabilityModel.id)))).scalar_one()
        if existing_count > 0:
            return existing_count

        seeds = [
            {
                "cve_id": "CVE-2024-3094",
                "title": "XZ Utils Liblzma Upstream Backdoor Injection",
                "description": "Malicious backdoor in upstream xz/liblzma packages leading to unauthenticated SSH daemon pre-auth RCE.",
                "cwe_id": "CWE-506",
                "severity": VulnerabilitySeverity.CRITICAL.value,
                "cvss_v31_score": 10.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "scope": "CHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "HIGH",
                "availability_impact": "HIGH",
                "exploit_maturity": "FUNCTIONAL",
                "affected_products": ["xz-utils:5.6.0", "xz-utils:5.6.1", "openssh-server"],
                "remediation_guidance": "Downgrade xz-utils to 5.4.6 LTS immediately across all Linux distributions.",
                "patch_available": True,
                "active_exploit_observed": True,
                "compliance_tags": ["PCI-DSS-6.2", "NIST-CSF-PR.IP-1", "ISO-27001-A.12.6.1"],
            },
            {
                "cve_id": "CVE-2021-44228",
                "title": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
                "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP/RMI endpoints, enabling unauthenticated RCE.",
                "cwe_id": "CWE-502",
                "severity": VulnerabilitySeverity.CRITICAL.value,
                "cvss_v31_score": 10.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "scope": "CHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "HIGH",
                "availability_impact": "HIGH",
                "exploit_maturity": "HIGH",
                "affected_products": ["apache:log4j-core:2.14.1", "spring-boot:log4j2", "elastic-search"],
                "remediation_guidance": "Upgrade to Log4j 2.17.1+ or apply environment flag -Dlog4j2.formatMsgNoLookups=true.",
                "patch_available": True,
                "active_exploit_observed": True,
                "compliance_tags": ["PCI-DSS-6.2", "HIPAA-164.312", "NIST-CSF-DE.CM-8"],
            },
            {
                "cve_id": "CVE-2020-1472",
                "title": "Microsoft Netlogon Elevation of Privilege (ZeroLogon)",
                "description": "Flaw in AES-CFB8 cryptographic initialization vector allows unauthenticated attacker to impersonate any computer including Domain Controller.",
                "cwe_id": "CWE-326",
                "severity": VulnerabilitySeverity.CRITICAL.value,
                "cvss_v31_score": 10.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "scope": "CHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "HIGH",
                "availability_impact": "HIGH",
                "exploit_maturity": "HIGH",
                "affected_products": ["windows_server:2016", "windows_server:2019", "windows_server:2022"],
                "remediation_guidance": "Enforce Secure RPC for all Netlogon connections via Active Directory Group Policy.",
                "patch_available": True,
                "active_exploit_observed": True,
                "compliance_tags": ["PCI-DSS-2.2", "NIST-CSF-PR.AC-1", "ISO-27001-A.9.2.1"],
            },
            {
                "cve_id": "CVE-2017-0144",
                "title": "Microsoft SMBv1 Remote Code Execution (EternalBlue)",
                "description": "Buffer overflow vulnerability in Microsoft SMBv1 protocol allows remote attackers to execute arbitrary shellcode via crafted SMB packets.",
                "cwe_id": "CWE-120",
                "severity": VulnerabilitySeverity.CRITICAL.value,
                "cvss_v31_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "scope": "UNCHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "HIGH",
                "availability_impact": "HIGH",
                "exploit_maturity": "HIGH",
                "affected_products": ["windows_server:2008", "windows_7", "windows_10_prior_1703"],
                "remediation_guidance": "Disable SMBv1 completely and deploy Microsoft Security Bulletin MS17-010 patch.",
                "patch_available": True,
                "active_exploit_observed": True,
                "compliance_tags": ["PCI-DSS-6.2", "HIPAA-164.308", "NIST-CSF-PR.IP-1"],
            },
            {
                "cve_id": "CVE-2023-4966",
                "title": "Citrix Bleed NetScaler Sensitive Session Information Disclosure",
                "description": "Buffer overflow in NetScaler ADC and Gateway allows unauthorized exfiltration of active authentication tokens bypassing MFA.",
                "cwe_id": "CWE-119",
                "severity": VulnerabilitySeverity.HIGH.value,
                "cvss_v31_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "scope": "UNCHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "NONE",
                "availability_impact": "NONE",
                "exploit_maturity": "HIGH",
                "affected_products": ["citrix:netscaler_adc:13.1", "citrix:netscaler_gateway:13.0"],
                "remediation_guidance": "Apply Citrix vendor patch and terminate all active ICA/AAA user sessions.",
                "patch_available": True,
                "active_exploit_observed": True,
                "compliance_tags": ["PCI-DSS-8.3", "NIST-CSF-PR.AC-7", "ISO-27001-A.9.4.2"],
            },
            {
                "cve_id": "CVE-2014-0160",
                "title": "OpenSSL Heartbleed TLS Information Leaking",
                "description": "Missing bounds check in TLS heartbeat extension allows remote unauthenticated attackers to read up to 64KB of server memory.",
                "cwe_id": "CWE-125",
                "severity": VulnerabilitySeverity.HIGH.value,
                "cvss_v31_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "scope": "UNCHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "NONE",
                "availability_impact": "NONE",
                "exploit_maturity": "HIGH",
                "affected_products": ["openssl:1.0.1", "openssl:1.0.1f"],
                "remediation_guidance": "Upgrade OpenSSL to version 1.0.1g or rebuild with -DOPENSSL_NO_HEARTBEATS.",
                "patch_available": True,
                "active_exploit_observed": False,
                "compliance_tags": ["PCI-DSS-4.1", "HIPAA-164.312", "ISO-27001-A.10.1.1"],
            }
        ]

        for s in seeds:
            vuln = VulnerabilityModel(
                id=s["cve_id"],
                cve_id=s["cve_id"],
                title=s["title"],
                description=s["description"],
                cwe_id=s["cwe_id"],
                severity=s["severity"],
                cvss_v31_score=s["cvss_v31_score"],
                cvss_vector=s["cvss_vector"],
                attack_vector=s["attack_vector"],
                attack_complexity=s["attack_complexity"],
                privileges_required=s["privileges_required"],
                user_interaction=s["user_interaction"],
                scope=s["scope"],
                confidentiality_impact=s["confidentiality_impact"],
                integrity_impact=s["integrity_impact"],
                availability_impact=s["availability_impact"],
                exploit_maturity=s["exploit_maturity"],
                affected_products=s["affected_products"],
                remediation_guidance=s["remediation_guidance"],
                patch_available=s["patch_available"],
                active_exploit_observed=s["active_exploit_observed"],
                compliance_tags=s["compliance_tags"],
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            session.add(vuln)

        await session.commit()
        logger.info("Default enterprise CVE catalog seeded with %d vulnerabilities.", len(seeds))

        # Perform initial scan binding on existing seeded devices
        await self.scan_assets_for_vulnerabilities(session)
        return len(seeds)

    async def list_vulnerabilities(
        self,
        session: AsyncSession,
        search: Optional[str] = None,
        severity: Optional[str] = None,
        min_cvss: Optional[float] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> Dict[str, Any]:
        """Fetch filtered and paginated vulnerabilities."""
        stmt = select(VulnerabilityModel)
        conditions = []

        if search:
            s_term = f"%{search.strip().lower()}%"
            conditions.append(
                or_(
                    func.lower(VulnerabilityModel.cve_id).like(s_term),
                    func.lower(VulnerabilityModel.title).like(s_term),
                    func.lower(VulnerabilityModel.description).like(s_term),
                )
            )

        if severity:
            conditions.append(VulnerabilityModel.severity == severity.upper())

        if min_cvss is not None:
            conditions.append(VulnerabilityModel.cvss_v31_score >= min_cvss)

        if conditions:
            stmt = stmt.where(and_(*conditions))

        # Count total
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await session.execute(count_stmt)).scalar_one()

        # Paginate
        stmt = stmt.order_by(VulnerabilityModel.cvss_v31_score.desc())
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)

        result = await session.execute(stmt)
        items = result.scalars().all()

        return {
            "items": [v.to_dict() for v in items],
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": max(1, (total + page_size - 1) // page_size),
        }

    async def get_vulnerability_by_cve(
        self,
        session: AsyncSession,
        cve_id: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch CVE detail dossier including linked assets."""
        stmt = (
            select(VulnerabilityModel)
            .options(selectinload(VulnerabilityModel.asset_associations))
            .where(func.upper(VulnerabilityModel.cve_id) == cve_id.strip().upper())
        )
        res = await session.execute(stmt)
        vuln = res.scalar_one_or_none()
        if not vuln:
            return None

        data = vuln.to_dict()
        data["associated_assets"] = [a.to_dict() for a in vuln.asset_associations]
        return data

    async def create_vulnerability(
        self,
        session: AsyncSession,
        cve_id: str,
        title: str,
        description: str,
        cwe_id: Optional[str],
        severity: str,
        cvss_v31_score: float,
        cvss_vector: str,
        affected_products: List[str],
        remediation_guidance: str,
        patch_available: bool = True,
        active_exploit_observed: bool = False,
        compliance_tags: Optional[List[str]] = None,
    ) -> VulnerabilityModel:
        """Create a custom or ingested CVE record."""
        existing = await self.get_vulnerability_by_cve(session, cve_id)
        if existing:
            raise ValueError(f"Vulnerability '{cve_id}' already exists in catalog.")

        vuln = VulnerabilityModel(
            id=cve_id.upper(),
            cve_id=cve_id.upper(),
            title=title,
            description=description,
            cwe_id=cwe_id,
            severity=severity.upper(),
            cvss_v31_score=cvss_v31_score,
            cvss_vector=cvss_vector,
            affected_products=affected_products or [],
            remediation_guidance=remediation_guidance,
            patch_available=patch_available,
            active_exploit_observed=active_exploit_observed,
            compliance_tags=compliance_tags or ["NIST-CSF-PR.IP-1"],
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        session.add(vuln)
        await session.commit()
        await session.refresh(vuln)
        return vuln

    async def scan_assets_for_vulnerabilities(
        self,
        session: AsyncSession,
        device_id: Optional[str] = None,
        subnet_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Automated vulnerability assessment scanner.
        Matches device open ports, OS family, and services against known CVE signatures,
        calculates composite patch priorities, and binds asset vulnerabilities.
        """
        # 1. Fetch devices to scan
        stmt = select(NetworkDevice)
        if device_id:
            stmt = stmt.where(NetworkDevice.id == device_id)
        elif subnet_id:
            stmt = stmt.where(NetworkDevice.subnet_id == subnet_id)

        devices = (await session.execute(stmt)).scalars().all()
        if not devices:
            return {"scanned_devices": 0, "findings_generated": 0, "findings": []}

        # 2. Fetch CVE catalog
        cves = (await session.execute(select(VulnerabilityModel))).scalars().all()
        cve_map = {c.cve_id: c for c in cves}

        findings_created = 0
        findings_list = []

        for dev in devices:
            ports = dev.open_ports or []
            os_fam = (dev.os_family or "").upper()

            matched_cves: List[Tuple[str, int, str]] = []

            # Match signatures based on exposed services
            if 445 in ports:
                # SMB port exposed -> EternalBlue / ZeroLogon risk
                if "CVE-2017-0144" in cve_map:
                    matched_cves.append(("CVE-2017-0144", 445, "Microsoft SMBv1"))
                if "CVE-2020-1472" in cve_map and "WINDOWS" in os_fam:
                    matched_cves.append(("CVE-2020-1472", 445, "Netlogon RPC"))

            if 22 in ports and ("LINUX" in os_fam or "UNIX" in os_fam):
                # SSH on Linux -> XZ backdoor check
                if "CVE-2024-3094" in cve_map:
                    matched_cves.append(("CVE-2024-3094", 22, "OpenSSH with liblzma"))

            if 8080 in ports or 8443 in ports or 80 in ports:
                # Web Application ports -> Log4Shell / Heartbleed / Citrix Bleed
                if "CVE-2021-44228" in cve_map:
                    matched_cves.append(("CVE-2021-44228", 8080 if 8080 in ports else 80, "Java Web App / Log4j2"))
                if "CVE-2014-0160" in cve_map:
                    matched_cves.append(("CVE-2014-0160", 443 if 443 in ports else 8443, "OpenSSL TLS Heartbeat"))

            if 443 in ports and ("CVE-2023-4966" in cve_map):
                matched_cves.append(("CVE-2023-4966", 443, "NetScaler AAA Portal"))

            # Fallback: if no port matches but device is critical, assign Log4Shell check
            if not matched_cves and dev.is_critical_asset and "CVE-2021-44228" in cve_map:
                matched_cves.append(("CVE-2021-44228", 443, "Enterprise Service"))

            for cve_code, port, srv in matched_cves:
                cve_obj = cve_map[cve_code]
                binding_id = f"VULN-{dev.id[:12]}-{cve_code.replace('-', '')[:10]}"

                # Check if binding already exists
                existing = (
                    await session.execute(
                        select(AssetVulnerabilityModel).where(AssetVulnerabilityModel.id == binding_id)
                    )
                ).scalar_one_or_none()

                # Calculate Composite Patch Priority Score (0 - 100)
                # Weighted CVSS (50%) + Asset Criticality (25%) + Active Exploit (25%)
                cvss_contrib = cve_obj.cvss_v31_score * 5.0
                crit_contrib = 25.0 if dev.is_critical_asset else 10.0
                exploit_contrib = 25.0 if cve_obj.active_exploit_observed else 5.0
                patch_priority = min(100.0, cvss_contrib + crit_contrib + exploit_contrib)

                if not existing:
                    binding = AssetVulnerabilityModel(
                        id=binding_id,
                        device_id=dev.id,
                        cve_id=cve_code,
                        port=port,
                        service_name=srv,
                        status=VulnerabilityStatus.DISCOVERED.value,
                        patch_priority_score=patch_priority,
                        analyst_notes=f"Automated scan match on {srv} (Port {port}).",
                        discovered_at=datetime.utcnow(),
                        updated_at=datetime.utcnow(),
                    )
                    session.add(binding)
                    findings_created += 1
                else:
                    existing.patch_priority_score = patch_priority
                    existing.updated_at = datetime.utcnow()
                    findings_created += 1

                findings_list.append({
                    "id": binding_id,
                    "device_id": dev.id,
                    "hostname": dev.hostname,
                    "cve_id": cve_code,
                    "port": port,
                    "patch_priority_score": patch_priority,
                })

        await session.commit()
        return {
            "scanned_devices": len(devices),
            "findings_generated": findings_created,
            "findings": findings_list,
        }

    async def list_asset_vulnerabilities(
        self,
        session: AsyncSession,
        device_id: Optional[str] = None,
        cve_id: Optional[str] = None,
        status: Optional[str] = None,
        page: int = 1,
        page_size: int = 25,
    ) -> Dict[str, Any]:
        """Fetch asset vulnerability bindings."""
        stmt = (
            select(AssetVulnerabilityModel)
            .options(
                selectinload(AssetVulnerabilityModel.vulnerability),
                selectinload(AssetVulnerabilityModel.device),
            )
        )
        conditions = []
        if device_id:
            conditions.append(AssetVulnerabilityModel.device_id == device_id)
        if cve_id:
            conditions.append(func.upper(AssetVulnerabilityModel.cve_id) == cve_id.upper())
        if status:
            conditions.append(AssetVulnerabilityModel.status == status.upper())

        if conditions:
            stmt = stmt.where(and_(*conditions))

        # Count total
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await session.execute(count_stmt)).scalar_one()

        stmt = stmt.order_by(AssetVulnerabilityModel.patch_priority_score.desc())
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)

        res = await session.execute(stmt)
        items = res.scalars().all()

        return {
            "items": [item.to_dict() for item in items],
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": max(1, (total + page_size - 1) // page_size),
        }

    async def update_asset_vuln_status(
        self,
        session: AsyncSession,
        binding_id: str,
        new_status: str,
        analyst_notes: Optional[str] = None,
    ) -> Optional[AssetVulnerabilityModel]:
        """Transition asset vulnerability through remediation lifecycle."""
        stmt = (
            select(AssetVulnerabilityModel)
            .options(
                selectinload(AssetVulnerabilityModel.vulnerability),
                selectinload(AssetVulnerabilityModel.device),
            )
            .where(AssetVulnerabilityModel.id == binding_id)
        )
        res = await session.execute(stmt)
        binding = res.scalar_one_or_none()
        if not binding:
            return None

        binding.status = new_status.upper()
        if analyst_notes:
            existing_note = binding.analyst_notes or ""
            binding.analyst_notes = f"{existing_note}\n[{datetime.utcnow().strftime('%Y-%m-%d %H:%M')}] {analyst_notes}".strip()

        if new_status.upper() in (VulnerabilityStatus.CLOSED.value, VulnerabilityStatus.VERIFIED.value):
            binding.remediated_at = datetime.utcnow()

        binding.updated_at = datetime.utcnow()
        await session.commit()
        await session.refresh(binding)
        return binding

    async def get_vulnerability_kpis(self, session: AsyncSession) -> Dict[str, Any]:
        """Calculate executive vulnerability posture metrics."""
        total_cves = (await session.execute(select(func.count(VulnerabilityModel.id)))).scalar_one()
        critical_cves = (
            await session.execute(
                select(func.count(VulnerabilityModel.id)).where(VulnerabilityModel.severity == VulnerabilitySeverity.CRITICAL.value)
            )
        ).scalar_one()
        high_cves = (
            await session.execute(
                select(func.count(VulnerabilityModel.id)).where(VulnerabilityModel.severity == VulnerabilitySeverity.HIGH.value)
            )
        ).scalar_one()

        total_assets_affected = (
            await session.execute(
                select(func.count(func.distinct(AssetVulnerabilityModel.device_id)))
            )
        ).scalar_one()

        unpatched_critical = (
            await session.execute(
                select(func.count(AssetVulnerabilityModel.id))
                .join(VulnerabilityModel, AssetVulnerabilityModel.cve_id == VulnerabilityModel.cve_id)
                .where(
                    and_(
                        VulnerabilityModel.severity == VulnerabilitySeverity.CRITICAL.value,
                        AssetVulnerabilityModel.status.in_([
                            VulnerabilityStatus.DISCOVERED.value,
                            VulnerabilityStatus.CONFIRMED.value,
                            VulnerabilityStatus.IN_REMEDIATION.value,
                        ])
                    )
                )
            )
        ).scalar_one()

        avg_priority_res = (
            await session.execute(select(func.avg(AssetVulnerabilityModel.patch_priority_score)))
        ).scalar_one()
        avg_priority = round(avg_priority_res or 0.0, 1)

        # Compliance mapping breakdown
        all_vulns = (await session.execute(select(VulnerabilityModel.compliance_tags))).scalars().all()
        compliance_breakdown = {"PCI-DSS": 0, "HIPAA": 0, "NIST-CSF": 0, "ISO-27001": 0}
        for tags in all_vulns:
            for t in (tags or []):
                t_u = t.upper()
                if "PCI" in t_u:
                    compliance_breakdown["PCI-DSS"] += 1
                if "HIPAA" in t_u:
                    compliance_breakdown["HIPAA"] += 1
                if "NIST" in t_u:
                    compliance_breakdown["NIST-CSF"] += 1
                if "ISO" in t_u:
                    compliance_breakdown["ISO-27001"] += 1

        return {
            "total_cves": total_cves,
            "critical_cves": critical_cves,
            "high_cves": high_cves,
            "total_vulnerable_assets": total_assets_affected,
            "unpatched_critical_assets": unpatched_critical,
            "avg_patch_priority": avg_priority,
            "compliance_breakdown": compliance_breakdown,
        }


vulnerability_service = VulnerabilityService()
