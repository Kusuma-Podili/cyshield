"""Software Bill of Materials (SBOM) Ingestion & Vulnerability Analyzer.

Parses CycloneDX and SPDX format JSON documents, extracts components and Package URLs (PURL),
and correlates dependencies against the offline CVE/CPE knowledge base.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from cybershield.vulnerabilities.cpe_matcher import CPEMatcher
from cybershield.vulnerabilities.offline_cve_db import OfflineCVEDatabase, OfflineCVEEntry

logger = logging.getLogger("cybershield.vulnerabilities.sbom")


@dataclass
class SBOMComponent:
    name: str
    version: str
    vendor: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None
    licenses: List[str] = field(default_factory=list)


@dataclass
class SBOMVulnerabilityFinding:
    component_name: str
    installed_version: str
    cve_id: str
    cvss_base_score: float
    severity: str
    title: str
    epss_score: float
    remediation: str


@dataclass
class SBOMScanReport:
    format_type: str  # CycloneDX, SPDX, Generic
    total_components: int
    vulnerable_components_count: int
    total_cves_found: int
    critical_cves: int
    high_cves: int
    findings: List[SBOMVulnerabilityFinding] = field(default_factory=list)


class SBOMAnalyzer:
    """Enterprise SBOM parser and local vulnerability assessor."""

    @classmethod
    def parse_sbom(cls, sbom_raw: str) -> List[SBOMComponent]:
        """Parse raw JSON string into normalized SBOMComponent objects."""
        components: List[SBOMComponent] = []
        try:
            doc = json.loads(sbom_raw)
        except Exception as e:
            logger.warning("Failed to parse SBOM JSON: %s", e)
            return []

        # 1. CycloneDX JSON format
        if "bomFormat" in doc and doc.get("bomFormat") == "CycloneDX":
            for c in doc.get("components", []):
                name = c.get("name", "unknown")
                version = c.get("version", "*")
                group = c.get("group", "")
                purl = c.get("purl")
                cpe = c.get("cpe")
                licenses = []
                for lic_item in c.get("licenses", []):
                    if "license" in lic_item and "id" in lic_item["license"]:
                        licenses.append(lic_item["license"]["id"])

                # Determine vendor from group or purl
                vendor = group or name
                if not group and purl and "/" in purl:
                    # pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
                    match = re.search(r"pkg:[a-zA-Z0-9]+/(?:([^/]+)/)?([^@]+)@?", purl)
                    if match and match.group(1):
                        vendor = match.group(1)

                components.append(
                    SBOMComponent(
                        name=name,
                        version=version,
                        vendor=vendor,
                        purl=purl,
                        cpe=cpe,
                        licenses=licenses,
                    )
                )
            return components

        # 2. SPDX JSON format
        if "spdxVersion" in doc or "packages" in doc:
            for p in doc.get("packages", []):
                name = p.get("name", "unknown")
                version = p.get("versionInfo", "*")
                vendor = p.get("supplier", "").replace("Organization:", "").replace("Person:", "").strip() or name
                cpe = None
                purl = None
                for ref in p.get("externalRefs", []):
                    ref_type = ref.get("referenceType", "")
                    locator = ref.get("referenceLocator", "")
                    if "cpe" in ref_type.lower():
                        cpe = locator
                    elif "purl" in ref_type.lower():
                        purl = locator

                licenses = [p.get("licenseConcluded", "NOASSERTION")]
                components.append(
                    SBOMComponent(
                        name=name,
                        version=version,
                        vendor=vendor,
                        purl=purl,
                        cpe=cpe,
                        licenses=licenses,
                    )
                )
            return components

        # 3. Generic component array
        if isinstance(doc, list):
            for item in doc:
                if isinstance(item, dict) and "name" in item:
                    components.append(
                        SBOMComponent(
                            name=item.get("name"),
                            version=item.get("version", "*"),
                            vendor=item.get("vendor", item.get("name")),
                            purl=item.get("purl"),
                            cpe=item.get("cpe"),
                            licenses=item.get("licenses", []),
                        )
                    )
            return components

        return components

    @classmethod
    def scan_sbom(cls, sbom_raw: str) -> SBOMScanReport:
        """Parse SBOM and correlate all components against offline CVE database."""
        components = cls.parse_sbom(sbom_raw)
        findings: List[SBOMVulnerabilityFinding] = []
        vulnerable_components = set()

        format_type = "Generic JSON"
        if "CycloneDX" in sbom_raw:
            format_type = "CycloneDX JSON"
        elif "spdxVersion" in sbom_raw:
            format_type = "SPDX JSON"

        for comp in components:
            # Query offline database for matching vulnerabilities
            matched_cves = OfflineCVEDatabase.find_vulnerabilities_for_package(
                vendor=comp.vendor or comp.name,
                product=comp.name,
                version=comp.version,
            )

            if matched_cves:
                vulnerable_components.add(f"{comp.name}@{comp.version}")
                for cve in matched_cves:
                    findings.append(
                        SBOMVulnerabilityFinding(
                            component_name=comp.name,
                            installed_version=comp.version,
                            cve_id=cve.cve_id,
                            cvss_base_score=cve.cvss_base_score,
                            severity=cve.severity,
                            title=cve.title,
                            epss_score=cve.epss_score,
                            remediation=cve.remediation,
                        )
                    )

        crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")

        return SBOMScanReport(
            format_type=format_type,
            total_components=len(components),
            vulnerable_components_count=len(vulnerable_components),
            total_cves_found=len(findings),
            critical_cves=crit_count,
            high_cves=high_count,
            findings=findings,
        )
