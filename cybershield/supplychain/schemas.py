"""
Software Supply Chain Risk & Dependency Vulnerability Graph Schemas.
Models package ecosystems, typosquatting vectors, malicious install hooks, and dependency graphs.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PackageEcosystem(str, Enum):
    NPM = "NPM"
    PYPI = "PYPI"
    MAVEN = "MAVEN"
    GOLANG = "GOLANG"
    CARGO = "CARGO"


class SupplyChainRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SupplyChainThreatType(str, Enum):
    TYPOSQUATTING = "TYPOSQUATTING"
    DEPENDENCY_CONFUSION = "DEPENDENCY_CONFUSION"
    MALICIOUS_INSTALL_HOOK = "MALICIOUS_INSTALL_HOOK"
    POISONED_PACKAGE = "POISONED_PACKAGE"
    UNPINNED_VERSION = "UNPINNED_VERSION"
    RESTRICTIVE_LICENSE = "RESTRICTIVE_LICENSE"


class DependencyPackage(BaseModel):
    """Represent an individual dependency node in the project graph."""
    name: str
    version: str
    ecosystem: PackageEcosystem
    is_direct: bool = True
    license_type: Optional[str] = "MIT"
    dependencies: List[str] = Field(default_factory=list)


class SupplyChainFinding(BaseModel):
    """Specific supply chain security defect or threat discovered in manifest."""
    finding_id: str
    threat_type: SupplyChainThreatType
    severity: SupplyChainRiskLevel
    package_name: str
    installed_version: Optional[str] = None
    target_legitimate_package: Optional[str] = None
    description: str
    remediation: str


class SupplyChainScanRequest(BaseModel):
    """Request payload for scanning package dependency manifests."""
    ecosystem: PackageEcosystem
    manifest_filename: str
    manifest_content: str  # Raw content of package.json, requirements.txt, etc.


class SupplyChainScanResult(BaseModel):
    """Consolidated supply chain security assessment report."""
    scan_id: str
    ecosystem: PackageEcosystem
    manifest_filename: str
    total_packages_identified: int
    direct_dependencies: int
    transitive_depth: int
    findings: List[SupplyChainFinding] = Field(default_factory=list)
    risk_score: float = 15.0  # 0 to 100
    is_build_blocked: bool = False
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
