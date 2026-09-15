"""
CyberShield Enterprise - Vulnerability Management Database Models
Provides persistent relational models for CVE vulnerabilities, compliance mapping,
asset vulnerability bindings, patch priority scoring, and remediation lifecycles.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Dict, Any, Optional, List

from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Text,
    JSON,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import relationship

from cybershield.database.session import Base


class VulnerabilitySeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class VulnerabilityStatus(str, enum.Enum):
    DISCOVERED = "DISCOVERED"
    CONFIRMED = "CONFIRMED"
    IN_REMEDIATION = "IN_REMEDIATION"
    VERIFIED = "VERIFIED"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class VulnerabilityModel(Base):
    """
    Enterprise CVE Catalog record detailing flaw dimensions, CVSS v3.1 vectors,
    compliance controls, and vendor mitigation instructions.
    """
    __tablename__ = "vulnerabilities"

    id = Column(String(64), primary_key=True)  # CVE identifier, e.g. "CVE-2024-3094"
    cve_id = Column(String(64), unique=True, nullable=False, index=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    cwe_id = Column(String(32), nullable=True)  # e.g. "CWE-506"
    severity = Column(String(32), default=VulnerabilitySeverity.HIGH.value, nullable=False, index=True)
    
    # CVSS v3.1 Metrics
    cvss_v31_score = Column(Float, default=7.5, nullable=False, index=True)
    cvss_vector = Column(String(128), nullable=False)
    attack_vector = Column(String(32), default="NETWORK", nullable=False)
    attack_complexity = Column(String(32), default="LOW", nullable=False)
    privileges_required = Column(String(32), default="NONE", nullable=False)
    user_interaction = Column(String(32), default="NONE", nullable=False)
    scope = Column(String(32), default="UNCHANGED", nullable=False)
    confidentiality_impact = Column(String(32), default="HIGH", nullable=False)
    integrity_impact = Column(String(32), default="HIGH", nullable=False)
    availability_impact = Column(String(32), default="HIGH", nullable=False)
    exploit_maturity = Column(String(32), default="PROOF_OF_CONCEPT", nullable=False)

    # Affected Ecosystem & Guidance
    affected_products = Column(JSON, default=list, nullable=False)
    remediation_guidance = Column(Text, nullable=False)
    patch_available = Column(Boolean, default=True, nullable=False)
    active_exploit_observed = Column(Boolean, default=False, nullable=False)

    # Compliance frameworks mapping
    compliance_tags = Column(JSON, default=list, nullable=False)  # e.g. ["PCI-DSS-6.2", "HIPAA-164.308"]

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    asset_associations = relationship(
        "AssetVulnerabilityModel",
        back_populates="vulnerability",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        Index("idx_vuln_sev_score", "severity", "cvss_v31_score"),
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize vulnerability model to dictionary."""
        return {
            "id": self.id,
            "cve_id": self.cve_id,
            "title": self.title,
            "description": self.description,
            "cwe_id": self.cwe_id,
            "severity": self.severity,
            "cvss_v31_score": round(self.cvss_v31_score, 1),
            "cvss_vector": self.cvss_vector,
            "attack_vector": self.attack_vector,
            "attack_complexity": self.attack_complexity,
            "privileges_required": self.privileges_required,
            "user_interaction": self.user_interaction,
            "scope": self.scope,
            "confidentiality_impact": self.confidentiality_impact,
            "integrity_impact": self.integrity_impact,
            "availability_impact": self.availability_impact,
            "exploit_maturity": self.exploit_maturity,
            "affected_products": self.affected_products or [],
            "remediation_guidance": self.remediation_guidance,
            "patch_available": self.patch_available,
            "active_exploit_observed": self.active_exploit_observed,
            "compliance_tags": self.compliance_tags or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "associated_assets_count": len(self.asset_associations) if "asset_associations" in self.__dict__ and self.asset_associations else 0,
        }


class AssetVulnerabilityModel(Base):
    """
    Association between a managed NetworkDevice asset and an identified CVE vulnerability,
    tracking remediation lifecycles, patch priority, and verification notes.
    """
    __tablename__ = "asset_vulnerabilities"

    id = Column(String(64), primary_key=True)  # e.g. "VULN-DEV01-CVE2024"
    device_id = Column(String(64), ForeignKey("network_devices.id", ondelete="CASCADE"), nullable=False, index=True)
    cve_id = Column(String(64), ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE"), nullable=False, index=True)
    
    port = Column(Integer, nullable=True)
    service_name = Column(String(64), nullable=True)
    status = Column(String(32), default=VulnerabilityStatus.DISCOVERED.value, nullable=False, index=True)
    patch_priority_score = Column(Float, default=50.0, nullable=False, index=True)  # 0 - 100
    analyst_notes = Column(Text, nullable=True)
    
    discovered_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    remediated_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    vulnerability = relationship("VulnerabilityModel", back_populates="asset_associations", lazy="selectin")
    device = relationship("NetworkDevice", lazy="selectin")

    __table_args__ = (
        Index("idx_asset_vuln_status_priority", "status", "patch_priority_score"),
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize asset vulnerability binding."""
        device_host = self.device.hostname if ("device" in self.__dict__ and self.device) else "Unknown"
        device_ip = self.device.ip_address if ("device" in self.__dict__ and self.device) else "Unknown"
        cve_title = self.vulnerability.title if ("vulnerability" in self.__dict__ and self.vulnerability) else self.cve_id
        cve_sev = self.vulnerability.severity if ("vulnerability" in self.__dict__ and self.vulnerability) else "HIGH"
        cve_score = self.vulnerability.cvss_v31_score if ("vulnerability" in self.__dict__ and self.vulnerability) else 7.0

        return {
            "id": self.id,
            "device_id": self.device_id,
            "device_hostname": device_host,
            "device_ip": device_ip,
            "cve_id": self.cve_id,
            "cve_title": cve_title,
            "severity": cve_sev,
            "cvss_score": round(cve_score, 1),
            "port": self.port,
            "service_name": self.service_name,
            "status": self.status,
            "patch_priority_score": round(self.patch_priority_score, 1),
            "analyst_notes": self.analyst_notes,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
            "remediated_at": self.remediated_at.isoformat() if self.remediated_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
