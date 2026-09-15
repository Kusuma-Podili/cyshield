"""
CyberShield Enterprise - Threat Intelligence Database Models
Provides persistent relational models for Indicators of Compromise (IoCs),
APT threat actor profiles, attack campaigns, and feed ingestion provenance.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Dict, Any, Optional, List

from sqlalchemy import (
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    Text,
    JSON,
    Index,
)

from cybershield.database.session import Base


class IoCTypeEnum(str, enum.Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    CIDR = "CIDR"


class ThreatTypeEnum(str, enum.Enum):
    C2_SERVER = "C2_SERVER"
    MALWARE_HASH = "MALWARE_HASH"
    PHISHING_URL = "PHISHING_URL"
    SCANNER = "SCANNER"
    EXFILTRATION = "EXFILTRATION"
    BOTNET = "BOTNET"
    RANSOMWARE = "RANSOMWARE"
    EXPLOIT_KIT = "EXPLOIT_KIT"


class IoCRecordModel(Base):
    """
    Persistent enterprise Indicator of Compromise (IoC) ledger tracking
    hashes, IPs, domains, confidence scores, and threat actor provenance.
    """
    __tablename__ = "threat_iocs"

    id = Column(String(64), primary_key=True)  # e.g. "IOC-2026-0001"
    indicator_value = Column(String(512), nullable=False, index=True)
    indicator_type = Column(String(32), default=IoCTypeEnum.IP.value, nullable=False, index=True)
    threat_type = Column(String(64), default=ThreatTypeEnum.C2_SERVER.value, nullable=False, index=True)
    severity = Column(String(32), default="HIGH", nullable=False)
    confidence_score = Column(Integer, default=85, nullable=False, index=True)  # 0 to 100

    threat_actor = Column(String(128), nullable=True, index=True)  # e.g. "APT29", "Lazarus Group"
    campaign = Column(String(128), nullable=True, index=True)      # e.g. "SolarWinds Supply Chain"
    mitre_tactics = Column(JSON, default=list, nullable=False)     # e.g. ["Command and Control", "Initial Access"]
    source_feed = Column(String(128), default="INTERNAL_SOC", nullable=False)

    is_active = Column(Boolean, default=True, nullable=False, index=True)
    hits_count = Column(Integer, default=0, nullable=False)

    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("idx_ioc_type_val", "indicator_type", "indicator_value"),
        Index("idx_ioc_active_conf", "is_active", "confidence_score"),
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize IoC record to dictionary."""
        return {
            "id": self.id,
            "indicator_value": self.indicator_value,
            "indicator_type": self.indicator_type,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "confidence_score": self.confidence_score,
            "threat_actor": self.threat_actor,
            "campaign": self.campaign,
            "mitre_tactics": self.mitre_tactics or [],
            "source_feed": self.source_feed,
            "is_active": self.is_active,
            "hits_count": self.hits_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


class ThreatActorModel(Base):
    """
    Nation-state and cybercrime Advanced Persistent Threat (APT) actor profiles.
    """
    __tablename__ = "threat_actors"

    id = Column(String(64), primary_key=True)  # e.g. "ACTOR-APT29"
    name = Column(String(128), unique=True, nullable=False, index=True)
    aliases = Column(JSON, default=list, nullable=False)  # ["Cozy Bear", "Nobelium"]
    origin_country = Column(String(64), default="UNKNOWN", nullable=False)
    motivation = Column(String(64), default="ESPIONAGE", nullable=False)  # ESPIONAGE, FINANCIAL, SABOTAGE
    targeted_sectors = Column(JSON, default=list, nullable=False)
    known_ttps = Column(JSON, default=list, nullable=False)  # MITRE technique codes ["T1078", "T1566"]
    description = Column(Text, nullable=False)
    active_campaigns = Column(JSON, default=list, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize threat actor profile."""
        return {
            "id": self.id,
            "name": self.name,
            "aliases": self.aliases or [],
            "origin_country": self.origin_country,
            "motivation": self.motivation,
            "targeted_sectors": self.targeted_sectors or [],
            "known_ttps": self.known_ttps or [],
            "description": self.description,
            "active_campaigns": self.active_campaigns or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ThreatCampaignModel(Base):
    """
    Coordinated cyber attack campaigns linking multiple incidents, assets, and IoCs.
    """
    __tablename__ = "threat_campaigns"

    id = Column(String(64), primary_key=True)  # e.g. "CAMP-2026-01"
    name = Column(String(128), unique=True, nullable=False, index=True)
    associated_actor = Column(String(128), nullable=True)
    target_industries = Column(JSON, default=list, nullable=False)
    objective = Column(Text, nullable=False)
    status = Column(String(32), default="ACTIVE", nullable=False, index=True)  # ACTIVE, MONITORED, DORMANT
    first_observed = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_activity = Column(DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize campaign record."""
        return {
            "id": self.id,
            "name": self.name,
            "associated_actor": self.associated_actor,
            "target_industries": self.target_industries or [],
            "objective": self.objective,
            "status": self.status,
            "first_observed": self.first_observed.isoformat() if self.first_observed else None,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
        }
