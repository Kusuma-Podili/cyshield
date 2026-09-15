"""
CyberShield Enterprise - Incidents & Detection Rules Database Models
Defines ORM entities for multi-stage security incidents, forensic timeline
evidence, detection rules (Sigma & YARA), and automated SOAR action records.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy import (
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    Text,
    JSON,
    ForeignKey,
    Index
)
from sqlalchemy.orm import relationship
from cybershield.database.session import Base


class IncidentSeverity(str, enum.Enum):
    """Incident Priority & Impact Rating."""
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, enum.Enum):
    """Incident Management Lifecycle Stages."""
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    CONTAINED = "CONTAINED"
    ERADICATED = "ERADICATED"
    RECOVERED = "RECOVERED"
    CLOSED = "CLOSED"


class IncidentType(str, enum.Enum):
    """Categorized Threat Archetypes."""
    MALWARE_INFECTION = "MALWARE_INFECTION"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"
    APT_CAMPAIGN = "APT_CAMPAIGN"
    RANSOMWARE = "RANSOMWARE"
    INSIDER_THREAT = "INSIDER_THREAT"
    POLICY_VIOLATION = "POLICY_VIOLATION"


class KillChainPhase(str, enum.Enum):
    """Cyber Kill Chain & MITRE ATT&CK Progression."""
    RECONNAISSANCE = "RECONNAISSANCE"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DISCOVERY = "DISCOVERY"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COLLECTION = "COLLECTION"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    EXFILTRATION = "EXFILTRATION"
    IMPACT = "IMPACT"


class RuleType(str, enum.Enum):
    """Engine Format of Detection Rule."""
    SIGMA = "SIGMA"
    YARA = "YARA"
    BEHAVIORAL = "BEHAVIORAL"
    CORRELATION = "CORRELATION"


class IncidentModel(Base):
    """
    Security Incident Entity representing correlated multi-stage cyber attack campaigns.
    Aggregates impacted host assets, affected identities, and chained detection alerts.
    """
    __tablename__ = "incidents"

    id = Column(String(64), primary_key=True, index=True)
    title = Column(String(256), nullable=False)
    summary = Column(Text, nullable=False)
    severity = Column(String(32), default=IncidentSeverity.MEDIUM.value, nullable=False, index=True)
    status = Column(String(32), default=IncidentStatus.OPEN.value, nullable=False, index=True)
    incident_type = Column(String(64), default=IncidentType.MALWARE_INFECTION.value, nullable=False, index=True)
    kill_chain_phase = Column(String(64), default=KillChainPhase.EXECUTION.value, nullable=False, index=True)
    lead_analyst = Column(String(128), default="unassigned", nullable=False)
    
    impacted_hosts = Column(JSON, default=list, nullable=False)
    impacted_users = Column(JSON, default=list, nullable=False)
    associated_alert_ids = Column(JSON, default=list, nullable=False)
    assigned_playbook = Column(String(128), nullable=True)
    root_cause = Column(Text, nullable=True)
    containment_actions_taken = Column(JSON, default=list, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    closed_at = Column(DateTime, nullable=True)

    # Relationship to timeline events
    timeline_events = relationship(
        "IncidentTimelineModel",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentTimelineModel.timestamp.desc()",
        lazy="selectin",
    )

    __table_args__ = (
        Index("idx_incident_status_severity", "status", "severity"),
        Index("idx_incident_type_phase", "incident_type", "kill_chain_phase"),
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert ORM model to dictionary for API serialization."""
        timeline_count = 0
        if "timeline_events" in self.__dict__ and self.timeline_events:
            timeline_count = len(self.timeline_events)

        return {
            "id": self.id,
            "title": self.title,
            "summary": self.summary,
            "severity": self.severity,
            "status": self.status,
            "incident_type": self.incident_type,
            "kill_chain_phase": self.kill_chain_phase,
            "lead_analyst": self.lead_analyst,
            "impacted_hosts": self.impacted_hosts or [],
            "impacted_users": self.impacted_users or [],
            "associated_alert_ids": self.associated_alert_ids or [],
            "assigned_playbook": self.assigned_playbook,
            "root_cause": self.root_cause,
            "containment_actions_taken": self.containment_actions_taken or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "timeline_count": timeline_count,
        }


class IncidentTimelineModel(Base):
    """
    Forensic timeline log record tracking analyst investigations,
    containment actions, and automated SOAR playbook execution.
    """
    __tablename__ = "incident_timeline"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(64), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    author = Column(String(128), nullable=False)
    action_type = Column(String(64), nullable=False)  # TRIAGE, CONTAINMENT, NOTE, SOAR_ACTION, STATUS_CHANGE
    description = Column(Text, nullable=False)
    evidence_reference = Column(String(256), nullable=True)

    incident = relationship("IncidentModel", back_populates="timeline_events")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "author": self.author,
            "action_type": self.action_type,
            "description": self.description,
            "evidence_reference": self.evidence_reference,
        }


class DetectionRuleModel(Base):
    """
    Database entity for Sigma and YARA detection rules, supporting live editing,
    compilation AST tracking, and match telemetry counters.
    """
    __tablename__ = "detection_rules"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    rule_type = Column(String(32), default=RuleType.SIGMA.value, nullable=False, index=True)
    severity = Column(String(32), default=IncidentSeverity.MEDIUM.value, nullable=False, index=True)
    mitre_tactics = Column(JSON, default=list, nullable=False)
    mitre_techniques = Column(JSON, default=list, nullable=False)
    raw_content = Column(Text, nullable=False)
    parsed_ast = Column(JSON, default=dict, nullable=False)
    is_enabled = Column(Boolean, default=True, nullable=False, index=True)
    match_count = Column(Integer, default=0, nullable=False)
    last_matched_at = Column(DateTime, nullable=True)
    author = Column(String(128), default="CyberShield Threat Labs", nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "rule_type": self.rule_type,
            "severity": self.severity,
            "mitre_tactics": self.mitre_tactics or [],
            "mitre_techniques": self.mitre_techniques or [],
            "raw_content": self.raw_content,
            "parsed_ast": self.parsed_ast or {},
            "is_enabled": self.is_enabled,
            "match_count": self.match_count,
            "last_matched_at": self.last_matched_at.isoformat() if self.last_matched_at else None,
            "author": self.author,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
