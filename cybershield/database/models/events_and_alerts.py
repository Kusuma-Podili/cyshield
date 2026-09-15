"""
CyberShield Enterprise - Security Events & Alerts Database Models
ORM entities for SIEM normalized telemetry events, triageable alerts,
alert deduplication caches, and suppression rules.
"""

import enum
from datetime import datetime
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
    Enum as SQLEnum,
    Index
)
from sqlalchemy.orm import relationship
from cybershield.database.session import Base


class EventSeverity(str, enum.Enum):
    """Normalized Event & Alert Severity Levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventType(str, enum.Enum):
    """Categorized Enterprise Security Event Types."""
    PROCESS_CREATION = "PROCESS_CREATION"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    AUTHENTICATION_ATTEMPT = "AUTHENTICATION_ATTEMPT"
    FILE_MODIFICATION = "FILE_MODIFICATION"
    DNS_QUERY = "DNS_QUERY"
    WEB_REQUEST = "WEB_REQUEST"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    REGISTRY_MODIFICATION = "REGISTRY_MODIFICATION"
    SECURITY_LOG_CLEARED = "SECURITY_LOG_CLEARED"
    FLOW_STATISTICS = "FLOW_STATISTICS"


class LogSourceType(str, enum.Enum):
    """Originating Telemetry Log Sources."""
    SYSMON = "SYSMON"
    SYSLOG = "SYSLOG"
    ZEEK = "ZEEK"
    SURICATA = "SURICATA"
    WINDOWS_EVENT = "WINDOWS_EVENT"
    WEB_ACCESS = "WEB_ACCESS"
    NETFLOW = "NETFLOW"
    CLOUDTRAIL = "CLOUDTRAIL"
    API_TELEMETRY = "API_TELEMETRY"


class AlertStatus(str, enum.Enum):
    """SOC Analyst Alert Lifecycle Status."""
    NEW = "NEW"
    ASSIGNED = "ASSIGNED"
    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SUPPRESSED = "SUPPRESSED"


class DetectionEngineType(str, enum.Enum):
    """Engine responsible for raising detection alert."""
    SIGMA = "SIGMA"
    YARA = "YARA"
    UEBA = "UEBA"
    ANOMALY_ISOLATION_FOREST = "ANOMALY_ISOLATION_FOREST"
    NLP_INJECTION = "NLP_INJECTION"
    STATIC_BINARY = "STATIC_BINARY"
    MITRE_CORRELATION = "MITRE_CORRELATION"
    SURICATA = "SURICATA"
    CUSTOM_RULE = "CUSTOM_RULE"


class SecurityEventModel(Base):
    """Enterprise SIEM Normalized Security Telemetry Event."""
    __tablename__ = "security_events"

    id = Column(String(64), primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    event_type = Column(SQLEnum(EventType), default=EventType.NETWORK_CONNECTION, nullable=False, index=True)
    severity = Column(SQLEnum(EventSeverity), default=EventSeverity.INFO, nullable=False, index=True)
    source_type = Column(SQLEnum(LogSourceType), default=LogSourceType.SYSLOG, nullable=False, index=True)

    # Network Dimensions
    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True, index=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True, index=True)
    protocol = Column(String(16), default="TCP", nullable=True)

    # Host & Identity Dimensions
    host_name = Column(String(128), nullable=True, index=True)
    host_id = Column(String(64), ForeignKey("network_devices.id", ondelete="SET NULL"), nullable=True, index=True)
    user_name = Column(String(128), nullable=True, index=True)
    domain = Column(String(128), nullable=True)

    # Process & Execution Dimensions
    process_name = Column(String(256), nullable=True, index=True)
    process_id = Column(Integer, nullable=True)
    parent_process_name = Column(String(256), nullable=True)
    command_line = Column(Text, nullable=True)
    process_hash = Column(String(64), nullable=True, index=True)

    # File & Payload Dimensions
    file_path = Column(String(512), nullable=True)
    file_hash_sha256 = Column(String(64), nullable=True, index=True)

    # Message & Raw Telemetry
    message = Column(Text, nullable=False)
    raw_log = Column(Text, nullable=True)
    parsed_fields = Column(JSON, default=dict)
    is_anomalous = Column(Boolean, default=False, index=True)
    anomaly_score = Column(Float, default=0.0)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    alerts = relationship("AlertModel", back_populates="source_event")

    __table_args__ = (
        Index("idx_ev_time_type", "timestamp", "event_type"),
        Index("idx_ev_host_user", "host_name", "user_name"),
        Index("idx_ev_src_dst_ip", "source_ip", "destination_ip"),
    )

    def __repr__(self):
        return f"<SecurityEvent id={self.id} type={self.event_type} host={self.host_name} sev={self.severity}>"


class AlertModel(Base):
    """Actionable Security Alert in the SOC Triage Queue."""
    __tablename__ = "security_alerts"

    id = Column(String(64), primary_key=True, index=True)
    alert_code = Column(String(32), nullable=False, unique=True, index=True)  # e.g. ALT-2026-0001
    title = Column(String(256), nullable=False, index=True)
    description = Column(Text, nullable=False)
    severity = Column(SQLEnum(EventSeverity), default=EventSeverity.MEDIUM, nullable=False, index=True)
    status = Column(SQLEnum(AlertStatus), default=AlertStatus.NEW, nullable=False, index=True)
    engine = Column(SQLEnum(DetectionEngineType), default=DetectionEngineType.SIGMA, nullable=False, index=True)
    rule_id = Column(String(128), nullable=False, index=True)
    rule_name = Column(String(256), nullable=False)

    # Source Event Link
    source_event_id = Column(String(64), ForeignKey("security_events.id", ondelete="SET NULL"), nullable=True, index=True)

    # Entity Context
    host_name = Column(String(128), nullable=True, index=True)
    host_ip = Column(String(45), nullable=True, index=True)
    user_name = Column(String(128), nullable=True, index=True)

    # MITRE ATT&CK Mapping
    mitre_tactic = Column(String(64), nullable=True, index=True)
    mitre_technique_id = Column(String(32), nullable=True, index=True)
    mitre_technique_name = Column(String(128), nullable=True)

    # Triage & Analyst Assignment
    assigned_analyst_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    assigned_analyst_name = Column(String(128), nullable=True)
    incident_id = Column(String(64), nullable=True, index=True)

    # Deduplication & Volume Management
    deduplication_hash = Column(String(64), nullable=False, index=True)
    occurrence_count = Column(Integer, default=1)
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Notes & Suppression
    triage_notes = Column(JSON, default=list)  # list of {author, timestamp, note}
    suppressed = Column(Boolean, default=False, index=True)
    suppression_reason = Column(String(256), nullable=True)

    # Resolution
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(128), nullable=True)
    resolution_summary = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    source_event = relationship("SecurityEventModel", back_populates="alerts")

    __table_args__ = (
        Index("idx_alt_status_sev", "status", "severity"),
        Index("idx_alt_dedup_last", "deduplication_hash", "last_seen"),
    )

    def __repr__(self):
        return f"<Alert id={self.id} code={self.alert_code} title='{self.title}' sev={self.severity} status={self.status}>"


class AlertSuppressionRuleModel(Base):
    """Dynamic Filter Rule to Suppress Benign Known-Alert Noise."""
    __tablename__ = "alert_suppression_rules"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    rule_name_pattern = Column(String(256), nullable=True)
    host_pattern = Column(String(128), nullable=True)
    user_pattern = Column(String(128), nullable=True)
    reason = Column(Text, nullable=False)
    created_by = Column(String(128), nullable=False)
    is_active = Column(Boolean, default=True, index=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<AlertSuppressionRule id={self.id} name={self.name} active={self.is_active}>"
