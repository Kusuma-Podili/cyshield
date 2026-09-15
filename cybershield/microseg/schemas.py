"""
Enterprise Network Microsegmentation Schemas and Models.
Defines workload tiers, declarative east-west traffic policies, target firewall formats, and drift detection.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class WorkloadTier(str, Enum):
    WEB_FRONTEND = "WEB_FRONTEND"
    APP_BACKEND = "APP_BACKEND"
    DATABASE = "DATABASE"
    MANAGEMENT_ADMIN = "MANAGEMENT_ADMIN"
    CORP_WORKSTATION = "CORP_WORKSTATION"
    PCI_ZONE = "PCI_ZONE"


class NetworkAction(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    LOG_AND_DROP = "LOG_AND_DROP"


class TargetFirewallFormat(str, Enum):
    NFTABLES = "NFTABLES"
    IPTABLES = "IPTABLES"
    WINDOWS_FIREWALL = "WINDOWS_FIREWALL"
    KUBERNETES_NETWORK_POLICY = "KUBERNETES_NETWORK_POLICY"
    AWS_SECURITY_GROUP = "AWS_SECURITY_GROUP"


class MicrosegmentationRule(BaseModel):
    """Declarative Zero Trust policy controlling east-west traffic between workload tiers."""
    rule_id: str
    name: str
    source_tier: WorkloadTier
    destination_tier: WorkloadTier
    protocol: str = "TCP"  # TCP, UDP, ICMP, ANY
    port_range: str = "443"  # e.g., "5432", "8000-8080", "ANY"
    action: NetworkAction = NetworkAction.ALLOW
    description: str = ""
    enabled: bool = True


class CompileRequest(BaseModel):
    """Request to compile declarative policies into native firewall syntax."""
    target_format: TargetFirewallFormat
    rule_ids: Optional[List[str]] = None


class CompiledFirewallRuleset(BaseModel):
    """Output containing compiled native firewall configuration script."""
    target_format: TargetFirewallFormat
    rule_count: int
    generated_code: str
    compiled_at: datetime = Field(default_factory=datetime.utcnow)


class FlowEvaluationRequest(BaseModel):
    """Telemetry of an observed network flow to test against microsegmentation policy."""
    src_ip: str
    dst_ip: str
    src_tier: WorkloadTier
    dst_tier: WorkloadTier
    protocol: str = "TCP"
    dst_port: int


class FlowViolationEvent(BaseModel):
    """Alert emitted when an east-west flow violates least-privilege microsegmentation boundaries."""
    violation_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    src_ip: str
    dst_ip: str
    src_tier: WorkloadTier
    dst_tier: WorkloadTier
    dst_port: int
    protocol: str
    reason: str
    severity: str = "HIGH"
