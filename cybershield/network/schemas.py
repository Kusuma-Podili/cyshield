"""
CyberShield Enterprise - Network & Device Pydantic Schemas
Validates network requests, IP allocations, CIDR boundaries, and topology graphs.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator, ConfigDict
import ipaddress
import re


class DeviceBase(BaseModel):
    """Base fields for Network Device."""
    hostname: str = Field(..., min_length=2, max_length=128, description="Device FQDN or hostname")
    ip_address: str = Field(..., description="IPv4 or IPv6 address")
    mac_address: str = Field(..., description="Standard MAC address e.g. 00:1A:2B:3C:4D:5E")
    device_type: str = Field(default="WORKSTATION", description="Device category")
    os_family: str = Field(default="WINDOWS", description="Operating system family")
    os_version: Optional[str] = None
    subnet_id: Optional[str] = None
    location: Optional[str] = Field(default="Primary Datacenter", max_length=128)
    department: Optional[str] = Field(default="General Corporate", max_length=64)
    owner: Optional[str] = None
    is_critical_asset: bool = False
    open_ports: List[int] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid IP address format: {v}")

    @field_validator("mac_address")
    @classmethod
    def validate_mac(cls, v: str) -> str:
        cleaned = v.replace("-", ":").upper()
        if not re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", cleaned):
            raise ValueError(f"Invalid MAC address format: {v}. Must be XX:XX:XX:XX:XX:XX")
        return cleaned


class DeviceCreate(DeviceBase):
    """Schema for registering a new managed device."""
    agent_installed: bool = False
    agent_version: Optional[str] = None


class DeviceUpdate(BaseModel):
    """Schema for partial update of a device."""
    hostname: Optional[str] = None
    status: Optional[str] = None
    risk_score: Optional[float] = None
    subnet_id: Optional[str] = None
    location: Optional[str] = None
    owner: Optional[str] = None
    department: Optional[str] = None
    is_critical_asset: Optional[bool] = None
    open_ports: Optional[List[int]] = None
    tags: Optional[List[str]] = None


class DeviceResponse(DeviceBase):
    """Detailed response schema for a device."""
    id: str
    status: str
    risk_score: float
    agent_installed: bool
    agent_version: Optional[str] = None
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DevicePaginatedList(BaseModel):
    """Paginated collection of devices."""
    total: int
    page: int
    page_size: int
    items: List[DeviceResponse]


class SubnetBase(BaseModel):
    """Base fields for Subnet / VLAN."""
    name: str = Field(..., min_length=2, max_length=128, description="Friendly subnet title")
    cidr: str = Field(..., description="CIDR network notation e.g. 10.0.1.0/24")
    vlan_id: Optional[int] = Field(None, ge=1, le=4094, description="IEEE 802.1Q VLAN Tag")
    zone_type: str = Field(default="CORP_LAN", description="Security architecture tier")
    description: Optional[str] = None
    risk_level: str = Field(default="LOW", description="Inherent subnet risk posture")
    is_monitored: bool = True
    dns_servers: List[str] = Field(default_factory=lambda: ["10.0.3.10", "1.1.1.1"])

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        try:
            ipaddress.ip_network(v, strict=False)
            return v
        except ValueError:
            raise ValueError(f"Invalid CIDR network format: {v}")


class SubnetCreate(SubnetBase):
    """Schema for declaring a new network subnet."""
    pass


class SubnetUpdate(BaseModel):
    """Schema for modifying an existing subnet."""
    name: Optional[str] = None
    vlan_id: Optional[int] = None
    zone_type: Optional[str] = None
    description: Optional[str] = None
    risk_level: Optional[str] = None
    is_monitored: Optional[bool] = None
    dns_servers: Optional[List[str]] = None


class SubnetResponse(SubnetBase):
    """Response schema representing an enterprise subnet."""
    id: str
    gateway_ip: str
    netmask: str
    broadcast_ip: str
    total_ips: int
    allocated_ips: int
    utilization_pct: float
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
 
 
class SubnetPaginatedList(BaseModel):
    """Paginated collection of subnets."""
    total: int
    items: List[SubnetResponse]


class IPRecordResponse(BaseModel):
    """IP Address allocation record schema."""
    id: str
    ip_address: str
    subnet_id: str
    device_id: Optional[str] = None
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    allocation_type: str
    status: str
    lease_start: Optional[datetime] = None
    lease_expires: Optional[datetime] = None
    last_ping_latency_ms: Optional[float] = None
    last_active: datetime

    model_config = ConfigDict(from_attributes=True)


class IPRecordPaginatedList(BaseModel):
    """Paginated list of IP address records."""
    total: int
    page: int
    page_size: int
    items: List[IPRecordResponse]


class IPReserveRequest(BaseModel):
    """Request to statically reserve an IP within a subnet."""
    subnet_id: str
    ip_address: str
    hostname: str
    mac_address: Optional[str] = None
    notes: Optional[str] = None


class TopologyNode(BaseModel):
    """Graph vertex representing a device, gateway, or zone."""
    id: str
    label: str
    ip_address: str
    device_type: str
    status: str
    zone: str
    risk_score: float
    x: float
    y: float


class TopologyEdge(BaseModel):
    """Graph edge representing communication or physical links."""
    id: str
    source: str
    target: str
    link_type: str
    status: str
    bandwidth_mbps: int
    latency_ms: float
    load_pct: float


class TopologyGraphResponse(BaseModel):
    """Full enterprise network topology graph."""
    nodes: List[TopologyNode]
    edges: List[TopologyEdge]
    total_nodes: int
    total_edges: int
    healthy_links_pct: float
    isolated_nodes_count: int


class DeviceIsolateRequest(BaseModel):
    """Request to immediately quarantine an endpoint."""
    reason: str = Field(..., min_length=5, description="Justification for quarantine")
    playbook_reference: Optional[str] = "PB-RANSOMWARE-01"


class DeviceIsolateResponse(BaseModel):
    """Response confirming endpoint quarantine action."""
    device_id: str
    hostname: str
    ip_address: str
    previous_status: str
    current_status: str
    quarantine_timestamp: datetime
    containment_rule_id: str
    status: str = "SUCCESS"


class NetworkDiscoveryRequest(BaseModel):
    """Trigger request for network sweep and rogue device detection."""
    subnet_id: str
    ping_timeout_ms: int = Field(default=250, ge=50, le=2000)
    port_scan_depth: str = Field(default="STANDARD", pattern="^(FAST|STANDARD|DEEP)$")


class DiscoveredHost(BaseModel):
    """Single host found during discovery sweep."""
    ip_address: str
    mac_address: str
    hostname: Optional[str] = None
    latency_ms: float
    is_known: bool
    device_id: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list)
    os_fingerprint: str = "Unknown"
    is_conflict: bool = False


class NetworkDiscoveryResult(BaseModel):
    """Summary result of a subnet discovery operation."""
    subnet_id: str
    subnet_cidr: str
    scanned_ips: int
    active_hosts_found: int
    rogue_devices_count: int
    conflicts_detected: int
    hosts: List[DiscoveredHost]
    scan_duration_sec: float
    completed_at: datetime
