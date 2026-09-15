"""
CyberShield Enterprise - Network & Device Database Models
Defines ORM entities for Network Devices, Subnets, IP Allocations,
Topology Links, and Telemetry Performance Metrics.
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


class DeviceType(str, enum.Enum):
    """Supported Enterprise Network Device Categories."""
    SERVER = "SERVER"
    WORKSTATION = "WORKSTATION"
    ROUTER = "ROUTER"
    SWITCH = "SWITCH"
    FIREWALL = "FIREWALL"
    ACCESS_POINT = "ACCESS_POINT"
    LOAD_BALANCER = "LOAD_BALANCER"
    STORAGE_NAS = "STORAGE_NAS"
    IOT_DEVICE = "IOT_DEVICE"
    VIRTUAL_MACHINE = "VIRTUAL_MACHINE"
    CONTAINER_HOST = "CONTAINER_HOST"


class DeviceStatus(str, enum.Enum):
    """Operational and Security Lifecycle Status for Devices."""
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    DEGRADED = "DEGRADED"
    MAINTENANCE = "MAINTENANCE"
    ISOLATED = "ISOLATED"
    COMPROMISED = "COMPROMISED"


class OSFamily(str, enum.Enum):
    """Operating System Families."""
    WINDOWS = "WINDOWS"
    LINUX = "LINUX"
    MACOS = "MACOS"
    CISCO_IOS = "CISCO_IOS"
    JUNIPER_JUNOS = "JUNIPER_JUNOS"
    BSD = "BSD"
    EMBEDDED = "EMBEDDED"
    UNKNOWN = "UNKNOWN"


class ZoneType(str, enum.Enum):
    """Security Zoning Architecture Categories."""
    CORP_LAN = "CORP_LAN"
    DMZ = "DMZ"
    DATACENTER = "DATACENTER"
    CLOUD_VPC = "CLOUD_VPC"
    GUEST_WIFI = "GUEST_WIFI"
    MANAGEMENT = "MANAGEMENT"
    OT_ICS = "OT_ICS"


class IPAllocationType(str, enum.Enum):
    """Method of IP Address Assignment."""
    STATIC = "STATIC"
    DHCP = "DHCP"
    RESERVED = "RESERVED"
    GATEWAY = "GATEWAY"


class IPStatus(str, enum.Enum):
    """IP Address State."""
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    CONFLICT = "CONFLICT"
    BLOCKED = "BLOCKED"


class LinkType(str, enum.Enum):
    """Physical or Logical Link Types between Nodes."""
    ETHERNET_COPPER = "ETHERNET_COPPER"
    FIBER_OPTIC = "FIBER_OPTIC"
    VPN_TUNNEL = "VPN_TUNNEL"
    WIRELESS = "WIRELESS"
    TRUNK = "TRUNK"


class LinkStatus(str, enum.Enum):
    """Health State of Topology Links."""
    UP = "UP"
    DOWN = "DOWN"
    DEGRADED = "DEGRADED"
    CONGESTED = "CONGESTED"


class NetworkSubnet(Base):
    """Enterprise Subnet / VLAN Partition."""
    __tablename__ = "network_subnets"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(128), nullable=False, unique=True, index=True)
    cidr = Column(String(32), nullable=False, unique=True, index=True)
    vlan_id = Column(Integer, nullable=True, index=True)
    gateway_ip = Column(String(45), nullable=False)
    netmask = Column(String(45), nullable=False)
    broadcast_ip = Column(String(45), nullable=False)
    dns_servers = Column(JSON, default=list)  # list of IP strings
    zone_type = Column(SQLEnum(ZoneType), default=ZoneType.CORP_LAN, nullable=False, index=True)
    description = Column(Text, nullable=True)
    risk_level = Column(String(16), default="LOW")
    total_ips = Column(Integer, default=254)
    allocated_ips = Column(Integer, default=0)
    is_monitored = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    devices = relationship("NetworkDevice", back_populates="subnet", cascade="all, delete-orphan")
    ip_records = relationship("IPAddressRecord", back_populates="subnet", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<NetworkSubnet name={self.name} cidr={self.cidr} zone={self.zone_type}>"


class NetworkDevice(Base):
    """Enterprise Network Managed Node (Server, Workstation, Firewall, Switch, etc.)."""
    __tablename__ = "network_devices"

    id = Column(String(64), primary_key=True, index=True)
    hostname = Column(String(128), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    mac_address = Column(String(32), nullable=False, unique=True, index=True)
    subnet_id = Column(String(64), ForeignKey("network_subnets.id", ondelete="CASCADE"), nullable=True, index=True)
    device_type = Column(SQLEnum(DeviceType), default=DeviceType.WORKSTATION, nullable=False, index=True)
    status = Column(SQLEnum(DeviceStatus), default=DeviceStatus.ONLINE, nullable=False, index=True)
    os_family = Column(SQLEnum(OSFamily), default=OSFamily.UNKNOWN, nullable=False)
    os_version = Column(String(128), nullable=True)
    manufacturer = Column(String(128), nullable=True)
    model = Column(String(128), nullable=True)
    serial_number = Column(String(64), nullable=True)
    location = Column(String(128), nullable=True)
    owner = Column(String(128), nullable=True)
    department = Column(String(64), nullable=True)
    risk_score = Column(Float, default=0.0, index=True)
    is_critical_asset = Column(Boolean, default=False)
    agent_installed = Column(Boolean, default=False)
    agent_version = Column(String(32), nullable=True)
    open_ports = Column(JSON, default=list)  # list of int ports
    installed_software = Column(JSON, default=list)
    tags = Column(JSON, default=list)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    subnet = relationship("NetworkSubnet", back_populates="devices")
    ip_record = relationship("IPAddressRecord", back_populates="device", uselist=False)
    metrics = relationship("DeviceMetric", back_populates="device", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_dev_ip_status", "ip_address", "status"),
        Index("idx_dev_type_risk", "device_type", "risk_score"),
    )

    def __repr__(self):
        return f"<NetworkDevice id={self.id} host={self.hostname} ip={self.ip_address} status={self.status}>"


class IPAddressRecord(Base):
    """IP Address Inventory and Allocation Tracking."""
    __tablename__ = "ip_address_records"

    id = Column(String(64), primary_key=True, index=True)
    ip_address = Column(String(45), nullable=False, unique=True, index=True)
    subnet_id = Column(String(64), ForeignKey("network_subnets.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id = Column(String(64), ForeignKey("network_devices.id", ondelete="SET NULL"), nullable=True, unique=True)
    mac_address = Column(String(32), nullable=True, index=True)
    hostname = Column(String(128), nullable=True)
    allocation_type = Column(SQLEnum(IPAllocationType), default=IPAllocationType.DHCP, nullable=False)
    status = Column(SQLEnum(IPStatus), default=IPStatus.ACTIVE, nullable=False, index=True)
    lease_start = Column(DateTime, nullable=True)
    lease_expires = Column(DateTime, nullable=True)
    last_ping_latency_ms = Column(Float, nullable=True)
    last_active = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    subnet = relationship("NetworkSubnet", back_populates="ip_records")
    device = relationship("NetworkDevice", back_populates="ip_record")

    def __repr__(self):
        return f"<IPAddressRecord ip={self.ip_address} type={self.allocation_type} status={self.status}>"


class TopologyLink(Base):
    """Adjacency and Connection Link between Two Network Devices/Nodes."""
    __tablename__ = "topology_links"

    id = Column(String(64), primary_key=True, index=True)
    source_device_id = Column(String(64), ForeignKey("network_devices.id", ondelete="CASCADE"), nullable=False, index=True)
    target_device_id = Column(String(64), ForeignKey("network_devices.id", ondelete="CASCADE"), nullable=False, index=True)
    link_type = Column(SQLEnum(LinkType), default=LinkType.ETHERNET_COPPER, nullable=False)
    status = Column(SQLEnum(LinkStatus), default=LinkStatus.UP, nullable=False)
    bandwidth_mbps = Column(Integer, default=1000)
    current_load_pct = Column(Float, default=12.5)
    latency_ms = Column(Float, default=1.2)
    packet_loss_pct = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    source_device = relationship("NetworkDevice", foreign_keys=[source_device_id])
    target_device = relationship("NetworkDevice", foreign_keys=[target_device_id])

    def __repr__(self):
        return f"<TopologyLink src={self.source_device_id} dst={self.target_device_id} status={self.status}>"


class DeviceMetric(Base):
    """Continuous Telemetry and Resource Utilization Metric."""
    __tablename__ = "device_metrics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(64), ForeignKey("network_devices.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    bytes_in_sec = Column(Float, default=0.0)
    bytes_out_sec = Column(Float, default=0.0)
    packets_in_sec = Column(Float, default=0.0)
    packets_out_sec = Column(Float, default=0.0)
    active_tcp_connections = Column(Integer, default=0)
    cpu_usage_pct = Column(Float, default=0.0)
    memory_usage_pct = Column(Float, default=0.0)
    disk_usage_pct = Column(Float, default=0.0)

    # Relationships
    device = relationship("NetworkDevice", back_populates="metrics")

    __table_args__ = (
        Index("idx_dev_metric_time", "device_id", "timestamp"),
    )

    def __repr__(self):
        return f"<DeviceMetric dev={self.device_id} cpu={self.cpu_usage_pct}% mem={self.memory_usage_pct}%>"
