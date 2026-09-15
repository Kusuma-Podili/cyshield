"""
CyberShield Enterprise - Network Device & Asset Management Service
Handles device lifecycle, risk profiling, open-port risk assessment,
and immediate host network quarantine / containment.
"""

import uuid
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime
from sqlalchemy import select, func, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.models.network import (
    NetworkDevice,
    NetworkSubnet,
    IPAddressRecord,
    DeviceMetric,
    DeviceType,
    DeviceStatus,
    OSFamily,
    IPAllocationType,
    IPStatus,
)
from cybershield.network.schemas import (
    DeviceCreate,
    DeviceUpdate,
    DeviceResponse,
    DevicePaginatedList,
    DeviceIsolateResponse,
)
from cybershield.core.logging import get_logger
from cybershield.core.bus import event_bus, BusMessage, Priority

logger = get_logger("cybershield.network.devices")

HIGH_RISK_PORTS = {
    21: {"name": "FTP", "weight": 12.0},
    23: {"name": "Telnet", "weight": 25.0},
    135: {"name": "MSRPC", "weight": 15.0},
    139: {"name": "NetBIOS", "weight": 10.0},
    445: {"name": "SMB", "weight": 18.0},
    3389: {"name": "RDP", "weight": 15.0},
    5900: {"name": "VNC", "weight": 14.0},
    8080: {"name": "HTTP-Alt", "weight": 5.0},
    4444: {"name": "Metasploit Default", "weight": 40.0},
}


class DeviceRiskCalculator:
    """Calculates enterprise cyber risk score (0.0 to 100.0) for managed assets."""

    @staticmethod
    def calculate_score(
        device_type: DeviceType,
        status: DeviceStatus,
        is_critical_asset: bool,
        open_ports: List[int],
        agent_installed: bool
    ) -> float:
        score = 0.0

        # Status impact
        if status == DeviceStatus.COMPROMISED:
            return 100.0
        elif status == DeviceStatus.ISOLATED:
            return 85.0
        elif status == DeviceStatus.DEGRADED:
            score += 35.0

        # Open port risk vector
        port_risk = 0.0
        for port in (open_ports or []):
            if port in HIGH_RISK_PORTS:
                port_risk += HIGH_RISK_PORTS[port]["weight"]
            else:
                port_risk += 1.5
        score += min(port_risk, 45.0)

        # Asset criticality amplifier
        if is_critical_asset:
            score += 20.0

        # Agent absence penalty
        if not agent_installed and device_type in [DeviceType.SERVER, DeviceType.WORKSTATION]:
            score += 15.0

        return round(min(100.0, max(0.0, score)), 1)


class DeviceService:
    """Enterprise Device Management Operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def list_devices(
        self,
        page: int = 1,
        page_size: int = 20,
        search: Optional[str] = None,
        device_type: Optional[str] = None,
        status: Optional[str] = None,
        subnet_id: Optional[str] = None,
    ) -> DevicePaginatedList:
        """Query devices with filtering, search, and pagination."""
        stmt = select(NetworkDevice)

        filters = []
        if search:
            search_pattern = f"%{search}%"
            filters.append(or_(
                NetworkDevice.hostname.ilike(search_pattern),
                NetworkDevice.ip_address.ilike(search_pattern),
                NetworkDevice.mac_address.ilike(search_pattern),
                NetworkDevice.owner.ilike(search_pattern),
            ))

        if device_type:
            filters.append(NetworkDevice.device_type == getattr(DeviceType, device_type, DeviceType.WORKSTATION))
        if status:
            filters.append(NetworkDevice.status == getattr(DeviceStatus, status, DeviceStatus.ONLINE))
        if subnet_id:
            filters.append(NetworkDevice.subnet_id == subnet_id)

        if filters:
            stmt = stmt.where(and_(*filters))

        # Count total
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await self.session.execute(count_stmt)).scalar() or 0

        # Pagination & sorting by risk_score desc
        stmt = stmt.order_by(NetworkDevice.risk_score.desc(), NetworkDevice.hostname.asc())
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)

        result = await self.session.execute(stmt)
        devices = result.scalars().all()

        items = [
            DeviceResponse(
                id=d.id,
                hostname=d.hostname,
                ip_address=d.ip_address,
                mac_address=d.mac_address,
                device_type=d.device_type.value if hasattr(d.device_type, "value") else str(d.device_type),
                status=d.status.value if hasattr(d.status, "value") else str(d.status),
                os_family=d.os_family.value if hasattr(d.os_family, "value") else str(d.os_family),
                os_version=d.os_version,
                subnet_id=d.subnet_id,
                location=d.location,
                department=d.department,
                owner=d.owner,
                risk_score=d.risk_score,
                is_critical_asset=d.is_critical_asset,
                agent_installed=d.agent_installed,
                agent_version=d.agent_version,
                open_ports=d.open_ports or [],
                tags=d.tags or [],
                last_seen=d.last_seen,
                created_at=d.created_at,
                updated_at=d.updated_at,
            )
            for d in devices
        ]

        return DevicePaginatedList(
            total=total,
            page=page,
            page_size=page_size,
            items=items
        )

    async def get_device_by_id(self, device_id: str) -> Optional[NetworkDevice]:
        """Fetch single device model."""
        stmt = select(NetworkDevice).where(NetworkDevice.id == device_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def create_device(self, data: DeviceCreate) -> DeviceResponse:
        """Register a new managed device and create corresponding IP address record."""
        dev_type = getattr(DeviceType, data.device_type, DeviceType.WORKSTATION)
        os_fam = getattr(OSFamily, data.os_family, OSFamily.UNKNOWN)
        initial_status = DeviceStatus.ONLINE

        risk_score = DeviceRiskCalculator.calculate_score(
            device_type=dev_type,
            status=initial_status,
            is_critical_asset=data.is_critical_asset,
            open_ports=data.open_ports,
            agent_installed=data.agent_installed
        )

        dev_id = f"dev-{uuid.uuid4().hex[:8]}"
        device = NetworkDevice(
            id=dev_id,
            hostname=data.hostname,
            ip_address=data.ip_address,
            mac_address=data.mac_address,
            subnet_id=data.subnet_id,
            device_type=dev_type,
            status=initial_status,
            os_family=os_fam,
            os_version=data.os_version,
            location=data.location,
            department=data.department,
            owner=data.owner,
            risk_score=risk_score,
            is_critical_asset=data.is_critical_asset,
            agent_installed=data.agent_installed,
            agent_version=data.agent_version,
            open_ports=data.open_ports,
            tags=data.tags,
            last_seen=datetime.utcnow(),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        self.session.add(device)

        # Allocate or update IP Record
        existing_ip_stmt = select(IPAddressRecord).where(IPAddressRecord.ip_address == data.ip_address)
        existing_ip = (await self.session.execute(existing_ip_stmt)).scalar_one_or_none()
        if existing_ip:
            existing_ip.device_id = dev_id
            existing_ip.mac_address = data.mac_address
            existing_ip.hostname = data.hostname
            existing_ip.updated_at = datetime.utcnow()
        else:
            ip_record = IPAddressRecord(
                id=f"ip-{uuid.uuid4().hex[:8]}",
                ip_address=data.ip_address,
                subnet_id=data.subnet_id or "sub-corp-01",
                device_id=dev_id,
                mac_address=data.mac_address,
                hostname=data.hostname,
                allocation_type=IPAllocationType.DHCP if not data.is_critical_asset else IPAllocationType.STATIC,
                status=IPStatus.ACTIVE,
                last_ping_latency_ms=1.4,
                last_active=datetime.utcnow(),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            self.session.add(ip_record)

        await self.session.commit()
        await self.session.refresh(device)
        logger.info("Registered device %s (%s) with IP %s", device.hostname, device.id, device.ip_address)

        return DeviceResponse(
            id=device.id,
            hostname=device.hostname,
            ip_address=device.ip_address,
            mac_address=device.mac_address,
            device_type=device.device_type.value,
            status=device.status.value,
            os_family=device.os_family.value,
            os_version=device.os_version,
            subnet_id=device.subnet_id,
            location=device.location,
            department=device.department,
            owner=device.owner,
            risk_score=device.risk_score,
            is_critical_asset=device.is_critical_asset,
            agent_installed=device.agent_installed,
            agent_version=device.agent_version,
            open_ports=device.open_ports or [],
            tags=device.tags or [],
            last_seen=device.last_seen,
            created_at=device.created_at,
            updated_at=device.updated_at,
        )

    async def update_device(self, device_id: str, data: DeviceUpdate) -> Optional[DeviceResponse]:
        """Update existing device attributes and recalculate risk score."""
        device = await self.get_device_by_id(device_id)
        if not device:
            return None

        update_dict = data.model_dump(exclude_unset=True)
        for key, val in update_dict.items():
            if key == "status" and val:
                setattr(device, key, getattr(DeviceStatus, val, device.status))
            elif hasattr(device, key):
                setattr(device, key, val)

        # Recalculate risk score
        device.risk_score = DeviceRiskCalculator.calculate_score(
            device_type=device.device_type,
            status=device.status,
            is_critical_asset=device.is_critical_asset,
            open_ports=device.open_ports or [],
            agent_installed=device.agent_installed
        )
        device.updated_at = datetime.utcnow()

        await self.session.commit()
        await self.session.refresh(device)
        return DeviceResponse(
            id=device.id,
            hostname=device.hostname,
            ip_address=device.ip_address,
            mac_address=device.mac_address,
            device_type=device.device_type.value,
            status=device.status.value,
            os_family=device.os_family.value,
            os_version=device.os_version,
            subnet_id=device.subnet_id,
            location=device.location,
            department=device.department,
            owner=device.owner,
            risk_score=device.risk_score,
            is_critical_asset=device.is_critical_asset,
            agent_installed=device.agent_installed,
            agent_version=device.agent_version,
            open_ports=device.open_ports or [],
            tags=device.tags or [],
            last_seen=device.last_seen,
            created_at=device.created_at,
            updated_at=device.updated_at,
        )

    async def isolate_device(self, device_id: str, reason: str) -> Optional[DeviceIsolateResponse]:
        """Execute autonomous host network containment and quarantine."""
        device = await self.get_device_by_id(device_id)
        if not device:
            return None

        prev_status = device.status.value
        device.status = DeviceStatus.ISOLATED
        device.risk_score = 90.0
        device.updated_at = datetime.utcnow()

        # Update IP record to BLOCKED
        stmt = select(IPAddressRecord).where(IPAddressRecord.device_id == device.id)
        ip_rec = (await self.session.execute(stmt)).scalar_one_or_none()
        if ip_rec:
            ip_rec.status = IPStatus.BLOCKED
            ip_rec.updated_at = datetime.utcnow()

        await self.session.commit()

        containment_rule_id = f"ACL-QUARANTINE-{device.id.upper()}"
        logger.warning(
            "CONTAINMENT: Device %s (%s) isolated. Reason: %s",
            device.hostname, device.ip_address, reason
        )

        # Publish containment event to the security bus
        await event_bus.publish(
            topic="containment.host_isolated",
            payload={
                "device_id": device.id,
                "hostname": device.hostname,
                "ip_address": device.ip_address,
                "reason": reason,
                "rule_id": containment_rule_id,
                "timestamp": datetime.utcnow().isoformat(),
            },
            priority=Priority.CRITICAL,
            source="cybershield.device_service"
        )

        return DeviceIsolateResponse(
            device_id=device.id,
            hostname=device.hostname,
            ip_address=device.ip_address,
            previous_status=prev_status,
            current_status=DeviceStatus.ISOLATED.value,
            quarantine_timestamp=datetime.utcnow(),
            containment_rule_id=containment_rule_id,
            status="SUCCESS",
        )

    async def unquarantine_device(self, device_id: str) -> Optional[DeviceResponse]:
        """Lift network quarantine and restore standard operational status."""
        device = await self.get_device_by_id(device_id)
        if not device:
            return None

        device.status = DeviceStatus.ONLINE
        device.risk_score = DeviceRiskCalculator.calculate_score(
            device_type=device.device_type,
            status=DeviceStatus.ONLINE,
            is_critical_asset=device.is_critical_asset,
            open_ports=device.open_ports or [],
            agent_installed=device.agent_installed
        )
        device.updated_at = datetime.utcnow()

        # Restore IP record
        stmt = select(IPAddressRecord).where(IPAddressRecord.device_id == device.id)
        ip_rec = (await self.session.execute(stmt)).scalar_one_or_none()
        if ip_rec:
            ip_rec.status = IPStatus.ACTIVE
            ip_rec.updated_at = datetime.utcnow()

        await self.session.commit()
        await self.session.refresh(device)
        logger.info("RESTORED: Device %s (%s) quarantine lifted.", device.hostname, device.ip_address)

        await event_bus.publish(
            topic="containment.host_restored",
            payload={
                "device_id": device.id,
                "hostname": device.hostname,
                "ip_address": device.ip_address,
                "timestamp": datetime.utcnow().isoformat(),
            },
            priority=Priority.HIGH,
            source="cybershield.device_service"
        )

        return DeviceResponse(
            id=device.id,
            hostname=device.hostname,
            ip_address=device.ip_address,
            mac_address=device.mac_address,
            device_type=device.device_type.value,
            status=device.status.value,
            os_family=device.os_family.value,
            os_version=device.os_version,
            subnet_id=device.subnet_id,
            location=device.location,
            department=device.department,
            owner=device.owner,
            risk_score=device.risk_score,
            is_critical_asset=device.is_critical_asset,
            agent_installed=device.agent_installed,
            agent_version=device.agent_version,
            open_ports=device.open_ports or [],
            tags=device.tags or [],
            last_seen=device.last_seen,
            created_at=device.created_at,
            updated_at=device.updated_at,
        )

    async def seed_enterprise_devices(self):
        """Seed realistic enterprise infrastructure nodes if table is empty."""
        stmt = select(func.count(NetworkDevice.id))
        count = (await self.session.execute(stmt)).scalar()
        if count and count > 0:
            return

        seeds = [
            {
                "id": "dev-fw-01",
                "hostname": "fw-perimeter-01.corp",
                "ip_address": "10.0.2.1",
                "mac_address": "00:50:56:A1:00:01",
                "subnet_id": "sub-dmz-01",
                "device_type": DeviceType.FIREWALL,
                "status": DeviceStatus.ONLINE,
                "os_family": OSFamily.LINUX,
                "os_version": "Palo Alto PAN-OS 11.0",
                "is_critical_asset": True,
                "agent_installed": True,
                "agent_version": "3.2.0-sec",
                "open_ports": [443, 8443, 22],
                "location": "HQ Datacenter Rack A1",
                "owner": "NetOps Team",
                "tags": ["perimeter", "firewall", "dmz"],
            },
            {
                "id": "dev-sw-01",
                "hostname": "sw-core-01.corp",
                "ip_address": "10.0.99.2",
                "mac_address": "00:50:56:A1:00:02",
                "subnet_id": "sub-mgmt-01",
                "device_type": DeviceType.SWITCH,
                "status": DeviceStatus.ONLINE,
                "os_family": OSFamily.CISCO_IOS,
                "os_version": "Cisco IOS-XE 17.6",
                "is_critical_asset": True,
                "agent_installed": False,
                "open_ports": [22, 161],
                "location": "HQ Datacenter Core Spine",
                "owner": "NetOps Team",
                "tags": ["backbone", "switch", "mgmt"],
            },
            {
                "id": "dev-dc-01",
                "hostname": "dc-primary.corp",
                "ip_address": "10.0.3.10",
                "mac_address": "00:50:56:A1:00:10",
                "subnet_id": "sub-dc-01",
                "device_type": DeviceType.SERVER,
                "status": DeviceStatus.ONLINE,
                "os_family": OSFamily.WINDOWS,
                "os_version": "Windows Server 2022 Datacenter",
                "is_critical_asset": True,
                "agent_installed": True,
                "agent_version": "3.2.0-sec",
                "open_ports": [53, 88, 135, 389, 445, 636, 3268],
                "location": "HQ Datacenter Rack B3",
                "owner": "Identity Team",
                "tags": ["active-directory", "domain-controller", "kerberos"],
            },
            {
                "id": "dev-db-01",
                "hostname": "db-prod-cluster.corp",
                "ip_address": "10.0.3.50",
                "mac_address": "00:50:56:A1:00:50",
                "subnet_id": "sub-dc-01",
                "device_type": DeviceType.SERVER,
                "status": DeviceStatus.ONLINE,
                "os_family": OSFamily.LINUX,
                "os_version": "RHEL 9.2 (Plow)",
                "is_critical_asset": True,
                "agent_installed": True,
                "agent_version": "3.2.0-sec",
                "open_ports": [22, 5432, 6379, 9100],
                "location": "HQ Datacenter Rack B4",
                "owner": "Data Engineering",
                "tags": ["database", "postgresql", "production"],
            },
            {
                "id": "dev-web-01",
                "hostname": "proxy-dmz-01.corp",
                "ip_address": "10.0.2.15",
                "mac_address": "00:50:56:A1:00:15",
                "subnet_id": "sub-dmz-01",
                "device_type": DeviceType.SERVER,
                "status": DeviceStatus.ONLINE,
                "os_family": OSFamily.LINUX,
                "os_version": "Ubuntu 22.04 LTS",
                "is_critical_asset": False,
                "agent_installed": True,
                "agent_version": "3.2.0-sec",
                "open_ports": [80, 443, 8080],
                "location": "HQ Datacenter DMZ Zone",
                "owner": "App Platform Team",
                "tags": ["nginx", "dmz-proxy", "ingress"],
            },
            {
                "id": "dev-ws-fin",
                "hostname": "ws-finance-08.corp",
                "ip_address": "10.0.1.108",
                "mac_address": "00:50:56:B2:01:08",
                "subnet_id": "sub-corp-01",
                "device_type": DeviceType.WORKSTATION,
                "status": DeviceStatus.ONLINE,
                "os_family": OSFamily.WINDOWS,
                "os_version": "Windows 11 Enterprise 23H2",
                "is_critical_asset": False,
                "agent_installed": True,
                "agent_version": "3.2.0-sec",
                "open_ports": [135, 445, 3389],
                "location": "Finance Floor 3, Desk 312",
                "owner": "Alice Smith (CFO Staff)",
                "tags": ["workstation", "finance", "high-privilege"],
            },
            {
                "id": "dev-ws-exec",
                "hostname": "ws-exec-laptop.corp",
                "ip_address": "10.0.1.101",
                "mac_address": "00:50:56:B2:01:01",
                "subnet_id": "sub-corp-01",
                "device_type": DeviceType.WORKSTATION,
                "status": DeviceStatus.ONLINE,
                "os_family": OSFamily.MACOS,
                "os_version": "macOS Sonoma 14.5",
                "is_critical_asset": True,
                "agent_installed": True,
                "agent_version": "3.2.0-sec",
                "open_ports": [22],
                "location": "Executive Suite Floor 7",
                "owner": "David Henderson (VP)",
                "tags": ["workstation", "executive", "macbook"],
            },
        ]

        for s in seeds:
            score = DeviceRiskCalculator.calculate_score(
                device_type=s["device_type"],
                status=s["status"],
                is_critical_asset=s["is_critical_asset"],
                open_ports=s["open_ports"],
                agent_installed=s["agent_installed"]
            )

            dev = NetworkDevice(
                id=s["id"],
                hostname=s["hostname"],
                ip_address=s["ip_address"],
                mac_address=s["mac_address"],
                subnet_id=s["subnet_id"],
                device_type=s["device_type"],
                status=s["status"],
                os_family=s["os_family"],
                os_version=s["os_version"],
                location=s["location"],
                owner=s["owner"],
                risk_score=score,
                is_critical_asset=s["is_critical_asset"],
                agent_installed=s["agent_installed"],
                agent_version=s.get("agent_version"),
                open_ports=s["open_ports"],
                tags=s["tags"],
                last_seen=datetime.utcnow(),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            self.session.add(dev)

            # Assign or link existing IP Record
            existing_ip_stmt = select(IPAddressRecord).where(IPAddressRecord.ip_address == s["ip_address"])
            existing_ip = (await self.session.execute(existing_ip_stmt)).scalar_one_or_none()
            if existing_ip:
                existing_ip.device_id = s["id"]
                existing_ip.mac_address = s["mac_address"]
                existing_ip.hostname = s["hostname"]
                existing_ip.updated_at = datetime.utcnow()
            else:
                ip_rec = IPAddressRecord(
                    id=f"ip-{s['id']}",
                    ip_address=s["ip_address"],
                    subnet_id=s["subnet_id"],
                    device_id=s["id"],
                    mac_address=s["mac_address"],
                    hostname=s["hostname"],
                    allocation_type=IPAllocationType.STATIC if s["is_critical_asset"] else IPAllocationType.DHCP,
                    status=IPStatus.ACTIVE,
                    last_ping_latency_ms=1.2,
                    last_active=datetime.utcnow(),
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                )
                self.session.add(ip_rec)

        await self.session.commit()
        logger.info("Default enterprise managed devices seeded (7 nodes).")
