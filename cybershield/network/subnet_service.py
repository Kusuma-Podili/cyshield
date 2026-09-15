"""
CyberShield Enterprise - Subnet & IP Calculator Service
Manages CIDR mathematics, IP range allocations, capacity metrics, and subnet operations.
"""

import ipaddress
import uuid
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime
from sqlalchemy import select, func, update, delete
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.models.network import (
    NetworkSubnet,
    IPAddressRecord,
    NetworkDevice,
    ZoneType,
    IPAllocationType,
    IPStatus,
)
from cybershield.network.schemas import SubnetCreate, SubnetUpdate, SubnetResponse
from cybershield.core.logging import get_logger

logger = get_logger("cybershield.network.subnet")


class SubnetCalculator:
    """Utility class for RFC 1878 / RFC 4632 IPv4 and IPv6 network mathematics."""

    @staticmethod
    def inspect_cidr(cidr: str) -> Dict[str, Any]:
        """Parse CIDR string and return network geometry."""
        net = ipaddress.ip_network(cidr, strict=False)
        total_hosts = max(1, net.num_addresses - 2) if net.version == 4 and net.prefixlen <= 30 else net.num_addresses

        # Standard gateway is customarily the .1 or first usable host
        hosts_generator = net.hosts()
        gateway = str(next(hosts_generator, net.network_address))

        return {
            "network_address": str(net.network_address),
            "broadcast_address": str(net.broadcast_address) if net.version == 4 else "N/A",
            "netmask": str(net.netmask),
            "prefixlen": net.prefixlen,
            "version": net.version,
            "total_usable_hosts": total_hosts,
            "gateway_ip": gateway,
        }

    @staticmethod
    def is_ip_in_subnet(ip: str, cidr: str) -> bool:
        """Check if an IP address resides within the specified CIDR block."""
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False

    @staticmethod
    def find_next_available_ip(cidr: str, used_ips: List[str]) -> Optional[str]:
        """Calculate the lowest available usable host IP in a subnet not present in used_ips."""
        net = ipaddress.ip_network(cidr, strict=False)
        used_set = set(used_ips)
        for host in net.hosts():
            ip_str = str(host)
            if ip_str not in used_set:
                return ip_str
        return None


class SubnetService:
    """Business logic for Enterprise Network Subnets."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def list_subnets(self) -> List[SubnetResponse]:
        """Fetch all configured enterprise subnets with live IP allocation stats."""
        stmt = select(NetworkSubnet).order_by(NetworkSubnet.name.asc())
        result = await self.session.execute(stmt)
        subnets = result.scalars().all()

        responses = []
        for s in subnets:
            # Calculate live allocated IPs count
            count_stmt = select(func.count(IPAddressRecord.id)).where(
                IPAddressRecord.subnet_id == s.id,
                IPAddressRecord.status == IPStatus.ACTIVE
            )
            alloc_count = (await self.session.execute(count_stmt)).scalar() or 0
            utilization = round((alloc_count / max(1, s.total_ips)) * 100, 2)

            responses.append(SubnetResponse(
                id=s.id,
                name=s.name,
                cidr=s.cidr,
                vlan_id=s.vlan_id,
                gateway_ip=s.gateway_ip,
                netmask=s.netmask,
                broadcast_ip=s.broadcast_ip,
                dns_servers=s.dns_servers or ["10.0.3.10", "1.1.1.1"],
                zone_type=s.zone_type.value if hasattr(s.zone_type, "value") else str(s.zone_type),
                description=s.description,
                risk_level=s.risk_level,
                is_monitored=s.is_monitored,
                total_ips=s.total_ips,
                allocated_ips=alloc_count,
                utilization_pct=utilization,
                created_at=s.created_at,
                updated_at=s.updated_at,
            ))
        return responses

    async def get_subnet_by_id(self, subnet_id: str) -> Optional[NetworkSubnet]:
        """Retrieve single subnet entity."""
        stmt = select(NetworkSubnet).where(NetworkSubnet.id == subnet_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def create_subnet(self, data: SubnetCreate) -> SubnetResponse:
        """Create a new network subnet partition."""
        # Calculate CIDR parameters
        geo = SubnetCalculator.inspect_cidr(data.cidr)

        subnet_id = f"sub-{uuid.uuid4().hex[:8]}"
        new_subnet = NetworkSubnet(
            id=subnet_id,
            name=data.name,
            cidr=data.cidr,
            vlan_id=data.vlan_id,
            gateway_ip=geo["gateway_ip"],
            netmask=geo["netmask"],
            broadcast_ip=geo["broadcast_address"],
            dns_servers=data.dns_servers,
            zone_type=getattr(ZoneType, data.zone_type, ZoneType.CORP_LAN),
            description=data.description,
            risk_level=data.risk_level,
            total_ips=geo["total_usable_hosts"],
            allocated_ips=0,
            is_monitored=data.is_monitored,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        self.session.add(new_subnet)

        # Register Gateway IP record
        gw_record = IPAddressRecord(
            id=f"ip-{uuid.uuid4().hex[:8]}",
            ip_address=geo["gateway_ip"],
            subnet_id=subnet_id,
            hostname=f"gw-{data.name.lower().replace(' ', '-')}",
            allocation_type=IPAllocationType.GATEWAY,
            status=IPStatus.ACTIVE,
            last_active=datetime.utcnow(),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        self.session.add(gw_record)

        await self.session.commit()
        await self.session.refresh(new_subnet)
        logger.info("Created network subnet: %s (%s)", new_subnet.name, new_subnet.cidr)

        return SubnetResponse(
            id=new_subnet.id,
            name=new_subnet.name,
            cidr=new_subnet.cidr,
            vlan_id=new_subnet.vlan_id,
            gateway_ip=new_subnet.gateway_ip,
            netmask=new_subnet.netmask,
            broadcast_ip=new_subnet.broadcast_ip,
            dns_servers=new_subnet.dns_servers,
            zone_type=new_subnet.zone_type.value if hasattr(new_subnet.zone_type, "value") else str(new_subnet.zone_type),
            description=new_subnet.description,
            risk_level=new_subnet.risk_level,
            is_monitored=new_subnet.is_monitored,
            total_ips=new_subnet.total_ips,
            allocated_ips=1,
            utilization_pct=round((1 / max(1, new_subnet.total_ips)) * 100, 2),
            created_at=new_subnet.created_at,
            updated_at=new_subnet.updated_at,
        )

    async def seed_enterprise_subnets(self):
        """Seed Fortune-500 enterprise network architecture if database has no subnets."""
        stmt = select(func.count(NetworkSubnet.id))
        count = (await self.session.execute(stmt)).scalar()
        if count and count > 0:
            return

        seeds = [
            {
                "id": "sub-corp-01",
                "name": "Corporate Workstations & Endpoints",
                "cidr": "10.0.1.0/24",
                "vlan_id": 10,
                "zone_type": ZoneType.CORP_LAN,
                "description": "Primary user workstation pool across HQ buildings A & B.",
                "risk_level": "MEDIUM",
            },
            {
                "id": "sub-dmz-01",
                "name": "DMZ Web & API Ingress Tier",
                "cidr": "10.0.2.0/24",
                "vlan_id": 20,
                "zone_type": ZoneType.DMZ,
                "description": "Perimeter reverse proxies, API gateways, and external mail relays.",
                "risk_level": "HIGH",
            },
            {
                "id": "sub-dc-01",
                "name": "Datacenter Core & Database Tier",
                "cidr": "10.0.3.0/24",
                "vlan_id": 30,
                "zone_type": ZoneType.DATACENTER,
                "description": "Primary mission-critical PostgreSQL clusters, Redis caches, and SAN arrays.",
                "risk_level": "CRITICAL",
            },
            {
                "id": "sub-mgmt-01",
                "name": "Out-of-Band SOC Management",
                "cidr": "10.0.99.0/24",
                "vlan_id": 99,
                "zone_type": ZoneType.MANAGEMENT,
                "description": "Isolated bastion hosts, SIEM ingest collectors, and firewall console switches.",
                "risk_level": "LOW",
            },
        ]

        for s in seeds:
            geo = SubnetCalculator.inspect_cidr(s["cidr"])
            subnet = NetworkSubnet(
                id=s["id"],
                name=s["name"],
                cidr=s["cidr"],
                vlan_id=s["vlan_id"],
                gateway_ip=geo["gateway_ip"],
                netmask=geo["netmask"],
                broadcast_ip=geo["broadcast_address"],
                dns_servers=["10.0.3.10", "1.1.1.1"],
                zone_type=s["zone_type"],
                description=s["description"],
                risk_level=s["risk_level"],
                total_ips=geo["total_usable_hosts"],
                allocated_ips=1,
                is_monitored=True,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            self.session.add(subnet)

            # Gateway record
            gw = IPAddressRecord(
                id=f"ip-gw-{s['id']}",
                ip_address=geo["gateway_ip"],
                subnet_id=s["id"],
                hostname=f"gw-{s['id']}",
                allocation_type=IPAllocationType.GATEWAY,
                status=IPStatus.ACTIVE,
                last_active=datetime.utcnow(),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            self.session.add(gw)

        await self.session.commit()
        logger.info("Default enterprise network subnets successfully seeded (4 zones).")
