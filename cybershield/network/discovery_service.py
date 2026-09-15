"""
CyberShield Enterprise - Subnet Discovery & Rogue Asset Detection Engine
Simulates low-level ARP/ICMP sweeps and port fingerprinting to detect
unmanaged devices, rogue endpoints, and IP address collisions.
"""

import time
import random
import ipaddress
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.models.network import (
    NetworkSubnet,
    NetworkDevice,
    IPAddressRecord,
    DeviceStatus,
)
from cybershield.network.schemas import (
    NetworkDiscoveryRequest,
    DiscoveredHost,
    NetworkDiscoveryResult,
)
from cybershield.core.logging import get_logger

logger = get_logger("cybershield.network.discovery")


class NetworkDiscoveryEngine:
    """Enterprise Active & Passive Subnet Scanner."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def scan_subnet(self, request: NetworkDiscoveryRequest) -> NetworkDiscoveryResult:
        """Conduct automated network discovery across target subnet."""
        start_time = time.time()

        # Retrieve target subnet
        stmt = select(NetworkSubnet).where(NetworkSubnet.id == request.subnet_id)
        subnet = (await self.session.execute(stmt)).scalar_one_or_none()
        if not subnet:
            raise ValueError(f"Subnet ID not found: {request.subnet_id}")

        # Fetch known registered devices in this subnet
        dev_stmt = select(NetworkDevice).where(NetworkDevice.subnet_id == subnet.id)
        known_devices = (await self.session.execute(dev_stmt)).scalars().all()
        known_by_ip = {d.ip_address: d for d in known_devices}

        net = ipaddress.ip_network(subnet.cidr, strict=False)
        total_ips = min(254, net.num_addresses - 2) if net.version == 4 else 50

        hosts: List[DiscoveredHost] = []
        rogue_count = 0
        conflict_count = 0

        # Add all known online devices
        for ip, dev in known_by_ip.items():
            hosts.append(DiscoveredHost(
                ip_address=ip,
                mac_address=dev.mac_address,
                hostname=dev.hostname,
                latency_ms=round(random.uniform(0.4, 2.8), 2),
                is_known=True,
                device_id=dev.id,
                open_ports=dev.open_ports or [80, 443],
                os_fingerprint=f"{dev.os_family.value} ({dev.os_version or 'Enterprise'})",
                is_conflict=False,
            ))

        # Detect or inject realistic unmanaged / shadow-IT device for SOC realism
        if subnet.id == "sub-corp-01":
            rogue_ip = "10.0.1.215"
            if rogue_ip not in known_by_ip:
                hosts.append(DiscoveredHost(
                    ip_address=rogue_ip,
                    mac_address="B8:27:EB:4A:91:12",  # Raspberry Pi Foundation OUI
                    hostname="rogue-pi-dropbox",
                    latency_ms=4.12,
                    is_known=False,
                    device_id=None,
                    open_ports=[22, 5900, 8080],
                    os_fingerprint="Linux Debian ARM (Raspberry Pi)",
                    is_conflict=False,
                ))
                rogue_count += 1
                logger.warning("ROGUE ASSET DETECTED: %s (MAC: B8:27:EB:4A:91:12) in subnet %s", rogue_ip, subnet.id)

        # Check for IP conflicts
        mac_seen = {}
        for h in hosts:
            if h.mac_address in mac_seen and mac_seen[h.mac_address] != h.ip_address:
                h.is_conflict = True
                conflict_count += 1
            mac_seen[h.mac_address] = h.ip_address

        duration = round(time.time() - start_time + random.uniform(0.2, 0.5), 3)

        return NetworkDiscoveryResult(
            subnet_id=subnet.id,
            subnet_cidr=subnet.cidr,
            scanned_ips=total_ips,
            active_hosts_found=len(hosts),
            rogue_devices_count=rogue_count,
            conflicts_detected=conflict_count,
            hosts=hosts,
            scan_duration_sec=duration,
            completed_at=datetime.utcnow(),
        )
