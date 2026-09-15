"""
CyberShield Enterprise - Network & Device REST API Endpoints
Exposes device management, subnet inventory, IP address allocations,
interactive topology graphs, and automated discovery sweeps.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from cybershield.database.session import get_db
from cybershield.database.models import User, Permission
from cybershield.database.models.network import (
    NetworkDevice,
    NetworkSubnet,
    IPAddressRecord,
    DeviceStatus,
    IPStatus,
)
from cybershield.auth.dependencies import get_current_user, require_permission
from cybershield.network.schemas import (
    DeviceCreate,
    DeviceUpdate,
    DeviceResponse,
    DevicePaginatedList,
    SubnetCreate,
    SubnetResponse,
    SubnetPaginatedList,
    IPRecordResponse,
    IPRecordPaginatedList,
    IPReserveRequest,
    TopologyGraphResponse,
    DeviceIsolateRequest,
    DeviceIsolateResponse,
    NetworkDiscoveryRequest,
    NetworkDiscoveryResult,
)
from cybershield.network.device_service import DeviceService
from cybershield.network.subnet_service import SubnetService
from cybershield.network.topology_service import TopologyService
from cybershield.network.discovery_service import NetworkDiscoveryEngine
from cybershield.audit.service import AuditService
from cybershield.core.logging import get_logger

logger = get_logger("cybershield.api.network")
router = APIRouter(prefix="/api", tags=["Networks & Devices"])


# ==========================================
# 1. Device Management Endpoints
# ==========================================

@router.get("/devices", response_model=DevicePaginatedList)
async def list_devices(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None),
    device_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    subnet_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve paginated inventory of enterprise network devices."""
    service = DeviceService(db)
    return await service.list_devices(
        page=page,
        page_size=page_size,
        search=search,
        device_type=device_type,
        status=status,
        subnet_id=subnet_id,
    )


@router.post("/devices", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
async def create_device(
    payload: DeviceCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Register a new managed device in the corporate asset inventory."""
    service = DeviceService(db)
    device = await service.create_device(payload)

    await AuditService.log_event(
        db=db,
        action="DEVICE_REGISTER",
        username=current_user.username,
        user_id=current_user.id,
        resource=f"device:{device.id}",
        status="SUCCESS",
        details={"hostname": device.hostname, "ip": device.ip_address, "mac": device.mac_address}
    )
    return device


@router.get("/devices/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve full configuration and security profile for a device."""
    service = DeviceService(db)
    device = await service.get_device_by_id(device_id)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")

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


@router.patch("/devices/{device_id}", response_model=DeviceResponse)
async def update_device(
    device_id: str,
    payload: DeviceUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Modify device metadata, location, owner, or open port profile."""
    service = DeviceService(db)
    updated = await service.update_device(device_id, payload)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")

    await AuditService.log_event(
        db=db,
        action="DEVICE_UPDATE",
        username=current_user.username,
        user_id=current_user.id,
        resource=f"device:{device_id}",
        status="SUCCESS",
        details=payload.model_dump(exclude_unset=True)
    )
    return updated


@router.post("/devices/{device_id}/isolate", response_model=DeviceIsolateResponse)
async def isolate_device(
    device_id: str,
    payload: DeviceIsolateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Execute host network quarantine and immediate isolation containment."""
    service = DeviceService(db)
    result = await service.isolate_device(device_id, reason=payload.reason)
    if not result:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")

    await AuditService.log_event(
        db=db,
        action="HOST_QUARANTINE_ISOLATE",
        username=current_user.username,
        user_id=current_user.id,
        resource=f"device:{device_id}",
        status="SUCCESS",
        details={"reason": payload.reason, "rule": result.containment_rule_id}
    )
    return result


@router.post("/devices/{device_id}/unquarantine", response_model=DeviceResponse)
async def unquarantine_device(
    device_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Lift network isolation and return host to standard online operational status."""
    service = DeviceService(db)
    result = await service.unquarantine_device(device_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")

    await AuditService.log_event(
        db=db,
        action="HOST_QUARANTINE_LIFT",
        username=current_user.username,
        user_id=current_user.id,
        resource=f"device:{device_id}",
        status="SUCCESS",
        details={"status": result.status}
    )
    return result


# ==========================================
# 2. Subnet & Network Endpoints
# ==========================================

@router.get("/networks", response_model=SubnetPaginatedList)
async def list_networks(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all corporate subnets and VLANs with capacity and IP utilization stats."""
    service = SubnetService(db)
    subnets = await service.list_subnets()
    return SubnetPaginatedList(total=len(subnets), items=subnets)


@router.post("/networks", response_model=SubnetResponse, status_code=status.HTTP_201_CREATED)
async def create_network(
    payload: SubnetCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Declare a new enterprise subnet with automated CIDR geometry calculation."""
    service = SubnetService(db)
    subnet = await service.create_subnet(payload)

    await AuditService.log_event(
        db=db,
        action="SUBNET_CREATE",
        username=current_user.username,
        user_id=current_user.id,
        resource=f"subnet:{subnet.id}",
        status="SUCCESS",
        details={"name": subnet.name, "cidr": subnet.cidr, "zone": subnet.zone_type}
    )
    return subnet


# ==========================================
# 3. IP Inventory & Allocation Endpoints
# ==========================================

@router.get("/ips", response_model=IPRecordPaginatedList)
async def list_ips(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    subnet_id: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all allocated IP address records across enterprise subnets."""
    stmt = select(IPAddressRecord)
    if subnet_id:
        stmt = stmt.where(IPAddressRecord.subnet_id == subnet_id)
    if status_filter:
        stmt = stmt.where(IPAddressRecord.status == getattr(IPStatus, status_filter, IPStatus.ACTIVE))

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    stmt = stmt.order_by(IPAddressRecord.ip_address.asc()).offset((page - 1) * page_size).limit(page_size)
    results = (await db.execute(stmt)).scalars().all()

    items = [
        IPRecordResponse(
            id=r.id,
            ip_address=r.ip_address,
            subnet_id=r.subnet_id,
            device_id=r.device_id,
            mac_address=r.mac_address,
            hostname=r.hostname,
            allocation_type=r.allocation_type.value,
            status=r.status.value,
            lease_start=r.lease_start,
            lease_expires=r.lease_expires,
            last_ping_latency_ms=r.last_ping_latency_ms,
            last_active=r.last_active,
        )
        for r in results
    ]

    return IPRecordPaginatedList(
        total=total,
        page=page,
        page_size=page_size,
        items=items
    )


# ==========================================
# 4. Interactive Topology Graph Endpoint
# ==========================================

@router.get("/network/topology", response_model=TopologyGraphResponse)
async def get_network_topology(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve full hierarchical and mesh network topology graph for SOC canvas."""
    service = TopologyService(db)
    return await service.get_topology_graph()


# ==========================================
# 5. Network Discovery Sweep Endpoint
# ==========================================

@router.post("/network/discovery/scan", response_model=NetworkDiscoveryResult)
async def scan_network(
    payload: NetworkDiscoveryRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Execute automated subnet discovery sweep to unmask rogue devices and IP conflicts."""
    engine = NetworkDiscoveryEngine(db)
    try:
        result = await engine.scan_subnet(payload)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    await AuditService.log_event(
        db=db,
        action="NETWORK_DISCOVERY_SCAN",
        username=current_user.username,
        user_id=current_user.id,
        resource=f"subnet:{payload.subnet_id}",
        status="SUCCESS",
        details={
            "scanned": result.scanned_ips,
            "hosts_found": result.active_hosts_found,
            "rogue_count": result.rogue_devices_count,
            "conflicts": result.conflicts_detected
        }
    )
    return result


# ==========================================
# 6. Aggregated Network Posture Summary
# ==========================================

@router.get("/network/summary")
async def get_network_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Aggregated network inventory KPIs."""
    total_devs = (await db.execute(select(func.count(NetworkDevice.id)))).scalar() or 0
    online_devs = (await db.execute(select(func.count(NetworkDevice.id)).where(NetworkDevice.status == DeviceStatus.ONLINE))).scalar() or 0
    isolated_devs = (await db.execute(select(func.count(NetworkDevice.id)).where(NetworkDevice.status == DeviceStatus.ISOLATED))).scalar() or 0
    subnets_count = (await db.execute(select(func.count(NetworkSubnet.id)))).scalar() or 0
    total_ips = (await db.execute(select(func.count(IPAddressRecord.id)))).scalar() or 0

    return {
        "total_devices": total_devs,
        "online_devices": online_devs,
        "isolated_devices": isolated_devs,
        "subnets_count": subnets_count,
        "total_allocated_ips": total_ips,
        "network_health_pct": round((online_devs / max(1, total_devs)) * 100, 1),
        "total_bandwidth_capacity_gbps": 40.0,
        "current_throughput_mbps": 418.5,
    }
