"""
Industrial Control Systems (ICS) REST API Routes.
Exposes endpoints for OT asset tracking, Modbus/S7comm telemetry inspection, and safety alerts.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.ics.inspector import ICSThreatInspector
from cybershield.ics.schemas import (
    ICSAlert,
    ICSAsset,
    ModbusTelemetry,
    S7CommTelemetry,
)

ics_router = APIRouter(prefix="/api/ics", tags=["OT & Industrial Control Systems (ICS) Security"])
ics_inspector = ICSThreatInspector()


@ics_router.get("/assets", response_model=List[ICSAsset])
async def list_assets():
    """List monitored OT/ICS controllers, PLCs, HMIs, and Safety Instrumented Systems."""
    return ics_inspector.list_assets()


@ics_router.get("/assets/{asset_id}", response_model=ICSAsset)
async def get_asset(asset_id: str):
    """Retrieve details and monitored registers for an ICS asset."""
    asset = ics_inspector.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"ICS asset '{asset_id}' not found")
    return asset


@ics_router.post("/inspect/modbus", response_model=Optional[ICSAlert])
async def inspect_modbus(telemetry: ModbusTelemetry):
    """Deep packet inspection of Modbus TCP transactions for safety setpoint and write violations."""
    return ics_inspector.inspect_modbus(telemetry)


@ics_router.post("/inspect/s7comm", response_model=Optional[ICSAlert])
async def inspect_s7comm(telemetry: S7CommTelemetry):
    """Deep packet inspection of Siemens S7comm frames for CPU Stop and rogue block uploads."""
    return ics_inspector.inspect_s7comm(telemetry)


@ics_router.get("/alerts", response_model=List[ICSAlert])
async def list_alerts(limit: int = Query(50, ge=1, le=500)):
    """List physical safety and cyber threats targeting industrial control networks."""
    return ics_inspector.list_alerts(limit=limit)


@ics_router.get("/overview")
async def get_overview():
    """Summary of ICS plant security, Safety Instrumented Systems, and critical alerts."""
    return ics_inspector.get_overview()
