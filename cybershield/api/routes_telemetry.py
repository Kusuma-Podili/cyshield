"""Telemetry Ingestion & CS-QL Query REST API Endpoints."""

from __future__ import annotations

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from cybershield.core.models import NormalizedEvent, NetworkFlow
from cybershield.ingestion.collector import collector
from cybershield.ingestion.query_engine import CSQLEngine

router = APIRouter(prefix="/api/v1/telemetry", tags=["Telemetry"])


class RawLogIngestRequest(BaseModel):
    raw: str | Dict[str, Any]


class CSQLQueryRequest(BaseModel):
    query: str
    target: str = "events"  # "events" or "alerts"


@router.post("/ingest", response_model=NormalizedEvent)
async def ingest_log(payload: RawLogIngestRequest):
    """Ingest arbitrary enterprise log (Syslog, Sysmon, Zeek, Web, Auditd)."""
    return await collector.ingest_raw(payload.raw)


@router.post("/flow", response_model=Dict[str, Any])
async def ingest_flow(flow: NetworkFlow):
    """Ingest raw network flow record for AI anomaly detection."""
    _, alert = await collector.ingest_network_flow(flow)
    return {
        "status": "processed",
        "flow_id": flow.flow_id,
        "anomaly_alert_id": alert.alert_id if alert else None,
    }


@router.get("/recent", response_model=List[NormalizedEvent])
async def get_recent_telemetry(limit: int = Query(default=50, ge=1, le=500)):
    """Retrieve the most recent normalized security telemetry."""
    return collector.get_recent_events(limit=limit)


@router.post("/csql", response_model=Dict[str, Any])
async def execute_csql(payload: CSQLQueryRequest):
    """Execute CS-QL query with filters, regex, and pipe aggregations."""
    if payload.target.lower() == "alerts":
        alerts = collector.get_recent_alerts(limit=5000)
        return CSQLEngine.execute_alerts(alerts, payload.query)
    else:
        events = collector.get_recent_events(limit=5000)
        return CSQLEngine.execute_events(events, payload.query)
