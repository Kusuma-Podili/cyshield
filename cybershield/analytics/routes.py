"""
CyberShield Enterprise - Analytics & Data Pipelines REST API Routes
Exposes endpoints for scheduled ETL pipeline management, Feature Store lookups,
MITRE ATT&CK coverage matrices, and the Security Posture Index (SPI).
"""

from __future__ import annotations

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.session import get_db
from cybershield.database.models.user import User
from cybershield.database.models.role import Permission
from cybershield.auth import require_permission
from cybershield.audit.service import AuditService
from cybershield.analytics.schemas import (
    ETLPipelineResponse,
    PipelineRunResponse,
    FeatureVectorResponse,
    SecurityMetricsRollupResponse,
    SecurityPostureResponse,
    MitreCoverageResponse,
)
from cybershield.analytics.service import analytics_service

router = APIRouter(prefix="/api/analytics", tags=["Data Pipelines & Security Analytics"])


@router.get("/pipelines", response_model=List[ETLPipelineResponse], summary="List ETL Data Pipelines")
async def list_pipelines(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PIPELINES_VIEW)),
):
    """Retrieve all configured ETL pipelines with execution status, schedule, and processed counters."""
    return await analytics_service.list_pipelines(session=db)


@router.post("/pipelines/{pipeline_id}/run", response_model=PipelineRunResponse, summary="Trigger ETL Pipeline Execution")
async def run_pipeline(
    pipeline_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PIPELINES_RUN)),
):
    """Execute a data pipeline job immediately on-demand."""
    try:
        result = await analytics_service.execute_pipeline(session=db, pipeline_id=pipeline_id)

        await AuditService.log_event(
            db=db,
            action="ETL_PIPELINE_EXECUTED",
            resource=f"pipeline:{pipeline_id}",
            username=current_user.username,
            user_id=current_user.id,
            details={"records_processed": result["records_processed"], "duration": result["duration_sec"]},
            status="SUCCESS",
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/posture", response_model=SecurityPostureResponse, summary="Get Enterprise Security Posture Index")
async def get_security_posture(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ANALYTICS_VIEW)),
):
    """Compute enterprise Security Posture Index (SPI), letter grade, and remediation priorities."""
    return await analytics_service.get_security_posture(session=db)


@router.get("/mitre/coverage", response_model=MitreCoverageResponse, summary="Get MITRE ATT&CK Defense Coverage")
async def get_mitre_coverage(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ANALYTICS_VIEW)),
):
    """Calculate defense rule coverage percentages across all 14 MITRE ATT&CK tactics."""
    return await analytics_service.get_mitre_coverage(session=db)


@router.get("/metrics/rollup", response_model=List[SecurityMetricsRollupResponse], summary="Get Time-Series Rollups")
async def get_metrics_rollups(
    hours: int = Query(24, ge=1, le=168, description="Number of historical hourly buckets"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ANALYTICS_VIEW)),
):
    """Retrieve pre-computed historical hourly metrics rollups for charting and trend analysis."""
    return await analytics_service.get_metrics_rollups(session=db, hours=hours)


@router.get("/features/{entity_id}", response_model=FeatureVectorResponse, summary="Query Entity Feature Vector")
async def get_entity_features(
    entity_id: str,
    feature_group: str = Query("DEVICE_HOURLY", description="Feature group identifier"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ANALYTICS_VIEW)),
):
    """Query online feature store for low-latency behavioral vector of a device, IP, or user."""
    return await analytics_service.get_entity_features(session=db, entity_id=entity_id, feature_group=feature_group)
