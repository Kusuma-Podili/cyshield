"""
CyberShield Enterprise - Analytics & Pipelines Orchestration Service
Coordinates scheduled ETL jobs, feature store queries, and enterprise posture metrics.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from cybershield.database.models.analytics import (
    ETLPipelineModel,
    PipelineStatus,
    PipelineType,
)
from cybershield.analytics.etl_engine import etl_engine
from cybershield.analytics.feature_store import feature_store
from cybershield.analytics.analytics_engine import analytics_engine

logger = logging.getLogger("cybershield.analytics.service")


class AnalyticsService:
    """Enterprise Analytics & Pipeline Management Service."""

    async def seed_default_pipelines(self, session: AsyncSession) -> int:
        """Seed default enterprise ETL pipelines into the database if not present."""
        existing_count = (await session.execute(select(func.count(ETLPipelineModel.id)))).scalar_one()
        if existing_count > 0:
            return existing_count

        default_pipelines = [
            {
                "id": "ETL-SECURITY-METRICS-HOURLY",
                "name": "Hourly Security Metrics Rollup & Posture Index",
                "schedule_cron": "0 * * * *",
                "pipeline_type": PipelineType.METRICS_ROLLUP.value,
                "is_enabled": True,
            },
            {
                "id": "ETL-FEATURE-STORE-UPDATE",
                "name": "Device & User Behavioral Feature Store Aggregator",
                "schedule_cron": "*/15 * * * *",
                "pipeline_type": PipelineType.FEATURE_STORE_UPDATE.value,
                "is_enabled": True,
            },
            {
                "id": "ETL-ASSET-RISK-RECALCULATION",
                "name": "Continuous Bayesian Asset Risk Recalculation",
                "schedule_cron": "*/30 * * * *",
                "pipeline_type": PipelineType.ASSET_RISK_RECALCULATION.value,
                "is_enabled": True,
            },
            {
                "id": "ETL-MITRE-HEATMAP-COMPILATION",
                "name": "MITRE ATT&CK Defense Coverage Matrix Rollup",
                "schedule_cron": "0 0 * * *",
                "pipeline_type": PipelineType.MITRE_HEATMAP_COMPILATION.value,
                "is_enabled": True,
            },
        ]

        now = datetime.utcnow()
        for p in default_pipelines:
            m = ETLPipelineModel(
                id=p["id"],
                name=p["name"],
                schedule_cron=p["schedule_cron"],
                pipeline_type=p["pipeline_type"],
                status=PipelineStatus.IDLE.value,
                is_enabled=p["is_enabled"],
                records_processed=0,
                duration_sec=0.0,
                created_at=now,
                updated_at=now,
            )
            session.add(m)

        await session.commit()
        logger.info("Default enterprise ETL pipelines seeded successfully (%d pipelines).", len(default_pipelines))
        return len(default_pipelines)

    async def list_pipelines(self, session: AsyncSession) -> List[Dict[str, Any]]:
        """Query all registered ETL pipelines with execution states."""
        stmt = select(ETLPipelineModel).order_by(ETLPipelineModel.created_at.asc())
        records = (await session.execute(stmt)).scalars().all()
        return [r.to_dict() for r in records]

    async def execute_pipeline(self, session: AsyncSession, pipeline_id: str) -> Dict[str, Any]:
        """Trigger an immediate execution of an ETL pipeline."""
        return await etl_engine.execute_pipeline(session, pipeline_id)

    async def get_security_posture(self, session: AsyncSession) -> Dict[str, Any]:
        """Compute the executive Enterprise Security Posture Index."""
        return await analytics_engine.calculate_security_posture(session)

    async def get_mitre_coverage(self, session: AsyncSession) -> Dict[str, Any]:
        """Evaluate detection coverage across all 14 MITRE tactics."""
        return await analytics_engine.compute_mitre_coverage(session)

    async def get_metrics_rollups(self, session: AsyncSession, hours: int = 24) -> List[Dict[str, Any]]:
        """Fetch historical hourly time-series metrics rollups."""
        return await analytics_engine.get_or_generate_metrics_rollup(session, hours)

    async def get_entity_features(
        self, session: AsyncSession, entity_id: str, feature_group: str = "DEVICE_HOURLY"
    ) -> Dict[str, Any]:
        """Query feature vector for a specified entity from the feature store."""
        return await feature_store.get_features(entity_id=entity_id, feature_group=feature_group, session=session)


analytics_service = AnalyticsService()
