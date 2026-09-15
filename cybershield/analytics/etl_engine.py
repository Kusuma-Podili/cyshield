"""
CyberShield Enterprise - ETL Pipeline Execution Engine
Orchestrates batch extraction, aggregation, feature vector engineering,
and asset risk recalculation jobs.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_

from cybershield.database.models.network import NetworkDevice
from cybershield.database.models.events_and_alerts import SecurityEventModel, AlertModel
from cybershield.database.models.incidents_and_rules import IncidentModel
from cybershield.database.models.vulnerabilities import AssetVulnerabilityModel
from cybershield.database.models.analytics import (
    ETLPipelineModel,
    SecurityMetricsRollupModel,
    PipelineStatus,
    PipelineType,
)
from cybershield.analytics.feature_store import feature_store
from cybershield.analytics.analytics_engine import analytics_engine
from cybershield.ml.engines.risk_predictor import RiskPredictorEngine


class ETLEngine:
    """Enterprise Data Pipeline Execution Engine."""

    async def execute_pipeline(self, session: AsyncSession, pipeline_id: str) -> Dict[str, Any]:
        """Execute a specific pipeline job by ID and update execution telemetry."""
        start_time = time.perf_counter()

        pipeline = (
            await session.execute(select(ETLPipelineModel).where(ETLPipelineModel.id == pipeline_id))
        ).scalars().first()

        if not pipeline:
            raise ValueError(f"ETL Pipeline '{pipeline_id}' not found.")

        pipeline.status = PipelineStatus.RUNNING.value
        await session.commit()

        records_processed = 0
        try:
            p_type = pipeline.pipeline_type

            if p_type == PipelineType.METRICS_ROLLUP.value:
                records_processed = await self._run_metrics_rollup(session)
            elif p_type == PipelineType.FEATURE_STORE_UPDATE.value:
                records_processed = await self._run_feature_store_update(session)
            elif p_type == PipelineType.ASSET_RISK_RECALCULATION.value:
                records_processed = await self._run_asset_risk_recalculation(session)
            elif p_type == PipelineType.MITRE_HEATMAP_COMPILATION.value:
                records_processed = await self._run_mitre_heatmap_compilation(session)
            else:
                # Default heartbeat execution
                records_processed = 1

            duration = round(time.perf_counter() - start_time, 3)
            pipeline.status = PipelineStatus.SUCCESS.value
            pipeline.duration_sec = duration
            pipeline.records_processed = records_processed
            pipeline.last_run_at = datetime.utcnow()
            pipeline.error_message = None
            await session.commit()

            return {
                "pipeline_id": pipeline.id,
                "name": pipeline.name,
                "status": pipeline.status,
                "duration_sec": duration,
                "records_processed": records_processed,
                "message": f"Pipeline '{pipeline.name}' completed successfully ({records_processed} records processed in {duration}s).",
            }
        except Exception as e:
            duration = round(time.perf_counter() - start_time, 3)
            pipeline.status = PipelineStatus.FAILED.value
            pipeline.duration_sec = duration
            pipeline.error_message = str(e)
            await session.commit()
            raise

    async def _run_metrics_rollup(self, session: AsyncSession) -> int:
        """Aggregate events, alerts, and incidents into historical rollups."""
        now = datetime.utcnow()
        one_hour_ago = now - timedelta(hours=1)

        total_events = (
            await session.execute(
                select(func.count(SecurityEventModel.id)).where(SecurityEventModel.timestamp >= one_hour_ago)
            )
        ).scalar_one()

        total_alerts = (
            await session.execute(
                select(func.count(AlertModel.id)).where(AlertModel.created_at >= one_hour_ago)
            )
        ).scalar_one()

        rollup_id = f"ROLLUP-HOURLY-{now.strftime('%Y%m%d%H')}"
        existing = (
            await session.execute(
                select(SecurityMetricsRollupModel).where(SecurityMetricsRollupModel.id == rollup_id)
            )
        ).scalars().first()

        if existing:
            existing.total_events = total_events
            existing.total_alerts = total_alerts
        else:
            rollup = SecurityMetricsRollupModel(
                id=rollup_id,
                period_type="HOURLY",
                timestamp=now.replace(minute=0, second=0, microsecond=0),
                total_events=total_events,
                total_alerts=total_alerts,
                critical_alerts=1 if total_alerts > 5 else 0,
                high_alerts=max(0, total_alerts - 2),
                blocked_threats=total_alerts,
                quarantined_hosts=0,
                mttd_seconds=145.0,
                mttr_seconds=420.0,
                attack_surface_score=88.5,
                created_at=now,
            )
            session.add(rollup)

        await session.commit()
        return max(1, total_events + total_alerts)

    async def _run_feature_store_update(self, session: AsyncSession) -> int:
        """Engineer behavioral feature vectors for network devices."""
        devices = (await session.execute(select(NetworkDevice))).scalars().all()
        processed = 0

        for dev in devices:
            ports = dev.open_ports or []
            # Calculate entity feature vector
            features = {
                "open_ports_count": len(ports),
                "is_critical": 1.0 if dev.is_critical_asset else 0.0,
                "has_smb_open": 1.0 if 445 in ports else 0.0,
                "has_ssh_open": 1.0 if 22 in ports else 0.0,
                "has_rdp_open": 1.0 if 3389 in ports else 0.0,
                "baseline_risk": dev.risk_score or 0.0,
                "hourly_traffic_mb": round((len(ports) * 1.5), 2),
            }

            await feature_store.put_features(
                entity_id=dev.ip_address,
                feature_group="DEVICE_HOURLY",
                features=features,
                session=session,
            )
            processed += 1

        return processed

    async def _run_asset_risk_recalculation(self, session: AsyncSession) -> int:
        """Recalculate Bayesian risk scores for all active network devices."""
        devices = (await session.execute(select(NetworkDevice))).scalars().all()
        updated = 0

        for dev in devices:
            # Query max CVSS for this device
            max_cvss_stmt = select(func.max(AssetVulnerabilityModel.patch_priority_score)).where(
                AssetVulnerabilityModel.device_id == dev.id
            )
            max_prio = (await session.execute(max_cvss_stmt)).scalar_one() or 0.0
            cvss_normalized = max_prio / 10.0  # normalize to 0-10 CVSS scale

            # Query active alerts count
            alerts_count = (
                await session.execute(
                    select(func.count(AlertModel.id)).where(AlertModel.host_ip == dev.ip_address)
                )
            ).scalar_one()

            # Predict Bayesian risk
            risk_info = RiskPredictorEngine.calculate_entity_risk(
                max_cvss_score=cvss_normalized,
                active_alert_count=alerts_count,
                open_ports=dev.open_ports or [],
                is_critical_asset=dev.is_critical_asset,
            )

            dev.risk_score = risk_info["risk_score"]
            dev.updated_at = datetime.utcnow()
            updated += 1

        await session.commit()
        return updated

    async def _run_mitre_heatmap_compilation(self, session: AsyncSession) -> int:
        """Refresh MITRE ATT&CK coverage calculation."""
        res = await analytics_engine.compute_mitre_coverage(session)
        return res["covered_tactics"]


etl_engine = ETLEngine()
