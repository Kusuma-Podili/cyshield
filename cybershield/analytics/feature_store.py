"""
CyberShield Enterprise - High-Performance Online & Offline Feature Store
Provides sub-millisecond feature vector lookups for real-time inference
and durable relational persistence for batch ML model retraining.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Dict, Any, Optional, List

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from cybershield.database.models.analytics import FeatureStoreRecordModel


class FeatureStore:
    """Enterprise Feature Store managing online cache and offline relational vectors."""

    def __init__(self):
        # High-speed in-memory online feature cache: (entity_id, feature_group) -> record dict
        self._online_cache: Dict[Tuple[str, str], Dict[str, Any]] = {}

    async def put_features(
        self,
        entity_id: str,
        feature_group: str,
        features: Dict[str, Any],
        session: Optional[AsyncSession] = None,
    ) -> Dict[str, Any]:
        """Insert or update feature vector in online cache and offline store."""
        now = datetime.utcnow()
        cache_key = (entity_id, feature_group)
        rec_data = {
            "entity_id": entity_id,
            "feature_group": feature_group,
            "feature_vector": features,
            "computed_at": now.isoformat(),
        }
        self._online_cache[cache_key] = rec_data

        if session:
            record_id = f"FEAT-{entity_id[:16]}-{feature_group[:16]}-{now.strftime('%Y%m%d%H')}"
            existing = (
                await session.execute(
                    select(FeatureStoreRecordModel).where(FeatureStoreRecordModel.id == record_id)
                )
            ).scalars().first()

            if existing:
                existing.feature_vector = features
                existing.computed_at = now
            else:
                db_record = FeatureStoreRecordModel(
                    id=record_id,
                    feature_group=feature_group,
                    entity_id=entity_id,
                    feature_vector=features,
                    computed_at=now,
                )
                session.add(db_record)
            await session.commit()

        return rec_data

    async def get_features(
        self,
        entity_id: str,
        feature_group: str = "DEVICE_HOURLY",
        session: Optional[AsyncSession] = None,
    ) -> Dict[str, Any]:
        """Fetch feature vector, querying low-latency online cache before falling back to database."""
        cache_key = (entity_id, feature_group)
        if cache_key in self._online_cache:
            return self._online_cache[cache_key]

        if session:
            stmt = (
                select(FeatureStoreRecordModel)
                .where(
                    and_(
                        FeatureStoreRecordModel.entity_id == entity_id,
                        FeatureStoreRecordModel.feature_group == feature_group,
                    )
                )
                .order_by(FeatureStoreRecordModel.computed_at.desc())
            )
            rec = (await session.execute(stmt)).scalars().first()
            if rec:
                res = rec.to_dict()
                self._online_cache[cache_key] = res
                return res

        # Default synthetic baseline features for unprofiled entities
        default_vector = {
            "failed_logins_1h": 0,
            "unique_dest_ports_1h": 3,
            "outbound_bytes_ratio": 0.35,
            "avg_packet_size": 512.0,
            "total_events_1h": 15,
            "risk_score_baseline": 10.0,
        }
        return {
            "entity_id": entity_id,
            "feature_group": feature_group,
            "feature_vector": default_vector,
            "computed_at": datetime.utcnow().isoformat(),
        }


feature_store = FeatureStore()
