"""
CyberShield Enterprise - User & Entity Behavior Analytics (UEBA) Profiler
Profiles user activity baselines, computes statistical Z-score deviations,
detects off-hours logins, and correlates impossible travel alerts into risk scores.
"""

from __future__ import annotations

import math
import time
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from cybershield.database.models.ml import UserBehaviorBaselineModel
from cybershield.ml.ueba.impossible_travel import ImpossibleTravelDetector


class BehavioralProfiler:
    """Evaluates user telemetry against statistical behavioral baselines."""

    def __init__(self):
        self.travel_detector = ImpossibleTravelDetector()

    async def seed_default_baselines(self, session: AsyncSession) -> int:
        """Seed baseline behavioral profiles for core enterprise personas."""
        count = (await session.execute(select(UserBehaviorBaselineModel))).scalars().all()
        if count:
            return len(count)

        baselines = [
            {
                "id": "UEBA-USER-superadmin",
                "username": "superadmin",
                "typical_login_hours": [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
                "typical_ip_ranges": ["10.0.0.0/16", "192.168.1.0/24"],
                "typical_locations": [{"country": "US", "city": "New York", "lat": 40.7128, "lon": -74.0060}],
                "avg_daily_events": 120.0,
                "avg_bytes_transferred": 5242880.0,  # 5 MB
                "std_dev_bytes": 1048576.0,  # 1 MB
                "accessed_resources": ["/api/system", "/api/auth", "/api/audit", "/api/devices"],
                "risk_score": 15.0,
                "peer_group": "ADMINISTRATOR",
            },
            {
                "id": "UEBA-USER-secadmin",
                "username": "secadmin",
                "typical_login_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
                "typical_ip_ranges": ["10.0.10.0/24"],
                "typical_locations": [{"country": "US", "city": "New York", "lat": 40.7128, "lon": -74.0060}],
                "avg_daily_events": 85.0,
                "avg_bytes_transferred": 2097152.0,  # 2 MB
                "std_dev_bytes": 524288.0,  # 512 KB
                "accessed_resources": ["/api/alerts", "/api/incidents", "/api/detection"],
                "risk_score": 10.0,
                "peer_group": "SECURITY_ANALYST",
            },
            {
                "id": "UEBA-USER-analyst",
                "username": "analyst",
                "typical_login_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
                "typical_ip_ranges": ["10.0.10.0/24"],
                "typical_locations": [{"country": "US", "city": "Boston", "lat": 42.3601, "lon": -71.0589}],
                "avg_daily_events": 60.0,
                "avg_bytes_transferred": 1048576.0,
                "std_dev_bytes": 262144.0,
                "accessed_resources": ["/api/alerts", "/api/telemetry"],
                "risk_score": 8.0,
                "peer_group": "SECURITY_ANALYST",
            },
            {
                "id": "UEBA-USER-finance01",
                "username": "finance01",
                "typical_login_hours": [8, 9, 10, 11, 12, 13, 14, 15, 16],
                "typical_ip_ranges": ["10.0.20.0/24"],
                "typical_locations": [{"country": "US", "city": "Chicago", "lat": 41.8781, "lon": -87.6298}],
                "avg_daily_events": 40.0,
                "avg_bytes_transferred": 524288.0,
                "std_dev_bytes": 131072.0,
                "accessed_resources": ["/erp", "/payroll", "/invoices"],
                "risk_score": 5.0,
                "peer_group": "STANDARD_EMPLOYEE",
            },
        ]

        for b in baselines:
            m = UserBehaviorBaselineModel(
                id=b["id"],
                username=b["username"],
                typical_login_hours=b["typical_login_hours"],
                typical_ip_ranges=b["typical_ip_ranges"],
                typical_locations=b["typical_locations"],
                avg_daily_events=b["avg_daily_events"],
                avg_bytes_transferred=b["avg_bytes_transferred"],
                std_dev_bytes=b["std_dev_bytes"],
                accessed_resources=b["accessed_resources"],
                risk_score=b["risk_score"],
                peer_group=b["peer_group"],
                last_calculated_at=datetime.utcnow(),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            session.add(m)

        await session.commit()
        return len(baselines)

    async def evaluate_event(
        self,
        session: AsyncSession,
        username: str,
        bytes_transferred: Optional[float] = None,
        event_hour: Optional[int] = None,
        login_lat: Optional[float] = None,
        login_lon: Optional[float] = None,
        city: Optional[str] = None,
        country: Optional[str] = None,
        accessed_resource: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate real-time user event against baseline profile.
        Computes Z-scores, checks impossible travel, and returns composite risk score.
        """
        start_time = time.perf_counter()

        # Fetch baseline
        stmt = select(UserBehaviorBaselineModel).where(UserBehaviorBaselineModel.username == username)
        profile = (await session.execute(stmt)).scalars().first()

        anomalies: List[str] = []
        risk_points = 0.0

        if not profile:
            # Create dynamic baseline if user not yet profiled
            profile = UserBehaviorBaselineModel(
                id=f"UEBA-USER-{username}",
                username=username,
                typical_login_hours=[8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                typical_ip_ranges=["10.0.0.0/8"],
                typical_locations=[],
                avg_daily_events=50.0,
                avg_bytes_transferred=1048576.0,
                std_dev_bytes=524288.0,
                accessed_resources=[],
                risk_score=10.0,
                peer_group="STANDARD_EMPLOYEE",
                last_calculated_at=datetime.utcnow(),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            session.add(profile)
            await session.commit()

        # 1. Evaluate Geographic / Travel Velocity
        travel_result = None
        if login_lat is not None and login_lon is not None:
            travel_result = self.travel_detector.evaluate_login(
                username=username,
                lat=login_lat,
                lon=login_lon,
                city=city,
                country=country,
            )
            if travel_result["impossible_travel"]:
                anomalies.append(travel_result["reason"])
                risk_points += 45.0

        # 2. Evaluate Login Time
        hour = event_hour if event_hour is not None else datetime.utcnow().hour
        is_off_hours = False
        typical_hours = profile.typical_login_hours or []
        if typical_hours and hour not in typical_hours:
            is_off_hours = True
            anomalies.append(f"Off-hours login detected at {hour:02d}:00 (typical working hours: {min(typical_hours)}:00 - {max(typical_hours)}:00)")
            risk_points += 20.0

        # 3. Evaluate Data Volume Z-Score
        z_score = 0.0
        if bytes_transferred is not None and profile.std_dev_bytes and profile.std_dev_bytes > 0:
            diff = bytes_transferred - profile.avg_bytes_transferred
            z_score = round(diff / profile.std_dev_bytes, 2)

            if z_score > 3.0:
                anomalies.append(f"Extreme data transfer spike: {round(bytes_transferred / 1048576.0, 2)} MB (Z-Score: +{z_score}σ above baseline)")
                risk_points += min(35.0, z_score * 8.0)
            elif z_score > 2.0:
                anomalies.append(f"Elevated data transfer volume: {round(bytes_transferred / 1048576.0, 2)} MB (Z-Score: +{z_score}σ)")
                risk_points += 15.0

        # 4. Evaluate Resource Access
        if accessed_resource and profile.accessed_resources:
            if accessed_resource not in profile.accessed_resources:
                anomalies.append(f"First-time access to sensitive resource '{accessed_resource}'")
                risk_points += 15.0

        composite_risk = min(100.0, profile.risk_score + risk_points)
        is_anomalous = len(anomalies) > 0

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)

        return {
            "username": username,
            "risk_score": round(composite_risk, 1),
            "is_anomalous": is_anomalous,
            "impossible_travel_detected": travel_result["impossible_travel"] if travel_result else False,
            "distance_km": travel_result.get("distance_km") if travel_result else None,
            "velocity_kmh": travel_result.get("velocity_kmh") if travel_result else None,
            "off_hours_login": is_off_hours,
            "z_score_bytes": z_score,
            "anomalous_factors": anomalies,
            "peer_group": profile.peer_group,
            "latency_ms": elapsed_ms,
        }


behavioral_profiler = BehavioralProfiler()
