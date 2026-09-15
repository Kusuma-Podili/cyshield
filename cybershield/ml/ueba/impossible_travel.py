"""
CyberShield Enterprise - Impossible Travel Detection Engine
Calculates Great-Circle physical distance and transit velocity between consecutive user logins
using the Haversine trigonometric formula to detect concurrent geographic anomalies and credential theft.
"""

from __future__ import annotations

import math
from datetime import datetime
from typing import Dict, Any, Optional, Tuple


class ImpossibleTravelDetector:
    """Detects physically impossible geographic transit between login events."""

    EARTH_RADIUS_KM = 6371.0088
    MAX_COMMERCIAL_SPEED_KMH = 800.0  # Commercial flight cruising speed + customs/boarding

    def __init__(self):
        # In-memory tracking of last known user logins: username -> (timestamp, lat, lon, city, country)
        self._last_locations: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def haversine_distance_km(
        cls, lat1: float, lon1: float, lat2: float, lon2: float
    ) -> float:
        """
        Calculate the great-circle distance between two points on the Earth surface.
        """
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        delta_phi = math.radians(lat2 - lat1)
        delta_lambda = math.radians(lon2 - lon1)

        a = (
            math.sin(delta_phi / 2.0) ** 2
            + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
        )
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
        return cls.EARTH_RADIUS_KM * c

    def evaluate_login(
        self,
        username: str,
        lat: float,
        lon: float,
        timestamp: Optional[datetime] = None,
        city: Optional[str] = None,
        country: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate incoming login against user's previous login location.
        Returns distance, velocity, and impossible travel anomaly verdict.
        """
        now = timestamp or datetime.utcnow()
        prev = self._last_locations.get(username)

        # Update last location
        self._last_locations[username] = {
            "timestamp": now,
            "lat": lat,
            "lon": lon,
            "city": city,
            "country": country,
        }

        if not prev:
            # First recorded login location
            return {
                "impossible_travel": False,
                "distance_km": 0.0,
                "time_delta_hours": 0.0,
                "velocity_kmh": 0.0,
                "reason": "First geographic coordinate recorded for user.",
            }

        prev_time = prev["timestamp"]
        delta_seconds = abs((now - prev_time).total_seconds())
        delta_hours = max(0.0001, delta_seconds / 3600.0)

        distance = self.haversine_distance_km(prev["lat"], prev["lon"], lat, lon)
        velocity = distance / delta_hours

        is_impossible = (velocity > self.MAX_COMMERCIAL_SPEED_KMH and distance > 100.0)

        reason = None
        if is_impossible:
            reason = (
                f"Impossible physical transit: {round(distance, 1)} km in {round(delta_hours, 2)} hrs "
                f"(required speed {round(velocity, 1)} km/h exceeds commercial threshold of {self.MAX_COMMERCIAL_SPEED_KMH} km/h). "
                f"Previous: {prev.get('city') or 'Unknown'}, {prev.get('country') or 'Unknown'} -> Current: {city or 'Unknown'}, {country or 'Unknown'}."
            )

        return {
            "impossible_travel": is_impossible,
            "distance_km": round(distance, 1),
            "time_delta_hours": round(delta_hours, 2),
            "velocity_kmh": round(velocity, 1),
            "reason": reason or "Transit velocity within normal physical bounds.",
            "previous_location": {
                "city": prev.get("city"),
                "country": prev.get("country"),
                "lat": prev["lat"],
                "lon": prev["lon"],
                "time": prev_time.isoformat(),
            }
        }
