"""
Autonomous IoC Aging and Exponential Decay Engine.
Implements half-life decay equations, sighting reinforcement, and automatic pruning
to maintain optimal signal-to-noise ratio in threat detection pipelines.
"""

import math
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from cybershield.iocdecay.schemas import (
    DecayEvaluationResult,
    DecayIndicator,
    DecayProfile,
    IOCStatus,
    IOCType,
    SightingRecordRequest,
)


class IOCDecayEngine:
    """
    Mathematical indicator aging engine computing continuous confidence decay.
    """

    DEFAULT_PROFILES: Dict[IOCType, DecayProfile] = {
        IOCType.IPV4: DecayProfile(
            ioc_type=IOCType.IPV4, half_life_days=7.0, initial_confidence=90.0, min_retention_score=20.0, sighting_boost=15.0
        ),
        IOCType.IPV6: DecayProfile(
            ioc_type=IOCType.IPV6, half_life_days=7.0, initial_confidence=90.0, min_retention_score=20.0, sighting_boost=15.0
        ),
        IOCType.DOMAIN: DecayProfile(
            ioc_type=IOCType.DOMAIN, half_life_days=21.0, initial_confidence=85.0, min_retention_score=25.0, sighting_boost=20.0
        ),
        IOCType.URL: DecayProfile(
            ioc_type=IOCType.URL, half_life_days=14.0, initial_confidence=80.0, min_retention_score=20.0, sighting_boost=20.0
        ),
        IOCType.SHA256: DecayProfile(
            ioc_type=IOCType.SHA256, half_life_days=365.0, initial_confidence=95.0, min_retention_score=30.0, sighting_boost=10.0
        ),
        IOCType.MD5: DecayProfile(
            ioc_type=IOCType.MD5, half_life_days=365.0, initial_confidence=90.0, min_retention_score=30.0, sighting_boost=10.0
        ),
        IOCType.EMAIL: DecayProfile(
            ioc_type=IOCType.EMAIL, half_life_days=45.0, initial_confidence=80.0, min_retention_score=25.0, sighting_boost=15.0
        ),
        IOCType.SSL_FINGERPRINT: DecayProfile(
            ioc_type=IOCType.SSL_FINGERPRINT, half_life_days=90.0, initial_confidence=90.0, min_retention_score=30.0, sighting_boost=15.0
        ),
    }

    def __init__(self):
        self._profiles = dict(self.DEFAULT_PROFILES)
        self._indicators: Dict[str, DecayIndicator] = {}
        self._seed_sample_indicators()

    def _seed_sample_indicators(self):
        """Seed sample active and aged threat indicators."""
        samples = [
            DecayIndicator(
                indicator_id="IOC-IP-001",
                value="198.51.100.77",
                ioc_type=IOCType.IPV4,
                initial_confidence=90.0,
                current_confidence=90.0,
                first_seen=datetime.utcnow() - timedelta(days=2),
                last_seen=datetime.utcnow() - timedelta(days=2),
                last_decay_calc=datetime.utcnow() - timedelta(days=2),
                sighting_count=3,
                status=IOCStatus.ACTIVE,
                tags=["c2", "cobalt_strike"]
            ),
            DecayIndicator(
                indicator_id="IOC-DOM-002",
                value="malicious-phishing-portal.xyz",
                ioc_type=IOCType.DOMAIN,
                initial_confidence=85.0,
                current_confidence=85.0,
                first_seen=datetime.utcnow() - timedelta(days=15),
                last_seen=datetime.utcnow() - timedelta(days=15),
                last_decay_calc=datetime.utcnow() - timedelta(days=15),
                sighting_count=1,
                status=IOCStatus.ACTIVE,
                tags=["phishing", "credential_harvesting"]
            ),
            DecayIndicator(
                indicator_id="IOC-HASH-003",
                value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                ioc_type=IOCType.SHA256,
                initial_confidence=95.0,
                current_confidence=95.0,
                first_seen=datetime.utcnow() - timedelta(days=60),
                last_seen=datetime.utcnow() - timedelta(days=60),
                last_decay_calc=datetime.utcnow() - timedelta(days=60),
                sighting_count=5,
                status=IOCStatus.ACTIVE,
                tags=["ransomware", "trojan"]
            ),
        ]
        for s in samples:
            self._indicators[s.indicator_id] = s

    def calculate_decay(
        self, indicator: DecayIndicator, now: Optional[datetime] = None
    ) -> DecayEvaluationResult:
        """
        Computes half-life decay: C(t) = C_0 * 2^(-dt / t_half)
        """
        now = now or datetime.utcnow()
        profile = self._profiles.get(
            indicator.ioc_type, self._profiles[IOCType.IPV4]
        )

        dt_seconds = (now - indicator.last_decay_calc).total_seconds()
        dt_days = max(0.0, dt_seconds / 86400.0)

        # Decay equation: 2^(-dt / half_life)
        half_life = profile.half_life_days
        decay_factor = math.pow(2.0, -(dt_days / half_life))
        old_conf = indicator.current_confidence
        new_conf = round(old_conf * decay_factor, 2)

        # Determine new status
        is_pruned = False
        if indicator.status == IOCStatus.WHITELISTED:
            new_conf = old_conf  # Whitelisted indicators never decay
            new_status = IOCStatus.WHITELISTED
        elif new_conf < profile.min_retention_score:
            new_status = IOCStatus.EXPIRED
            is_pruned = True
        elif new_conf < (indicator.initial_confidence * 0.70):
            new_status = IOCStatus.DECAYING
        else:
            new_status = IOCStatus.ACTIVE

        # Update in-place
        indicator.current_confidence = new_conf
        indicator.status = new_status
        indicator.last_decay_calc = now

        return DecayEvaluationResult(
            indicator_id=indicator.indicator_id,
            value=indicator.value,
            old_confidence=old_conf,
            new_confidence=new_conf,
            days_elapsed=round(dt_days, 2),
            status=new_status,
            is_pruned=is_pruned,
        )

    def record_sighting(self, req: SightingRecordRequest) -> DecayIndicator:
        """
        Reinforces indicator confidence when observed in fresh telemetry.
        """
        # Search for existing indicator
        now = datetime.utcnow()
        existing: Optional[DecayIndicator] = None
        for ind in self._indicators.values():
            if ind.value.lower() == req.indicator_value.lower() and ind.ioc_type == req.ioc_type:
                existing = ind
                break

        profile = self._profiles.get(req.ioc_type, self._profiles[IOCType.IPV4])

        if existing:
            # First decay up to now, then boost
            self.calculate_decay(existing, now)
            boosted = min(100.0, existing.current_confidence + profile.sighting_boost)
            existing.current_confidence = round(boosted, 2)
            existing.sighting_count += 1
            existing.last_seen = now
            existing.last_decay_calc = now
            existing.status = IOCStatus.ACTIVE
            return existing
        else:
            new_ind = DecayIndicator(
                indicator_id=f"IOC-{req.ioc_type.value[:3]}-{uuid.uuid4().hex[:6].upper()}",
                value=req.indicator_value,
                ioc_type=req.ioc_type,
                initial_confidence=profile.initial_confidence,
                current_confidence=profile.initial_confidence,
                first_seen=now,
                last_seen=now,
                last_decay_calc=now,
                sighting_count=1,
                status=IOCStatus.ACTIVE,
                source_feed=req.sighting_source,
                tags=[req.sighting_source.lower()]
            )
            self._indicators[new_ind.indicator_id] = new_ind
            return new_ind

    def execute_decay_sweep(self) -> List[DecayEvaluationResult]:
        """Runs temporal decay calculation across all stored indicators."""
        now = datetime.utcnow()
        results: List[DecayEvaluationResult] = []
        for ind in self._indicators.values():
            res = self.calculate_decay(ind, now)
            results.append(res)
        return results

    def add_indicator(self, indicator: DecayIndicator) -> DecayIndicator:
        self._indicators[indicator.indicator_id] = indicator
        return indicator

    def get_indicator(self, indicator_id: str) -> Optional[DecayIndicator]:
        return self._indicators.get(indicator_id)

    def list_indicators(self, status_filter: Optional[IOCStatus] = None) -> List[DecayIndicator]:
        # Compute fresh decay before returning
        now = datetime.utcnow()
        for ind in self._indicators.values():
            self.calculate_decay(ind, now)

        if status_filter:
            return [i for i in self._indicators.values() if i.status == status_filter]
        return list(self._indicators.values())

    def get_active_firewall_feed(self, min_confidence: float = 40.0) -> List[Dict[str, Any]]:
        """Returns verified, unexpired indicators suitable for network blocking."""
        active = self.list_indicators(status_filter=IOCStatus.ACTIVE)
        decaying = self.list_indicators(status_filter=IOCStatus.DECAYING)
        combined = [i for i in (active + decaying) if i.current_confidence >= min_confidence]

        return [
            {
                "indicator_id": i.indicator_id,
                "value": i.value,
                "type": i.ioc_type.value,
                "confidence": i.current_confidence,
                "sighting_count": i.sighting_count,
            }
            for i in combined
        ]

    def get_overview_metrics(self) -> Dict[str, Any]:
        indicators = self.list_indicators()
        status_counts = {"ACTIVE": 0, "DECAYING": 0, "EXPIRED": 0, "WHITELISTED": 0}
        type_counts: Dict[str, int] = {}
        total_conf = 0.0

        for i in indicators:
            s = i.status.value
            status_counts[s] = status_counts.get(s, 0) + 1
            t = i.ioc_type.value
            type_counts[t] = type_counts.get(t, 0) + 1
            total_conf += i.current_confidence

        mean_conf = round(total_conf / len(indicators), 1) if indicators else 0.0

        return {
            "total_tracked_indicators": len(indicators),
            "status_distribution": status_counts,
            "type_distribution": type_counts,
            "mean_confidence_score": mean_conf,
            "pruned_expired_count": status_counts["EXPIRED"],
        }
