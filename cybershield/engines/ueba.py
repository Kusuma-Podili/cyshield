"""User & Entity Behavior Analytics (UEBA) Engine for CyberShield Enterprise.

Profiles baseline behavioral norms per user identity and host endpoint.
Detects credential theft, impossible travel, privilege escalation surges,
and abnormal off-hours activity without external services.
"""

from __future__ import annotations

import logging
import math
from typing import Dict, List, Optional, Tuple, Set, Any
from datetime import datetime, timezone
from dataclasses import dataclass, field
from collections import defaultdict

from cybershield.core.models import (
    NormalizedEvent,
    Alert,
    Severity,
    DetectionEngineType,
    now_utc,
)
from cybershield.config import settings

logger = logging.getLogger("cybershield.engine.ueba")


def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate Great-Circle distance between two coordinates in kilometers."""
    radius_earth_km = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (
        math.sin(dlat / 2.0) ** 2
        + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return radius_earth_km * c


@dataclass
class LoginGeoPoint:
    """Geo-location metadata for a login event."""
    timestamp: datetime
    ip: str
    city: str
    latitude: float
    longitude: float


@dataclass
class UserProfile:
    """Behavioral baseline model for a specific enterprise user account."""
    username: str
    typical_hours: Set[int] = field(default_factory=lambda: set(range(8, 19)))  # 8am to 6pm
    known_hosts: Set[str] = field(default_factory=set)
    known_source_ips: Set[str] = field(default_factory=set)
    known_processes: Set[str] = field(default_factory=set)
    total_events: int = 0
    last_login: Optional[LoginGeoPoint] = None
    historical_risk_scores: List[float] = field(default_factory=list)
    elevated_privilege_count: int = 0


class UEBAEngine:
    """Enterprise UEBA engine performing real-time identity & host behavioral scoring."""

    # Built-in lightweight IP-to-location mapping for corporate internal/external subnets
    GEO_IP_DATABASE: Dict[str, Tuple[str, float, float]] = {
        "10.0.1.": ("New York, US", 40.7128, -74.0060),
        "10.0.2.": ("London, UK", 51.5074, -0.1278),
        "10.0.3.": ("Tokyo, JP", 35.6762, 139.6503),
        "10.0.4.": ("Sydney, AU", -33.8688, 151.2093),
        "192.168.1.": ("Headquarters (Austin, US)", 30.2672, -97.7431),
        "172.16.10.": ("Frankfurt, DE", 50.1109, 8.6821),
        "45.33.32.156": ("Moscow, RU", 55.7558, 37.6173),
        "185.220.101.5": ("Bucharest, RO", 44.4268, 26.1025),
        "103.251.167.20": ("Beijing, CN", 39.9042, 116.4074),
    }

    def __init__(self):
        self._profiles: Dict[str, UserProfile] = {}
        self._process_popularity: Dict[str, int] = defaultdict(int)
        self._initialize_corporate_baselines()

    def _initialize_corporate_baselines(self) -> None:
        """Seed initial corporate personas to simulate realistic enterprise environments."""
        # Standard administrative persona
        admin_profile = UserProfile(username="admin_corp")
        admin_profile.known_hosts.update(["dc-primary.corp", "jumpbox-01.corp"])
        admin_profile.known_processes.update(["powershell.exe", "cmd.exe", "mmc.exe"])
        self._profiles["admin_corp"] = admin_profile

        # Standard developer persona
        dev_profile = UserProfile(username="jdoe_dev")
        dev_profile.known_hosts.update(["dev-ws-104.corp", "git-internal.corp"])
        dev_profile.known_processes.update(["code.exe", "git.exe", "python.exe", "docker.exe"])
        self._profiles["jdoe_dev"] = dev_profile

        # Seed global process baseline
        common_procs = [
            "svchost.exe", "explorer.exe", "chrome.exe", "slack.exe", "code.exe",
            "teams.exe", "outlook.exe", "bash", "sshd", "systemd", "zsh"
        ]
        for p in common_procs:
            self._process_popularity[p] = 500

    def _resolve_geo(self, ip_address: Optional[str]) -> Tuple[str, float, float]:
        """Resolve IP address to approximate geo-coordinates."""
        if not ip_address:
            return ("Unknown", 0.0, 0.0)
        for prefix, geo in self.GEO_IP_DATABASE.items():
            if ip_address.startswith(prefix) or ip_address == prefix:
                return geo
        # Deterministic synthetic hashing for any other IP to facilitate testing
        h = hash(ip_address) % 1000
        lat = 20.0 + (h % 50)
        lon = -100.0 + (h % 120)
        return (f"Region-{h}", lat, lon)

    def get_or_create_profile(self, username: str) -> UserProfile:
        """Fetch or initialize a user profile."""
        if username not in self._profiles:
            self._profiles[username] = UserProfile(username=username)
        return self._profiles[username]

    def evaluate_event(self, event: NormalizedEvent) -> Tuple[float, List[str], Dict[str, Any]]:
        """Evaluate a NormalizedEvent for user/entity behavioral anomalies.
        
        Returns:
            (risk_score_0_to_100, risk_indicators, diagnostic_details)
        """
        if not event.user_name:
            return 0.0, [], {}

        profile = self.get_or_create_profile(event.user_name)
        profile.total_events += 1
        indicators: List[str] = []
        score_penalties: float = 0.0
        details: Dict[str, Any] = {}

        event_time = event.timestamp
        event_hour = event_time.hour

        # 1. Off-hours login anomaly check
        if event_hour not in profile.typical_hours:
            score_penalties += 20.0
            indicators.append(f"Off-Hours Activity at {event_hour:02d}:00 UTC (Usual: 08:00-18:00)")

        # 2. Host anomaly check
        if event.host_name and profile.known_hosts:
            if event.host_name not in profile.known_hosts:
                score_penalties += 25.0
                indicators.append(f"Unprecedented Host Access: '{event.host_name}'")
        if event.host_name:
            profile.known_hosts.add(event.host_name)

        # 3. Impossible Travel Anomaly
        if event.source_ip:
            city, lat, lon = self._resolve_geo(event.source_ip)
            current_geo = LoginGeoPoint(timestamp=event_time, ip=event.source_ip, city=city, latitude=lat, longitude=lon)
            
            if profile.last_login:
                time_diff_hours = max((event_time - profile.last_login.timestamp).total_seconds() / 3600.0, 0.001)
                distance_km = haversine_distance_km(
                    profile.last_login.latitude, profile.last_login.longitude,
                    lat, lon
                )
                speed_kmh = distance_km / time_diff_hours

                details["impossible_travel"] = {
                    "from_city": profile.last_login.city,
                    "to_city": city,
                    "distance_km": round(distance_km, 1),
                    "time_diff_hours": round(time_diff_hours, 2),
                    "speed_kmh": round(speed_kmh, 1),
                }

                if distance_km > 300.0 and speed_kmh > settings.ueba.impossible_travel_speed_kmh:
                    score_penalties += 60.0
                    indicators.append(
                        f"Impossible Travel: Traveled {distance_km:.0f}km from {profile.last_login.city} to {city} "
                        f"in {time_diff_hours:.1f}h ({speed_kmh:.0f} km/h)"
                    )
            
            profile.last_login = current_geo
            profile.known_source_ips.add(event.source_ip)

        # 4. Rare Process Execution
        if event.process_name:
            proc = event.process_name.lower()
            self._process_popularity[proc] += 1
            if profile.known_processes and proc not in profile.known_processes:
                # Check global popularity
                total_procs = sum(self._process_popularity.values()) or 1
                popularity_rate = self._process_popularity[proc] / total_procs
                if popularity_rate < settings.ueba.rare_process_percentile:
                    score_penalties += 30.0
                    indicators.append(f"Anomalous Rare Process Invocation: '{event.process_name}'")
            profile.known_processes.add(proc)

        # 5. Privilege Escalation Spike
        is_priv_event = any(term in (event.command_line or "").lower() for term in [
            "whoami /priv", "sudo su", "mimikatz", "sekurlsa", "privilege::debug", "chmod +s"
        ])
        if is_priv_event:
            profile.elevated_privilege_count += 1
            score_penalties += 40.0
            indicators.append("Suspicious Privilege Escalation Artifact Detected")

        # Clamp composite risk score
        risk_score = round(min(100.0, score_penalties), 2)
        profile.historical_risk_scores.append(risk_score)
        if len(profile.historical_risk_scores) > 100:
            profile.historical_risk_scores.pop(0)

        details["user"] = event.user_name
        details["composite_risk_score"] = risk_score
        details["indicators_count"] = len(indicators)

        return risk_score, indicators, details

    def process_and_alert(self, event: NormalizedEvent) -> Optional[Alert]:
        """Generate high-fidelity UEBA alert if behavioral threshold is crossed."""
        risk_score, indicators, details = self.evaluate_event(event)
        if risk_score < settings.ueba.high_risk_score_cutoff:
            return None

        severity = Severity.CRITICAL if risk_score >= settings.ueba.critical_risk_score_cutoff else Severity.HIGH

        tactics = ["Credential Access", "Defense Evasion"]
        techniques = ["T1078"]  # Valid Accounts
        if any("Impossible Travel" in ind for ind in indicators):
            techniques.append("T1078.004")  # Cloud / Remote Accounts
        if any("Privilege Escalation" in ind for ind in indicators):
            tactics.append("Privilege Escalation")
            techniques.append("T1548")

        return Alert(
            title=f"UEBA Anomaly: Compromised Account Indicator for '{event.user_name}' (Risk: {risk_score:.0f}/100)",
            description="; ".join(indicators),
            severity=severity,
            confidence=round(min(risk_score / 100.0, 0.95), 2),
            detection_engine=DetectionEngineType.UEBA_ENGINE,
            rule_id="UEBA-RISK-001",
            rule_name="User Entity Behavioral Baseline Breach",
            mitre_tactics=tactics,
            mitre_techniques=techniques,
            primary_source_ip=event.source_ip,
            impacted_user=event.user_name,
            impacted_host=event.host_name,
            source_event_ids=[event.event_id],
            metadata=details,
        )


# Global singleton UEBA engine
ueba_engine = UEBAEngine()
