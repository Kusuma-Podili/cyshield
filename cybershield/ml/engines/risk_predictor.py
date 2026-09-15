"""
CyberShield Enterprise - Bayesian Multi-Factor Entity Risk Predictor
Calculates continuous enterprise entity risk scores (0.0 - 100.0)
using weighted Bayesian risk factor aggregation and asset criticality metrics.
"""

from __future__ import annotations

import math
from typing import Dict, Any, List, Optional


class RiskPredictorEngine:
    """Bayesian Multi-Factor Asset & Entity Risk Prediction Engine."""

    PORT_WEIGHTS = {
        445: 25.0,   # SMB / EternalBlue
        3389: 20.0,  # RDP / Brute Force
        22: 12.0,    # SSH
        21: 15.0,    # FTP
        23: 20.0,    # Telnet
        8080: 10.0,  # Web Alternate
        80: 8.0,     # HTTP
        443: 5.0,    # HTTPS
    }

    @classmethod
    def calculate_entity_risk(
        cls,
        max_cvss_score: float = 0.0,
        active_alert_count: int = 0,
        open_ports: Optional[List[int]] = None,
        is_critical_asset: bool = False,
        active_exploit_observed: bool = False,
        ueba_anomaly_score: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Compute continuous composite risk score and return detailed factor contributions.
        """
        ports = open_ports or []

        # Factor 1: Vulnerability / CVSS (0 - 35 points)
        cvss_contribution = min(35.0, max_cvss_score * 3.5)

        # Factor 2: Port Exposure Risk (0 - 20 points)
        raw_port_score = sum(cls.PORT_WEIGHTS.get(p, 2.0) for p in ports)
        port_contribution = min(20.0, raw_port_score * 0.4)

        # Factor 3: Active Incident & Alert Volume (0 - 20 points)
        alert_contribution = min(20.0, math.log1p(active_alert_count) * 6.0)

        # Factor 4: UEBA User Behavioral Anomaly (0 - 15 points)
        ueba_contribution = min(15.0, (ueba_anomaly_score / 100.0) * 15.0)

        # Factor 5: Threat Multipliers
        criticality_multiplier = 1.3 if is_critical_asset else 1.0
        exploit_bonus = 10.0 if active_exploit_observed else 0.0

        raw_sum = (cvss_contribution + port_contribution + alert_contribution + ueba_contribution + exploit_bonus)
        final_risk = min(100.0, raw_sum * criticality_multiplier)
        final_risk = round(final_risk, 1)

        # Classify Tier
        if final_risk >= 80.0:
            tier = "CRITICAL"
        elif final_risk >= 60.0:
            tier = "HIGH"
        elif final_risk >= 35.0:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        breakdown = {
            "vulnerability_cvss": round(cvss_contribution, 1),
            "port_exposure": round(port_contribution, 1),
            "active_alerts": round(alert_contribution, 1),
            "ueba_behavior": round(ueba_contribution, 1),
            "active_exploit_bonus": exploit_bonus,
            "critical_asset_multiplier": criticality_multiplier,
        }

        return {
            "risk_score": final_risk,
            "risk_tier": tier,
            "factor_breakdown": breakdown,
            "requires_containment": final_risk >= 80.0,
        }
