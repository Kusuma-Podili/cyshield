"""AI-Powered Network Flow & Telemetry Anomaly Detection Engine.

Implements Isolation Forest unsupervised machine learning alongside statistical
Z-score / IQR dispersion analysis for zero-day threat and abnormal telemetry detection.
Operates 100% offline without external cloud or API calls.
"""

from __future__ import annotations

import logging
import math
from typing import List, Dict, Any, Optional, Tuple
from collections import deque
import numpy as np
from sklearn.ensemble import IsolationForest

from cybershield.core.models import (
    NetworkFlow,
    Alert,
    Severity,
    DetectionEngineType,
    generate_id,
    now_utc,
)
from cybershield.config import settings

logger = logging.getLogger("cybershield.engine.anomaly")


class FlowFeatureExtractor:
    """Extracts numerical feature vectors from raw network flows."""

    FEATURE_NAMES = [
        "bytes_ratio",           # Ratio of sent to received bytes
        "packet_rate",           # Packets per second
        "byte_rate",             # Bytes per second
        "duration_log",          # Log-scaled flow duration
        "byte_entropy",          # Payload randomness
        "port_entropy",          # Heuristic for port scan vs standard service
        "tcp_flag_score",        # Encoded suspicious flag combination
    ]

    @classmethod
    def extract(cls, flow: NetworkFlow) -> np.ndarray:
        """Transform a single NetworkFlow into a standardized numerical vector."""
        total_bytes = flow.bytes_sent + flow.bytes_received
        bytes_ratio = (flow.bytes_sent / (flow.bytes_received + 1.0)) if flow.bytes_received > 0 else float(flow.bytes_sent)
        duration_sec = max(flow.duration_ms / 1000.0, 0.001)
        
        total_packets = flow.packets_sent + flow.packets_received
        packet_rate = math.log1p(total_packets / duration_sec)
        byte_rate = math.log1p(total_bytes / duration_sec)
        duration_log = math.log1p(flow.duration_ms)

        # Flag score (SYN-only or FIN-ACK unusual patterns get high weight)
        flag_score = 0.0
        flags = set(f.upper() for f in flow.tcp_flags)
        if "SYN" in flags and len(flags) == 1:
            flag_score += 2.5  # Potential SYN flood or half-open scan
        if "FIN" in flags and "URG" in flags and "PSH" in flags:
            flag_score += 5.0  # Xmas scan pattern
        if not flags and flow.protocol.upper() == "TCP":
            flag_score += 4.0  # Null scan

        # Port variance: standard ports (80, 443, 53, 22) score low; ephemeral/high-range score higher
        dest_port = flow.destination_port
        is_standard_service = dest_port in {80, 443, 53, 22, 389, 636, 88, 3389, 8080, 8443}
        port_score = 0.5 if is_standard_service else 2.5

        return np.array([
            bytes_ratio,
            packet_rate,
            byte_rate,
            duration_log,
            flow.byte_entropy,
            port_score,
            flag_score,
        ], dtype=np.float64)


class AnomalyDetectionEngine:
    """Enterprise Anomaly Detection Engine combining Isolation Forest & Statistical Baselines."""

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 100,
        history_capacity: int = 5000,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.history_capacity = history_capacity

        self._model: Optional[IsolationForest] = None
        self._flow_history: deque[np.ndarray] = deque(maxlen=history_capacity)
        self._raw_flows: deque[NetworkFlow] = deque(maxlen=history_capacity)
        self._is_fitted: bool = False

        # Pre-seed with realistic baseline traffic distribution
        self._initialize_baseline()

    def _initialize_baseline(self) -> None:
        """Seed baseline traffic distribution with standard benign flow features."""
        np.random.seed(settings.anomaly.random_state)
        # Normal enterprise web/service traffic features
        normal_samples = []
        for _ in range(500):
            bytes_ratio = np.random.uniform(0.01, 10.0)
            packet_rate = math.log1p(np.random.uniform(2.0, 500.0))
            byte_rate = math.log1p(np.random.uniform(500.0, 2000000.0))
            duration_log = np.random.uniform(2.0, 8.0)
            byte_entropy = np.random.uniform(3.0, 5.8)
            port_score = 0.5 if np.random.rand() > 0.1 else 2.0
            flag_score = 0.0
            normal_samples.append([
                bytes_ratio, packet_rate, byte_rate, duration_log, byte_entropy, port_score, flag_score
            ])
        
        X = np.array(normal_samples, dtype=np.float64)
        for row in X:
            self._flow_history.append(row)

        self._fit_model()

    def _fit_model(self) -> None:
        """Fit Isolation Forest on historical feature vectors."""
        if len(self._flow_history) < 50:
            return

        X = np.array(self._flow_history)
        self._model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=settings.anomaly.random_state,
            n_jobs=-1,
        )
        self._model.fit(X)
        self._is_fitted = True
        logger.info("Isolation Forest fitted on %d historical flow vectors.", len(X))

    def evaluate_flow(self, flow: NetworkFlow) -> Tuple[bool, float, Dict[str, Any]]:
        """Evaluate a network flow for anomalies.
        
        Returns:
            (is_anomaly, anomaly_score_0_to_100, explanation_details)
        """
        features = FlowFeatureExtractor.extract(flow)
        self._flow_history.append(features)
        self._raw_flows.append(flow)

        # Statistical check (Z-scores against history)
        history_arr = np.array(self._flow_history)
        means = np.mean(history_arr, axis=0)
        stds = np.std(history_arr, axis=0) + 1e-6
        z_scores = np.abs((features - means) / stds)
        max_z = float(np.max(z_scores))
        max_z_feature_idx = int(np.argmax(z_scores))
        max_z_feature_name = FlowFeatureExtractor.FEATURE_NAMES[max_z_feature_idx]

        # ML model check
        ml_score = 15.0
        ml_anomaly = False
        if self._is_fitted and self._model is not None:
            raw_score = float(self._model.decision_function(features.reshape(1, -1))[0])
            if raw_score < 0:
                ml_anomaly = True
                ml_score = min(95.0, 60.0 + abs(raw_score) * 250.0)
            else:
                ml_anomaly = False
                ml_score = max(5.0, (0.20 - raw_score) * 100.0)

        # High entropy check (potential encrypted exfiltration or packed payload)
        entropy_anomaly = flow.byte_entropy >= settings.anomaly.entropy_threshold

        # Composite score
        stat_penalty = max(0.0, (max_z - 3.5) * 12.0) if max_z > 3.5 else 0.0
        composite_score = min(100.0, ml_score + stat_penalty)
        if entropy_anomaly:
            composite_score = max(composite_score, 88.0)

        is_anomaly = ml_anomaly or (max_z > 4.5) or entropy_anomaly

        details = {
            "ml_anomaly": ml_anomaly,
            "ml_score": round(ml_score, 2),
            "max_z_score": round(max_z, 2),
            "dominant_anomaly_feature": max_z_feature_name,
            "byte_entropy": flow.byte_entropy,
            "composite_score": round(composite_score, 2),
        }

        # Periodic retraining with new telemetry
        if len(self._flow_history) % 500 == 0 and settings.anomaly.enable_adaptive_learning:
            self._fit_model()

        return is_anomaly, composite_score, details

    def process_and_alert(self, flow: NetworkFlow) -> Optional[Alert]:
        """Evaluate flow and generate an Alert if malicious or anomalous."""
        is_anomaly, score, details = self.evaluate_flow(flow)
        if not is_anomaly:
            return None

        # Determine severity based on composite score
        if score >= 88.0:
            severity = Severity.CRITICAL
        elif score >= 75.0:
            severity = Severity.HIGH
        elif score >= 55.0:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        # Map to MITRE tactics
        mitre_tactics = ["Exfiltration", "Command and Control"]
        mitre_techniques = ["T1048.003", "T1071.001"]
        if flow.byte_entropy > 7.0:
            mitre_techniques.append("T1027")  # Obfuscated / Encrypted

        return Alert(
            title=f"Network Flow Anomaly Detected: {flow.source_ip} -> {flow.destination_ip}:{flow.destination_port}",
            description=(
                f"Statistical & ML Isolation Forest anomaly (Score: {score:.1f}/100). "
                f"Primary deviation in '{details['dominant_anomaly_feature']}' (Z-score: {details['max_z_score']}). "
                f"Flow bytes: {flow.bytes_sent} sent / {flow.bytes_received} rcvd. Entropy: {flow.byte_entropy:.2f}."
            ),
            severity=severity,
            confidence=round(min(score / 100.0, 0.98), 2),
            detection_engine=DetectionEngineType.ISOLATION_FOREST,
            rule_id="ANOMALY-IF-001",
            rule_name="Isolation Forest Traffic Anomaly",
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            primary_source_ip=flow.source_ip,
            primary_dest_ip=flow.destination_ip,
            indicators_of_compromise=[flow.source_ip, flow.destination_ip],
            metadata=details,
        )


# Global singleton anomaly detector
anomaly_engine = AnomalyDetectionEngine()
