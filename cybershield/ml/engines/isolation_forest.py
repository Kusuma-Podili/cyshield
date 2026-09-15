"""
CyberShield Enterprise - Multi-Feature Isolation Forest Anomaly Detection Engine
Uses unsupervised Scikit-Learn Isolation Forest to score network flows and telemetry events,
identifying port scans, data exfiltration bursts, and abnormal off-hours traffic.
"""

from __future__ import annotations

import os
import time
import pickle
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class IsolationForestEngine:
    """Enterprise Anomaly Detection Engine using Scikit-Learn Isolation Forest."""

    FEATURE_NAMES = [
        "packet_count",
        "byte_count",
        "duration_sec",
        "dst_port",
        "bytes_out_ratio",
        "is_off_hours",
    ]

    def __init__(self, contamination: float = 0.1, n_estimators: int = 100):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.is_trained: bool = False
        self.training_metrics: Dict[str, Any] = {}

    def _extract_vector(self, item: Dict[str, Any]) -> List[float]:
        """Convert a feature dictionary into an ordered numeric vector."""
        return [
            float(item.get("packet_count", 0.0)),
            float(item.get("byte_count", 0.0)),
            float(item.get("duration_sec", 0.0)),
            float(item.get("dst_port", 80)),
            float(item.get("bytes_out_ratio", 0.5)),
            1.0 if item.get("is_off_hours") else 0.0,
        ]

    def fit(self, dataset: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train the Isolation Forest model and standard scaler on the dataset."""
        start_time = time.perf_counter()

        if len(dataset) < 10:
            raise ValueError("Dataset must contain at least 10 samples for Isolation Forest training.")

        X = np.array([self._extract_vector(item) for item in dataset], dtype=np.float64)

        # Fit Scaler
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Fit Isolation Forest
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)
        self.is_trained = True

        duration = time.perf_counter() - start_time

        # Compute training metrics
        raw_scores = self.model.score_samples(X_scaled)
        preds = self.model.predict(X_scaled)  # -1 for anomaly, 1 for inlier
        detected_anomalies = int(np.sum(preds == -1))

        self.training_metrics = {
            "samples_trained": len(dataset),
            "features_count": len(self.FEATURE_NAMES),
            "contamination_parameter": self.contamination,
            "n_estimators": self.n_estimators,
            "detected_anomalies": detected_anomalies,
            "anomaly_rate": round(detected_anomalies / len(dataset), 4),
            "avg_anomaly_score": round(float(np.mean(raw_scores)), 4),
            "training_duration_sec": round(duration, 3),
        }
        return self.training_metrics

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate a single telemetry/flow sample and return anomaly classifications and risk scores.
        """
        start_time = time.perf_counter()

        if not self.is_trained or self.model is None or self.scaler is None:
            # Fallback heuristic if not yet trained
            vec = self._extract_vector(features)
            # Default auto-train on standard synthetic batch
            from cybershield.ml.datasets.generator import SecurityDatasetGenerator
            synth = SecurityDatasetGenerator.generate_netflow_dataset(n_samples=500)
            self.fit(synth)

        vec = np.array([self._extract_vector(features)], dtype=np.float64)
        vec_scaled = self.scaler.transform(vec)

        # raw score: lower (more negative) means more anomalous
        raw_score = float(self.model.score_samples(vec_scaled)[0])
        pred = int(self.model.predict(vec_scaled)[0])  # -1 or 1

        is_anomaly = (pred == -1)

        # Scale raw_score (-0.8 to -0.3 typical) to 0-100 risk score
        # Normal samples typically score -0.35 to -0.45; extreme anomalies < -0.65
        offset = -0.38
        if raw_score < offset:
            # Anomaly region
            risk_score = min(100.0, 50.0 + (offset - raw_score) * 200.0)
        else:
            # Inlier region
            risk_score = max(0.0, 50.0 - (raw_score - offset) * 150.0)

        risk_score = round(risk_score, 1)

        if risk_score >= 80.0:
            classification = "HIGH_ANOMALY"
        elif risk_score >= 50.0:
            classification = "SUSPICIOUS"
        else:
            classification = "NORMAL"

        reasons = []
        if features.get("bytes_out_ratio", 0.0) > 0.9 and features.get("byte_count", 0) > 500000:
            reasons.append("High volume outbound egress ratio (possible exfiltration)")
        if features.get("packet_count", 0) > 10000 and features.get("duration_sec", 1.0) < 2.0:
            reasons.append("Extreme packet burst rate per second (potential flood/DDoS)")
        if features.get("is_off_hours"):
            reasons.append("Unusual off-hours execution window")
        if features.get("dst_port", 0) > 1024 and features.get("packet_count", 0) <= 3:
            reasons.append("Ephemeral high-port connection probe (potential port scan)")

        explanation = "; ".join(reasons) if reasons else "Traffic flow metrics match normal operational baseline."

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(raw_score, 4),
            "risk_score": risk_score,
            "confidence": round(min(1.0, abs(raw_score) * 1.5), 2),
            "classification": classification,
            "explanation": explanation,
            "latency_ms": elapsed_ms,
        }

    def save(self, filepath: str) -> None:
        """Serialize model and scaler to disk."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "wb") as f:
            pickle.dump({
                "model": self.model,
                "scaler": self.scaler,
                "contamination": self.contamination,
                "n_estimators": self.n_estimators,
                "training_metrics": self.training_metrics,
            }, f)

    def load(self, filepath: str) -> None:
        """Deserialize model and scaler from disk."""
        with open(filepath, "rb") as f:
            data = pickle.load(f)
            self.model = data["model"]
            self.scaler = data["scaler"]
            self.contamination = data["contamination"]
            self.n_estimators = data["n_estimators"]
            self.training_metrics = data.get("training_metrics", {})
            self.is_trained = True
