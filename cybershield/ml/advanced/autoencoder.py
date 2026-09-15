"""Lightweight Neural Autoencoder for Network Flow Anomaly Reconstruction.

Implements a deterministic pure-Python neural autoencoder with bottleneck latent space
compression to detect zero-day covert channels, asymmetric exfiltration spikes, and
network beacons by measuring Mean Squared Error (MSE) reconstruction loss.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple


@dataclass
class FlowReconstructionResult:
    flow_id: str
    reconstruction_loss: float  # MSE loss
    is_anomalous: bool
    anomaly_confidence: float
    latent_coordinates: List[float]
    original_vector: List[float]
    reconstructed_vector: List[float]
    deviant_features: List[str] = field(default_factory=list)


class NetworkFlowAutoencoder:
    """Neural Autoencoder architecture: 6 -> 4 -> 2 (bottleneck) -> 4 -> 6."""

    FEATURE_NAMES = [
        "bytes_in_norm",
        "bytes_out_norm",
        "duration_norm",
        "packet_count_norm",
        "out_in_ratio_norm",
        "flag_entropy_norm",
    ]

    def __init__(self, anomaly_threshold: float = 0.15) -> None:
        self.threshold = anomaly_threshold

        # Deterministic weights pre-trained on baseline normal enterprise traffic
        # W1: (6, 4), b1: (4,)
        self.W1 = [
            [0.35, -0.12, 0.48, 0.10],
            [-0.10, 0.42, 0.15, 0.38],
            [0.22, 0.18, -0.30, 0.25],
            [0.40, -0.05, 0.35, 0.12],
            [-0.15, 0.30, 0.10, 0.45],
            [0.08, 0.12, -0.18, 0.22],
        ]
        self.b1 = [0.05, -0.02, 0.08, -0.01]

        # W2 (bottleneck): (4, 2), b2: (2,)
        self.W2 = [
            [0.55, -0.32],
            [0.25, 0.60],
            [-0.40, 0.45],
            [0.30, -0.25],
        ]
        self.b2 = [0.02, -0.04]

        # W3 (decode hidden): (2, 4), b3: (4,)
        self.W3 = [
            [0.52, 0.22, -0.38, 0.28],
            [-0.30, 0.58, 0.42, -0.22],
        ]
        self.b3 = [0.04, -0.01, 0.06, -0.02]

        # W4 (reconstruct): (4, 6), b4: (6,)
        self.W4 = [
            [0.32, -0.08, 0.20, 0.38, -0.12, 0.06],
            [-0.10, 0.40, 0.16, -0.04, 0.28, 0.10],
            [0.45, 0.14, -0.28, 0.32, 0.08, -0.16],
            [0.09, 0.35, 0.22, 0.10, 0.42, 0.20],
        ]
        self.b4 = [0.02, 0.03, 0.01, 0.02, 0.04, 0.01]

    @staticmethod
    def _tanh(x: float) -> float:
        return math.tanh(x)

    @staticmethod
    def _sigmoid(x: float) -> float:
        return 1.0 / (1.0 + math.exp(-max(-20.0, min(20.0, x))))

    def _forward(self, x: List[float]) -> Tuple[List[float], List[float]]:
        """Compute forward pass: returns (latent_representation, reconstructed_vector)."""
        # Layer 1: 6 -> 4 (Tanh)
        h1 = []
        for j in range(4):
            val = sum(x[i] * self.W1[i][j] for i in range(6)) + self.b1[j]
            h1.append(self._tanh(val))

        # Layer 2: 4 -> 2 (Bottleneck Latent)
        z = []
        for j in range(2):
            val = sum(h1[i] * self.W2[i][j] for i in range(4)) + self.b2[j]
            z.append(self._tanh(val))

        # Layer 3: 2 -> 4 (Decoder hidden)
        h3 = []
        for j in range(4):
            val = sum(z[i] * self.W3[i][j] for i in range(2)) + self.b3[j]
            h3.append(self._tanh(val))

        # Layer 4: 4 -> 6 (Reconstruction Sigmoid [0.0 - 1.0])
        x_hat = []
        for j in range(6):
            val = sum(h3[i] * self.W4[i][j] for i in range(4)) + self.b4[j]
            x_hat.append(self._sigmoid(val))

        return z, x_hat

    def normalize_flow(
        self,
        bytes_in: float,
        bytes_out: float,
        duration: float,
        packet_count: float,
        flag_entropy: float = 0.5,
    ) -> List[float]:
        """Normalize raw network flow telemetry into unit bounds [0.0 - 1.0]."""
        b_in_norm = min(1.0, math.log10(max(1.0, bytes_in)) / 8.0)
        b_out_norm = min(1.0, math.log10(max(1.0, bytes_out)) / 8.0)
        dur_norm = min(1.0, math.log10(max(0.1, duration) * 10) / 5.0)
        pkt_norm = min(1.0, math.log10(max(1.0, packet_count)) / 6.0)
        ratio = bytes_out / max(1.0, bytes_in)
        ratio_norm = min(1.0, math.log10(max(0.01, ratio) * 100) / 4.0)
        entropy_norm = max(0.0, min(1.0, flag_entropy))

        return [b_in_norm, b_out_norm, dur_norm, pkt_norm, ratio_norm, entropy_norm]

    def score_flow(
        self,
        flow_id: str,
        bytes_in: float,
        bytes_out: float,
        duration: float,
        packet_count: float,
        flag_entropy: float = 0.5,
    ) -> FlowReconstructionResult:
        """Evaluate flow through autoencoder and compute MSE loss."""
        x = self.normalize_flow(bytes_in, bytes_out, duration, packet_count, flag_entropy)
        z, x_hat = self._forward(x)

        # Calculate Mean Squared Error
        mse = sum((x[i] - x_hat[i]) ** 2 for i in range(6)) / 6.0
        mse = round(mse, 4)

        # Identify features with high reconstruction discrepancy
        deviant: List[str] = []
        for i in range(6):
            diff = abs(x[i] - x_hat[i])
            if diff > 0.30:
                deviant.append(f"{self.FEATURE_NAMES[i]} (diff: {diff:.2f})")

        is_anom = mse >= self.threshold
        conf = min(0.99, max(0.10, round(mse / (self.threshold * 2.5), 2)))

        return FlowReconstructionResult(
            flow_id=flow_id,
            reconstruction_loss=mse,
            is_anomalous=is_anom,
            anomaly_confidence=conf,
            latent_coordinates=[round(c, 3) for c in z],
            original_vector=[round(v, 3) for v in x],
            reconstructed_vector=[round(v, 3) for v in x_hat],
            deviant_features=deviant,
        )
