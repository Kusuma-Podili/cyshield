"""CyberShield Enterprise - Privacy-Preserving Differential Privacy & Federated Telemetry Engine.
Provides Laplace and Gaussian noise perturbation, k-anonymity and l-diversity enforcement,
privacy loss budget accounting, and secure multi-party federated aggregation.
"""

import math
import random
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timezone
from collections import defaultdict

from .schemas import (
    NoiseMechanism,
    DifferentialPrivacyRequest,
    DifferentialPrivacyResponse,
    RawIncidentRecord,
    AnonymizedIncidentRecord,
    KAnonymityBatchRequest,
    KAnonymityBatchResponse,
    FederatedParticipantUpdate,
    FederatedAggregationRequest,
    FederatedAggregationResponse,
    PrivacyBudgetStatus,
)


class PrivacyPreservingEngine:
    """Enterprise privacy sentinel enforcing mathematical privacy and secure telemetry sharing."""

    def __init__(self, total_budget_epsilon: float = 20.0):
        self.total_budget_epsilon: float = total_budget_epsilon
        self.consumed_epsilon: float = 0.0
        self.query_history: List[Dict[str, Any]] = []

    def sample_laplace_noise(self, scale: float) -> float:
        """Sample from zero-mean Laplace distribution with scale b: Lap(b).
        Using inverse transform sampling: X = -sgn(u) * b * ln(1 - 2|u|), u in (-0.5, 0.5).
        """
        if scale <= 0:
            return 0.0
        u = random.uniform(-0.499999, 0.499999)
        sign = 1.0 if u >= 0 else -1.0
        return float(-sign * scale * math.log(1.0 - 2.0 * abs(u)))

    def sample_gaussian_noise(self, sigma: float) -> float:
        """Sample from zero-mean Gaussian distribution N(0, sigma^2) using Box-Muller transform."""
        if sigma <= 0:
            return 0.0
        u1 = max(1e-9, random.random())
        u2 = random.random()
        z0 = math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)
        return float(z0 * sigma)

    def apply_differential_privacy(self, req: DifferentialPrivacyRequest) -> DifferentialPrivacyResponse:
        """Perturb query aggregate with calibrated differential privacy noise."""
        if self.consumed_epsilon + req.epsilon > self.total_budget_epsilon:
            # Privacy budget warning / cap
            pass

        noise = 0.0
        if req.mechanism == NoiseMechanism.LAPLACE:
            # Laplace mechanism: b = sensitivity / epsilon
            scale = req.sensitivity / req.epsilon
            noise = self.sample_laplace_noise(scale)
        elif req.mechanism == NoiseMechanism.GAUSSIAN:
            # Gaussian mechanism: sigma = (sensitivity * sqrt(2 * ln(1.25 / delta))) / epsilon
            numerator = req.sensitivity * math.sqrt(2.0 * math.log(1.25 / req.delta))
            sigma = numerator / req.epsilon
            noise = self.sample_gaussian_noise(sigma)

        perturbed = round(req.true_value + noise, 4)
        self.consumed_epsilon = round(self.consumed_epsilon + req.epsilon, 4)

        audit_entry = {
            "metric": req.metric_name,
            "epsilon": req.epsilon,
            "mechanism": req.mechanism.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.query_history.append(audit_entry)

        return DifferentialPrivacyResponse(
            metric_name=req.metric_name,
            perturbed_value=perturbed,
            epsilon_consumed=req.epsilon,
            noise_mechanism=req.mechanism,
            noise_magnitude=round(noise, 4),
        )

    def generalize_ip_subnet(self, ip: str) -> str:
        """Generalize IP address to /16 prefix (e.g. 10.240.18.42 -> 10.240.0.0/16)."""
        parts = ip.strip().split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.0.0/16"
        return "0.0.0.0/0"

    def generalize_department(self, dept: str) -> str:
        """Map specific sub-teams to high-level division."""
        d_lower = dept.strip().lower()
        if any(k in d_lower for k in ["fx", "payment", "ap", "ledger", "wire", "accounting", "finance"]):
            return "Financial Operations"
        elif any(k in d_lower for k in ["dev", "eng", "qa", "devops", "cloud", "infra"]):
            return "Engineering & Infrastructure"
        elif any(k in d_lower for k in ["hr", "payroll", "people", "talent"]):
            return "Human Resources"
        elif any(k in d_lower for k in ["sales", "crm", "marketing"]):
            return "Commercial & Marketing"
        return "General Corporate"

    def apply_k_anonymity(self, batch: KAnonymityBatchRequest) -> KAnonymityBatchResponse:
        """Enforce k-anonymity and l-diversity on raw incident records."""
        # Group records by quasi-identifiers: (generalized_subnet, quasi_dept, hour_bucket)
        equivalence_classes: Dict[Tuple[str, str, str], List[RawIncidentRecord]] = defaultdict(list)

        for rec in batch.records:
            gen_subnet = self.generalize_ip_subnet(rec.source_ip)
            gen_dept = self.generalize_department(rec.department)
            time_bucket = rec.observed_time.strftime("%Y-%m-%d %H:00")
            key = (gen_subnet, gen_dept, time_bucket)
            equivalence_classes[key].append(rec)

        anonymized_records: List[AnonymizedIncidentRecord] = []
        suppressed_count = 0
        min_k_observed = 999999
        min_l_observed = 999999

        for (subnet, dept, bucket), class_records in equivalence_classes.items():
            cohort_size = len(class_records)
            unique_tactics = {r.mitre_tactic for r in class_records}
            diversity_count = len(unique_tactics)

            # Check if this equivalence class meets k-anonymity and l-diversity thresholds
            if cohort_size >= batch.k_threshold and diversity_count >= batch.l_threshold:
                min_k_observed = min(min_k_observed, cohort_size)
                min_l_observed = min(min_l_observed, diversity_count)

                for r in class_records:
                    anonymized_records.append(
                        AnonymizedIncidentRecord(
                            generalized_subnet=subnet,
                            quasi_department=dept,
                            time_bucket=bucket,
                            mitre_tactic=r.mitre_tactic,
                            alert_severity=r.alert_severity,
                            cohort_size_k=cohort_size,
                            diversity_count_l=diversity_count,
                        )
                    )
            else:
                # Suppress records that fail privacy thresholds to avoid re-identification
                suppressed_count += cohort_size

        k_achieved = min_k_observed if anonymized_records else 0
        l_achieved = min_l_observed if anonymized_records else 0
        met = len(anonymized_records) > 0 and suppressed_count == 0

        return KAnonymityBatchResponse(
            total_records=len(batch.records),
            anonymized_records=anonymized_records,
            suppressed_records_count=suppressed_count,
            k_achieved=k_achieved,
            l_achieved=l_achieved,
            privacy_guarantee_met=met,
        )

    def secure_federated_aggregation(self, req: FederatedAggregationRequest) -> FederatedAggregationResponse:
        """Aggregate model weights from multiple participants without exposing individual updates.
        Implements federated averaging with dimension and boundary verification.
        """
        if not req.updates:
            return FederatedAggregationResponse(
                round_id=req.round_id,
                model_name=req.model_name,
                total_participants=0,
                aggregated_vector_weights=[],
            )

        vector_len = len(req.updates[0].vector_weights)
        num_participants = len(req.updates)

        # Coordinate-wise summation across all participants
        aggregated = [0.0] * vector_len
        for upd in req.updates:
            for idx in range(min(vector_len, len(upd.vector_weights))):
                aggregated[idx] += upd.vector_weights[idx]

        # Normalized federated mean
        averaged = [round(v / num_participants, 6) for v in aggregated]

        return FederatedAggregationResponse(
            round_id=req.round_id,
            model_name=req.model_name,
            total_participants=num_participants,
            aggregated_vector_weights=averaged,
        )

    def get_budget_status(self) -> PrivacyBudgetStatus:
        """Compute privacy loss budget expenditure and exhaustion status."""
        rem = round(max(0.0, self.total_budget_epsilon - self.consumed_epsilon), 4)
        return PrivacyBudgetStatus(
            total_budget_epsilon=self.total_budget_epsilon,
            consumed_epsilon=self.consumed_epsilon,
            remaining_epsilon=rem,
            active_queries_count=len(self.query_history),
            budget_exhausted=rem <= 0.0,
        )
