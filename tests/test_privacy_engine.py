"""Tests for CyberShield Enterprise - Privacy-Preserving Differential Privacy & Federated Telemetry.
Verifies Laplace & Gaussian noise sampling, privacy budget accounting, k-anonymity / l-diversity,
federated model weight aggregation, and FastAPI REST endpoints.
"""

import json
from datetime import datetime, timezone
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.privacy.schemas import (
    NoiseMechanism,
    DifferentialPrivacyRequest,
    RawIncidentRecord,
    KAnonymityBatchRequest,
    FederatedParticipantUpdate,
    FederatedAggregationRequest,
)
from cybershield.privacy.engine import PrivacyPreservingEngine


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def engine():
    return PrivacyPreservingEngine(total_budget_epsilon=10.0)


# =========================================================================
# Unit Tests: Differential Privacy Mechanisms
# =========================================================================

def test_laplace_mechanism_perturbation(engine):
    req = DifferentialPrivacyRequest(
        metric_name="daily_lateral_movement_count",
        true_value=150.0,
        epsilon=0.5,
        sensitivity=1.0,
        mechanism=NoiseMechanism.LAPLACE,
    )
    resp = engine.apply_differential_privacy(req)
    assert resp.metric_name == "daily_lateral_movement_count"
    assert resp.epsilon_consumed == 0.5
    assert resp.noise_mechanism == NoiseMechanism.LAPLACE
    # The perturbed value should be around 150 with random Laplace noise
    assert abs(resp.perturbed_value - 150.0) < 100.0
    assert engine.consumed_epsilon == 0.5


def test_gaussian_mechanism_perturbation(engine):
    req = DifferentialPrivacyRequest(
        metric_name="c2_beacon_frequency",
        true_value=42.0,
        epsilon=1.0,
        delta=1e-4,
        sensitivity=1.0,
        mechanism=NoiseMechanism.GAUSSIAN,
    )
    resp = engine.apply_differential_privacy(req)
    assert resp.metric_name == "c2_beacon_frequency"
    assert resp.epsilon_consumed == 1.0
    assert resp.noise_mechanism == NoiseMechanism.GAUSSIAN
    assert resp.noise_magnitude != 0.0


def test_privacy_budget_depletion(engine):
    initial_status = engine.get_budget_status()
    assert initial_status.remaining_epsilon == 10.0
    assert initial_status.budget_exhausted is False

    # Consume entire budget
    req = DifferentialPrivacyRequest(
        metric_name="high_privilege_logins",
        true_value=500.0,
        epsilon=10.0,
        sensitivity=1.0,
    )
    engine.apply_differential_privacy(req)

    final_status = engine.get_budget_status()
    assert final_status.remaining_epsilon == 0.0
    assert final_status.budget_exhausted is True


# =========================================================================
# Unit Tests: K-Anonymity & L-Diversity Sanitization
# =========================================================================

def test_quasi_identifier_generalization(engine):
    assert engine.generalize_ip_subnet("10.240.18.42") == "10.240.0.0/16"
    assert engine.generalize_ip_subnet("192.168.1.100") == "192.168.0.0/16"
    assert engine.generalize_department("Core AP Wire Processing") == "Financial Operations"
    assert engine.generalize_department("Cloud DevOps Engineering") == "Engineering & Infrastructure"


def test_k_anonymity_and_l_diversity_enforcement(engine):
    now = datetime.now(timezone.utc)
    # Create 3 records that fall into the same equivalence class
    # (10.240.0.0/16, Financial Operations, current hour)
    # with 2 distinct MITRE tactics (Lateral Movement, Credential Access)
    rec1 = RawIncidentRecord(
        incident_id="inc-01",
        source_ip="10.240.5.12",
        dest_ip="10.240.5.100",
        username="alice",
        department="AP Accounting",
        mitre_tactic="TA0008 - Lateral Movement",
        alert_severity="HIGH",
        observed_time=now,
    )
    rec2 = RawIncidentRecord(
        incident_id="inc-02",
        source_ip="10.240.9.33",
        dest_ip="10.240.5.101",
        username="bob",
        department="FX Wire Team",
        mitre_tactic="TA0006 - Credential Access",
        alert_severity="CRITICAL",
        observed_time=now,
    )
    rec3 = RawIncidentRecord(
        incident_id="inc-03",
        source_ip="10.240.1.20",
        dest_ip="10.240.5.102",
        username="carol",
        department="Treasury Ledger",
        mitre_tactic="TA0008 - Lateral Movement",
        alert_severity="HIGH",
        observed_time=now,
    )
    # Solitary record that will fail k=3
    rec_lonely = RawIncidentRecord(
        incident_id="inc-04",
        source_ip="172.16.88.5",
        dest_ip="172.16.88.1",
        username="dave",
        department="HR Payroll",
        mitre_tactic="TA0001 - Initial Access",
        alert_severity="LOW",
        observed_time=now,
    )

    batch = KAnonymityBatchRequest(
        records=[rec1, rec2, rec3, rec_lonely],
        k_threshold=3,
        l_threshold=2,
    )

    result = engine.apply_k_anonymity(batch)
    assert result.total_records == 4
    assert len(result.anonymized_records) == 3
    assert result.suppressed_records_count == 1  # rec_lonely suppressed
    assert result.k_achieved >= 3
    assert result.l_achieved >= 2


# =========================================================================
# Unit Tests: Federated Learning Secure Aggregation
# =========================================================================

def test_secure_federated_aggregation(engine):
    # 3 regional subsidiaries submitting 4-dimensional anomaly model weights
    p1 = FederatedParticipantUpdate(
        participant_id="sub-us-east",
        subsidiary_name="North America Enterprise",
        vector_weights=[0.1, 0.4, 0.2, 0.8],
    )
    p2 = FederatedParticipantUpdate(
        participant_id="sub-eu-central",
        subsidiary_name="EMEA Subsidiary",
        vector_weights=[0.2, 0.5, 0.1, 0.7],
    )
    p3 = FederatedParticipantUpdate(
        participant_id="sub-ap-south",
        subsidiary_name="APAC Subsidiary",
        vector_weights=[0.3, 0.6, 0.3, 0.9],
    )

    req = FederatedAggregationRequest(
        round_id="fl-round-101",
        model_name="Enterprise-Threat-Anomaly-GNN",
        updates=[p1, p2, p3],
    )

    resp = engine.secure_federated_aggregation(req)
    assert resp.round_id == "fl-round-101"
    assert resp.total_participants == 3
    # Mean of [0.1, 0.2, 0.3] = 0.2
    # Mean of [0.4, 0.5, 0.6] = 0.5
    # Mean of [0.2, 0.1, 0.3] = 0.2
    # Mean of [0.8, 0.7, 0.9] = 0.8
    assert resp.aggregated_vector_weights == [0.2, 0.5, 0.2, 0.8]


# =========================================================================
# Integration Tests: FastAPI REST Endpoints
# =========================================================================

def test_api_differential_privacy_noise(client):
    req = DifferentialPrivacyRequest(
        metric_name="endpoint_quarantine_events",
        true_value=85.0,
        epsilon=0.4,
        sensitivity=1.0,
        mechanism=NoiseMechanism.LAPLACE,
    )
    resp = client.post(
        "/api/v1/privacy/differential",
        json=json.loads(req.model_dump_json()),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["metric_name"] == "endpoint_quarantine_events"
    assert "perturbed_value" in data
    assert data["epsilon_consumed"] == 0.4


def test_api_privacy_budget_endpoint(client):
    resp = client.get("/api/v1/privacy/budget")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_budget_epsilon" in data
    assert "remaining_epsilon" in data
    assert "budget_exhausted" in data


def test_api_federated_aggregation(client):
    req = FederatedAggregationRequest(
        round_id="fl-api-01",
        updates=[
            FederatedParticipantUpdate(
                participant_id="node-1",
                subsidiary_name="Node 1",
                vector_weights=[1.0, 2.0],
            ),
            FederatedParticipantUpdate(
                participant_id="node-2",
                subsidiary_name="Node 2",
                vector_weights=[3.0, 4.0],
            ),
        ],
    )
    resp = client.post(
        "/api/v1/privacy/federated/aggregate",
        json=json.loads(req.model_dump_json()),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_participants"] == 2
    assert data["aggregated_vector_weights"] == [2.0, 3.0]
