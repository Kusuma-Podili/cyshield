"""
Unit and integration tests for Post-Quantum Cryptography & Quantum Readiness Subsystem.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.postquantum.engine import PostQuantumEngine
from cybershield.postquantum.schemas import (
    CryptoAsset,
    MoscaTheoremRequest,
    PQAlgorithmType,
    QuantumRiskTier,
)


@pytest.fixture
def engine():
    return PostQuantumEngine()


@pytest.fixture
def client():
    return TestClient(app)


def test_quantum_algorithm_vulnerability_matrix(engine):
    # Shor's Algorithm attacks
    risk_rsa, _ = engine.evaluate_algorithm(PQAlgorithmType.RSA_2048)
    assert risk_rsa == QuantumRiskTier.SHOR_CRITICAL

    risk_ec, _ = engine.evaluate_algorithm(PQAlgorithmType.ECDSA_P256)
    assert risk_ec == QuantumRiskTier.SHOR_CRITICAL

    # Grover's Algorithm attacks
    risk_aes128, _ = engine.evaluate_algorithm(PQAlgorithmType.AES_128_GCM)
    assert risk_aes128 == QuantumRiskTier.GROVER_VULNERABLE

    # Post-Quantum Safe algorithms
    risk_aes256, _ = engine.evaluate_algorithm(PQAlgorithmType.AES_256_GCM)
    assert risk_aes256 == QuantumRiskTier.QUANTUM_SAFE

    risk_ml_kem, _ = engine.evaluate_algorithm(PQAlgorithmType.ML_KEM_768)
    assert risk_ml_kem == QuantumRiskTier.QUANTUM_SAFE

    risk_ml_dsa, _ = engine.evaluate_algorithm(PQAlgorithmType.ML_DSA_65)
    assert risk_ml_dsa == QuantumRiskTier.QUANTUM_SAFE


def test_hybrid_kem_dual_layer_exchange(engine):
    exchange = engine.perform_hybrid_kem_exchange()
    assert exchange.quantum_safety_confirmed is True
    assert len(exchange.classical_public_key_hex) == 64
    assert len(exchange.pqc_public_key_hex) == 64
    assert len(exchange.combined_shared_secret_sha256) == 64
    assert exchange.session_id.startswith("HYBRID-KEM-")


def test_mosca_theorem_hndl_exposure(engine):
    # Case 1: Vulnerable to Harvest Now Decrypt Later (X=15, Y=4, Z=10 -> 19 > 10)
    vuln_req = MoscaTheoremRequest(
        data_shelf_life_years=15.0,
        migration_time_years=4.0,
        estimated_qday_years=10.0
    )
    vuln_res = engine.evaluate_mosca_theorem(vuln_req)
    assert vuln_res.is_vulnerable_to_hndl is True
    assert vuln_res.total_exposure_window_years == 19.0
    assert vuln_res.quantum_readiness_score < 50.0
    assert "CRITICAL VULNERABILITY" in vuln_res.risk_summary

    # Case 2: Secure Buffer (X=2, Y=2, Z=12 -> 4 < 12)
    safe_req = MoscaTheoremRequest(
        data_shelf_life_years=2.0,
        migration_time_years=2.0,
        estimated_qday_years=12.0
    )
    safe_res = engine.evaluate_mosca_theorem(safe_req)
    assert safe_res.is_vulnerable_to_hndl is False
    assert safe_res.quantum_readiness_score >= 80.0


def test_crypto_asset_inventory_management(engine):
    assets = engine.list_assets()
    assert len(assets) >= 5

    # Register custom PQC asset
    custom_asset = CryptoAsset(
        asset_id="CRYPTO-TEST-99",
        name="NextGen PQC Microservice Gateway",
        target_service="gRPC Service Mesh",
        current_algorithm=PQAlgorithmType.ML_KEM_768,
        key_size_bits=768,
        quantum_risk=QuantumRiskTier.QUANTUM_SAFE,
        recommended_pqc_replacement="Already quantum safe"
    )
    engine.add_asset(custom_asset)
    assert any(a.asset_id == "CRYPTO-TEST-99" for a in engine.list_assets())


def test_postquantum_api_lifecycle(client):
    # 1. List assets
    assets_res = client.get("/api/postquantum/assets")
    assert assets_res.status_code == 200
    assert len(assets_res.json()) >= 5

    # 2. Evaluate algorithm via API
    eval_res = client.post("/api/postquantum/evaluate-algorithm?algorithm=RSA_2048")
    assert eval_res.status_code == 200
    assert eval_res.json()["quantum_risk"] == "SHOR_CRITICAL"

    # 3. Perform Hybrid KEM via API
    kem_res = client.post("/api/postquantum/hybrid-kem")
    assert kem_res.status_code == 200
    assert kem_res.json()["quantum_safety_confirmed"] is True

    # 4. Evaluate Mosca's Theorem via API
    mosca_payload = {
        "data_shelf_life_years": 12.0,
        "migration_time_years": 3.0,
        "estimated_qday_years": 8.0
    }
    mosca_res = client.post("/api/postquantum/mosca-theorem", json=mosca_payload)
    assert mosca_res.status_code == 200
    assert mosca_res.json()["is_vulnerable_to_hndl"] is True

    # 5. Get overview
    ovr_res = client.get("/api/postquantum/overview")
    assert ovr_res.status_code == 200
    assert ovr_res.json()["total_monitored_crypto_assets"] >= 5
    assert len(ovr_res.json()["nist_pqc_standards_supported"]) >= 4
