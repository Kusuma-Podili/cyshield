"""
CyberShield Enterprise - Data Pipelines, Scheduled ETL & Security Analytics Automated Test Suite
Validates Feature Store, 14-Tactic MITRE ATT&CK coverage calculation, Security Posture Index (SPI),
ETL pipeline execution state transitions, and REST API RBAC enforcement.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from cybershield.api.server import app
from cybershield.database.session import init_db, async_session_factory
from cybershield.database.models.user import UserRole
from cybershield.auth.security import create_access_token
from cybershield.analytics.service import analytics_service
from cybershield.analytics.feature_store import feature_store
from cybershield.analytics.analytics_engine import analytics_engine
from cybershield.analytics.etl_engine import etl_engine


@pytest_asyncio.fixture(autouse=True)
async def ensure_db():
    """Ensure database schema is initialized and default ETL pipelines are seeded."""
    await init_db()
    async with async_session_factory() as session:
        await analytics_service.seed_default_pipelines(session)


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
    uname = "analytics_viewer_test"
    await client.post("/api/auth/register", json={
        "username": uname,
        "email": f"{uname}@enterprise.corp",
        "password": "ViewerPassword123!",
        "full_name": "Analytics Viewer User"
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


@pytest.mark.asyncio
async def test_feature_store_cache_and_persistence():
    """Verify FeatureStore online in-memory cache and offline database retrieval."""
    entity_id = "192.168.1.55"
    features_dict = {
        "flow_count_1h": 42.0,
        "bytes_in_ratio": 0.35,
        "distinct_dst_ports": 8.0,
        "mean_payload_entropy": 4.82,
        "failed_login_count": 0.0,
    }

    async with async_session_factory() as session:
        # Store features
        record = await feature_store.put_features(
            entity_id=entity_id,
            feature_group="DEVICE_HOURLY",
            features=features_dict,
            session=session
        )
        assert record["entity_id"] == entity_id
        assert record["feature_group"] == "DEVICE_HOURLY"
        assert record["feature_vector"] == features_dict

        # Retrieve features (should hit online memory cache)
        cached = await feature_store.get_features(entity_id=entity_id, feature_group="DEVICE_HOURLY", session=session)
        assert cached is not None
        assert cached["entity_id"] == entity_id
        assert cached["feature_vector"]["flow_count_1h"] == 42.0
        assert cached["feature_vector"]["mean_payload_entropy"] == 4.82

        # Clear memory cache and test offline database retrieval
        feature_store._online_cache.clear()
        offline_rec = await feature_store.get_features(entity_id=entity_id, feature_group="DEVICE_HOURLY", session=session)
        assert offline_rec is not None
        assert offline_rec["entity_id"] == entity_id
        assert offline_rec["feature_vector"]["bytes_in_ratio"] == 0.35

        # Query unprofiled entity returns default baseline vector
        baseline = await feature_store.get_features(entity_id="10.0.99.99", feature_group="DEVICE_HOURLY", session=session)
        assert baseline is not None
        assert "risk_score_baseline" in baseline["feature_vector"]


@pytest.mark.asyncio
async def test_analytics_engine_posture_and_mitre():
    """Verify Security Posture Index (SPI) mathematical calculation and MITRE ATT&CK coverage matrix."""
    async with async_session_factory() as session:
        # 1. Posture Index Calculation
        posture = await analytics_engine.calculate_security_posture(session)
        assert 0.0 <= posture["overall_score"] <= 100.0
        assert posture["security_grade"] in ["A", "B", "C", "D", "F"]
        assert isinstance(posture["active_incidents_count"], int)
        assert isinstance(posture["critical_unpatched_assets"], int)
        assert isinstance(posture["detection_coverage_score"], float)
        assert len(posture["recommendations"]) >= 1

        # 2. MITRE ATT&CK Coverage
        mitre = await analytics_engine.compute_mitre_coverage(session)
        assert mitre["total_tactics"] == 14
        assert 0.0 <= mitre["coverage_percentage"] <= 100.0
        assert len(mitre["tactics"]) == 14

        # Check key tactics in list
        tactic_names = [t["tactic_name"] for t in mitre["tactics"]]
        assert "Initial Access" in tactic_names
        assert "Execution" in tactic_names
        assert "Exfiltration" in tactic_names
        assert "Command and Control" in tactic_names


@pytest.mark.asyncio
async def test_etl_engine_pipeline_executions():
    """Verify ETL execution engine steps across rollups, feature store, and MITRE heatmap."""
    async with async_session_factory() as session:
        # 1. Hourly Metrics Rollup ETL Pipeline
        res_rollup = await etl_engine.execute_pipeline(session, "ETL-SECURITY-METRICS-HOURLY")
        assert res_rollup["status"] == "SUCCESS"
        assert res_rollup["records_processed"] >= 1
        assert res_rollup["duration_sec"] >= 0

        # 2. Feature Store Update Pipeline
        res_fs = await etl_engine.execute_pipeline(session, "ETL-FEATURE-STORE-UPDATE")
        assert res_fs["status"] == "SUCCESS"
        assert res_fs["records_processed"] >= 1

        # 3. Asset Risk Recalculation Pipeline
        res_risk = await etl_engine.execute_pipeline(session, "ETL-ASSET-RISK-RECALCULATION")
        assert res_risk["status"] == "SUCCESS"
        assert res_risk["records_processed"] >= 1

        # 4. MITRE Heatmap Compilation Pipeline
        res_mitre = await etl_engine.execute_pipeline(session, "ETL-MITRE-HEATMAP-COMPILATION")
        assert res_mitre["status"] == "SUCCESS"
        assert res_mitre["records_processed"] >= 1


@pytest.mark.asyncio
async def test_analytics_service_orchestration():
    """Verify ETL pipeline seeding, listing, and state lifecycle transitions."""
    async with async_session_factory() as session:
        pipelines = await analytics_service.list_pipelines(session)
        assert len(pipelines) >= 4
        names = [p["name"] for p in pipelines]
        assert "Hourly Security Metrics Rollup & Posture Index" in names
        assert "Device & User Behavioral Feature Store Aggregator" in names
        assert "Continuous Bayesian Asset Risk Recalculation" in names
        assert "MITRE ATT&CK Defense Coverage Matrix Rollup" in names

        # Execute first pipeline via the service
        target_pipe_id = pipelines[0]["id"]
        run_res = await analytics_service.execute_pipeline(session, target_pipe_id)
        assert run_res["status"] == "SUCCESS"
        assert run_res["records_processed"] >= 1
        assert run_res["duration_sec"] >= 0

        # Verify pipeline state updated in DB
        updated_pipes = await analytics_service.list_pipelines(session)
        updated_target = next(p for p in updated_pipes if p["id"] == target_pipe_id)
        assert updated_target["status"] == "SUCCESS"
        assert updated_target["last_run_at"] is not None
        assert updated_target["records_processed"] >= 1


@pytest.mark.asyncio
async def test_rest_api_pipelines_and_run(client: AsyncClient, admin_token: str):
    """Verify REST API /api/analytics/pipelines listing and execution endpoints."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. List pipelines
    list_res = await client.get("/api/analytics/pipelines", headers=headers)
    assert list_res.status_code == 200
    pipes = list_res.json()
    assert len(pipes) >= 4

    # 2. Run first pipeline
    first_id = pipes[0]["id"]
    run_res = await client.post(f"/api/analytics/pipelines/{first_id}/run", headers=headers)
    assert run_res.status_code == 200
    run_data = run_res.json()
    assert run_data["pipeline_id"] == first_id
    assert run_data["status"] == "SUCCESS"
    assert run_data["records_processed"] >= 1
    assert "duration_sec" in run_data
    assert "message" in run_data

    # 3. Non-existent pipeline returns 404
    bad_res = await client.post("/api/analytics/pipelines/INVALID-ID/run", headers=headers)
    assert bad_res.status_code == 404


@pytest.mark.asyncio
async def test_rest_api_posture_and_mitre_and_rollups(client: AsyncClient, admin_token: str):
    """Verify REST API posture, MITRE coverage, and hourly metric rollups endpoints."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Security Posture Index
    pos_res = await client.get("/api/analytics/posture", headers=headers)
    assert pos_res.status_code == 200
    pos_data = pos_res.json()
    assert "overall_score" in pos_data
    assert "security_grade" in pos_data
    assert "detection_coverage_score" in pos_data
    assert "active_incidents_count" in pos_data
    assert "critical_unpatched_assets" in pos_data
    assert "recommendations" in pos_data

    # 2. MITRE Coverage Matrix
    mit_res = await client.get("/api/analytics/mitre/coverage", headers=headers)
    assert mit_res.status_code == 200
    mit_data = mit_res.json()
    assert mit_data["total_tactics"] == 14
    assert "coverage_percentage" in mit_data
    assert len(mit_data["tactics"]) == 14

    # 3. Hourly Metric Rollups
    rol_res = await client.get("/api/analytics/metrics/rollup?hours=24", headers=headers)
    assert rol_res.status_code == 200
    rol_data = rol_res.json()
    assert isinstance(rol_data, list)
    assert len(rol_data) >= 1
    first_rollup = rol_data[0]
    assert "period_type" in first_rollup
    assert "total_events" in first_rollup


@pytest.mark.asyncio
async def test_rest_api_features_and_rbac(client: AsyncClient, admin_token: str, viewer_token: str):
    """Verify feature lookup endpoint and RBAC permission checks for pipeline execution."""
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

    # 1. Ingest/Update feature store via ETL first
    await client.post("/api/analytics/pipelines/ETL-FEATURE-STORE-UPDATE/run", headers=admin_headers)

    # 2. Query feature vector as admin
    feat_res = await client.get("/api/analytics/features/192.168.1.100?feature_group=DEVICE_HOURLY", headers=admin_headers)
    assert feat_res.status_code == 200
    feat_data = feat_res.json()
    assert feat_data["entity_id"] == "192.168.1.100"
    assert feat_data["feature_group"] == "DEVICE_HOURLY"
    assert "feature_vector" in feat_data
    assert isinstance(feat_data["feature_vector"], dict)

    # 3. RBAC: Viewer should be able to view pipelines (PIPELINES_VIEW permission granted)
    viewer_list_res = await client.get("/api/analytics/pipelines", headers=viewer_headers)
    assert viewer_list_res.status_code == 200

    # 4. RBAC: Viewer should be FORBIDDEN from running pipelines (PIPELINES_RUN requires ADMIN/SOC_ANALYST)
    viewer_run_res = await client.post("/api/analytics/pipelines/ETL-SECURITY-METRICS-HOURLY/run", headers=viewer_headers)
    assert viewer_run_res.status_code == 403
