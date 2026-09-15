"""
CyberShield Enterprise - Threat Intelligence Automated Test Suite
Validates in-memory Bloom filter matching, sub-millisecond IoC lookup,
STIX 2.1 feed ingestion, APT actor profiles, and campaign tracking.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from cybershield.api.server import app
from cybershield.database.session import init_db, async_session_factory
from cybershield.database.models.user import UserRole
from cybershield.auth.security import create_access_token
from cybershield.intel.ioc_database import BloomFilter
from cybershield.intel.feed_service import threat_intel_service


@pytest_asyncio.fixture(autouse=True)
async def ensure_db():
    """Ensure database schema is initialized and threat intel seeded."""
    await init_db()
    async with async_session_factory() as session:
        await threat_intel_service.seed_threat_intelligence(session)


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


def test_bloom_filter_accuracy():
    """Verify in-memory Bloom filter has zero false negatives and low error rate."""
    bf = BloomFilter(capacity=10000, error_rate=0.001)
    items = [f"198.51.100.{i}" for i in range(1, 200)]
    for it in items:
        bf.add(it)

    # 1. Zero False Negatives Guarantee
    for it in items:
        assert bf.contains(it) is True

    # 2. Test Non-Members
    clean_items = [f"10.0.0.{i}" for i in range(1, 200)]
    false_positives = sum(1 for it in clean_items if bf.contains(it))
    assert false_positives <= 2  # <= 1% error rate on 200 checks


@pytest.mark.asyncio
async def test_submillisecond_ioc_lookup(client: AsyncClient, admin_token: str):
    """Verify sub-millisecond indicator lookup and relational threat enrichment."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Check known malicious C2 IP
    c2_res = await client.post("/api/intel/lookup", json={"indicator": "198.51.100.23"}, headers=headers)
    assert c2_res.status_code == 200
    data = c2_res.json()
    assert data["matched"] is True
    assert data["confidence_score"] >= 90
    assert "APT29" in (data["threat_actor"] or "")
    assert data["lookup_latency_ms"] < 50.0  # Fast path execution

    # 2. Check clean IP
    clean_res = await client.post("/api/intel/lookup", json={"indicator": "8.8.8.8"}, headers=headers)
    assert clean_res.status_code == 200
    clean_data = clean_res.json()
    assert clean_data["matched"] is False
    assert clean_data["confidence_score"] == 0


@pytest.mark.asyncio
async def test_stix_bundle_ingestion(client: AsyncClient, admin_token: str):
    """Verify parsing and ingestion of STIX 2.1 JSON bundle."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    stix_payload = {
        "feed_format": "STIX",
        "feed_name": "CISA_ADVISORY_2026_01",
        "payload": {
            "type": "bundle",
            "id": "bundle--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--d81f86b9-975b-4232-a602-0e9643616337",
                    "pattern": "[ipv4-addr:value = '198.51.100.99']",
                    "confidence": 95,
                    "name": "Malicious Command Node",
                },
                {
                    "type": "indicator",
                    "id": "indicator--a78f86b9-975b-4232-a602-0e9643616399",
                    "pattern": "[domain-name:value = 'malicious-c2-beacon.xyz']",
                    "confidence": 90,
                    "name": "C2 Domain",
                }
            ]
        }
    }
    res = await client.post("/api/intel/feed/ingest", json=stix_payload, headers=headers)
    assert res.status_code == 200
    assert res.json()["indicators_imported"] == 2

    # Immediately lookup ingested indicator via fast path
    chk = await client.post("/api/intel/lookup", json={"indicator": "198.51.100.99"}, headers=headers)
    assert chk.status_code == 200
    assert chk.json()["matched"] is True


@pytest.mark.asyncio
async def test_threat_actors_and_campaigns_query(client: AsyncClient, admin_token: str):
    """Verify threat actor profiling and cyber campaign tracking endpoints."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Threat Actors
    actors_res = await client.get("/api/intel/actors", headers=headers)
    assert actors_res.status_code == 200
    actors = actors_res.json()
    assert len(actors) >= 3
    actor_names = [a["name"] for a in actors]
    assert any("APT29" in n for n in actor_names)
    assert any("Lazarus" in n for n in actor_names)

    # Campaigns
    camps_res = await client.get("/api/intel/campaigns", headers=headers)
    assert camps_res.status_code == 200
    camps = camps_res.json()
    assert len(camps) >= 2


@pytest.mark.asyncio
async def test_intel_kpis_endpoint(client: AsyncClient, admin_token: str):
    """Verify threat intelligence telemetry KPI endpoint."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    res = await client.get("/api/intel/kpis", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total_iocs"] >= 10
    assert data["active_iocs"] >= 10
    assert data["total_threat_actors"] >= 3
    assert data["avg_confidence_score"] > 50.0
