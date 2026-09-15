"""
Unit and Integration Tests for OASIS TAXII 2.1 Threat Intelligence Server.
Verifies discovery, API roots, collection endpoints, STIX 2.1 querying, and bundle ingestion.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.taxii.schemas import TAXII_MEDIA_TYPE_21
from cybershield.taxii.server import TaxiiServerEngine


@pytest.fixture
def taxii_engine():
    return TaxiiServerEngine()


@pytest.fixture
def client():
    return TestClient(app)


def test_taxii_discovery_and_api_root(taxii_engine):
    disc = taxii_engine.get_discovery()
    assert disc.title == "CyberShield Enterprise TAXII 2.1 Server"
    assert "/taxii2/api/" in disc.api_roots

    api_root = taxii_engine.get_api_root()
    assert "taxii-2.1" in api_root.versions


def test_taxii_collections_and_seeded_objects(taxii_engine):
    cols = taxii_engine.list_collections().collections
    assert len(cols) >= 3
    col_ids = [c.id for c in cols]
    assert "col-cisa-kev" in col_ids
    assert "col-ransomware-iocs" in col_ids

    # Query objects from ransomware collection
    envelope = taxii_engine.get_objects("col-ransomware-iocs")
    assert len(envelope.objects) >= 2
    types = [o["type"] for o in envelope.objects]
    assert "indicator" in types


def test_add_stix_objects_and_query_filter(taxii_engine):
    new_indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--custom-test-01",
        "name": "Malicious Domain C2",
        "pattern": "[domain-name:value = 'badc2-domain.com']",
        "pattern_type": "stix",
        "confidence": 85,
    }

    status_job = taxii_engine.add_objects_to_collection("col-apt-threat-actors", [new_indicator])
    assert status_job.status == "complete"
    assert status_job.success_count == 1

    # Query with match[id]
    env_id = taxii_engine.get_objects("col-apt-threat-actors", match_id="indicator--custom-test-01")
    assert len(env_id.objects) == 1
    assert env_id.objects[0]["id"] == "indicator--custom-test-01"


def test_taxii_api_endpoints(client):
    # 1. Discovery
    resp = client.get("/taxii2/")
    assert resp.status_code == 200
    assert TAXII_MEDIA_TYPE_21 in resp.headers["content-type"]
    assert resp.json()["title"] == "CyberShield Enterprise TAXII 2.1 Server"

    # 2. API Root
    resp = client.get("/taxii2/api/")
    assert resp.status_code == 200
    assert TAXII_MEDIA_TYPE_21 in resp.headers["content-type"]
    assert "taxii-2.1" in resp.json()["versions"]

    # 3. Collections List
    resp = client.get("/taxii2/api/collections/")
    assert resp.status_code == 200
    cols = resp.json()["collections"]
    assert len(cols) >= 3

    # 4. Collection Detail
    resp = client.get("/taxii2/api/collections/col-cisa-kev/")
    assert resp.status_code == 200
    assert resp.json()["id"] == "col-cisa-kev"

    # 5. Collection Objects
    resp = client.get("/taxii2/api/collections/col-cisa-kev/objects/")
    assert resp.status_code == 200
    env = resp.json()
    assert len(env["objects"]) >= 1
    assert any("CVE" in o["name"] for o in env["objects"])

    # 6. Ingest STIX Bundle via POST
    stix_bundle = {
        "type": "bundle",
        "id": "bundle--api-test-001",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--api-ingest-01",
                "name": "Emotet Dropper Hash",
                "pattern": "[file:hashes.'MD5' = '44d88612fea8a8f36de82e1278abb02f']",
                "pattern_type": "stix",
            }
        ]
    }
    resp = client.post("/taxii2/api/collections/col-ransomware-iocs/objects/", json=stix_bundle)
    assert resp.status_code == 202
    status_data = resp.json()
    assert status_data["status"] == "complete"
    assert status_data["success_count"] == 1
    status_id = status_data["id"]

    # 7. Check Ingestion Status
    resp = client.get(f"/taxii2/api/status/{status_id}/")
    assert resp.status_code == 200
    assert resp.json()["id"] == status_id
