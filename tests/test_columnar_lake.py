"""
CyberShield Enterprise - Columnar Storage & Fast Security Data Lake Test Suite
Tests pure-Python columnar serialization, Bloom filter indexing, min/max pruning,
vectorized query filtering, grouped aggregations, and REST API routes.
"""

import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.columnar.schemas import (
    QueryFilterPredicate,
    ColumnarQueryRequest,
)
from cybershield.columnar.engine import (
    ColumnarDataLakeEngine,
    ColumnarChunk,
    SimpleBloomFilter,
)


@pytest.fixture
def lake():
    return ColumnarDataLakeEngine(storage_dir="data/test_lakehouse")


@pytest.fixture
def client():
    return TestClient(app)


# ------------------------------------------------------------------------------
# 1. Bloom Filter & Chunk Serialization Tests
# ------------------------------------------------------------------------------

def test_bloom_filter_indexing():
    bf = SimpleBloomFilter(size_bytes=256)
    bf.add("192.168.1.100")
    bf.add("powershell.exe")

    assert bf.might_contain("192.168.1.100") is True
    assert bf.might_contain("powershell.exe") is True
    assert bf.might_contain("10.0.0.99") is False

    # Test serialization
    hex_str = bf.to_hex()
    restored = SimpleBloomFilter.from_hex(hex_str)
    assert restored.might_contain("192.168.1.100") is True
    assert restored.might_contain("10.0.0.99") is False


def test_columnar_chunk_serialization():
    cols = {
        "host": ["srv-1", "srv-2", "srv-1"],
        "severity": ["HIGH", "INFO", "CRITICAL"],
        "bytes_transferred": [1024, 2048, 4096],
    }
    chunk = ColumnarChunk("chunk-test-1", cols)
    assert chunk.row_count == 3
    assert chunk.metadata["bytes_transferred"].min_value == 1024
    assert chunk.metadata["bytes_transferred"].max_value == 4096

    # Serialize & Deserialize
    data_bytes = chunk.serialize()
    restored = ColumnarChunk.deserialize(data_bytes)
    assert restored.chunk_id == "chunk-test-1"
    assert restored.row_count == 3
    assert restored.columns["host"] == ["srv-1", "srv-2", "srv-1"]


# ------------------------------------------------------------------------------
# 2. Ingestion & Vectorized Query Execution Tests
# ------------------------------------------------------------------------------

def test_lake_ingest_and_query(lake):
    sample_rows = [
        {"host": "WEB-01", "user": "admin", "severity": "CRITICAL", "port": 443, "bytes": 5000},
        {"host": "WEB-01", "user": "guest", "severity": "INFO", "port": 80, "bytes": 200},
        {"host": "DB-01", "user": "postgres", "severity": "HIGH", "port": 5432, "bytes": 12000},
        {"host": "DB-01", "user": "backup", "severity": "INFO", "port": 5432, "bytes": 8000},
        {"host": "DC-01", "user": "SYSTEM", "severity": "CRITICAL", "port": 88, "bytes": 3500},
    ]

    # Ingest in chunks of 2 rows each to test multi-chunk queries and skipping
    lake.append_rows("telemetry", sample_rows, chunk_size=2)
    assert len(lake.tables["telemetry"]) == 3

    # Query 1: Filter on severity == 'CRITICAL'
    req = ColumnarQueryRequest(
        table_name="telemetry",
        filters=[QueryFilterPredicate(column="severity", operator="equals", value="CRITICAL")],
        limit=10,
    )
    res = lake.query(req)
    assert res.matched_rows_count == 2
    hosts = [r["host"] for r in res.rows]
    assert "WEB-01" in hosts
    assert "DC-01" in hosts

    # Query 2: Range filter on port > 1000
    req_range = ColumnarQueryRequest(
        table_name="telemetry",
        filters=[QueryFilterPredicate(column="port", operator="greater_than", value="1000")],
        limit=10,
    )
    res_range = lake.query(req_range)
    assert res_range.matched_rows_count == 2
    assert all(r["host"] == "DB-01" for r in res_range.rows)

    # Query 3: Non-existent item should skip chunks via Bloom filter
    req_skip = ColumnarQueryRequest(
        table_name="telemetry",
        filters=[QueryFilterPredicate(column="host", operator="equals", value="NON_EXISTENT_HOST_XYZ")],
    )
    res_skip = lake.query(req_skip)
    assert res_skip.matched_rows_count == 0
    assert res_skip.chunks_skipped_by_index > 0


def test_lake_aggregations_and_group_by(lake):
    rows = [
        {"host": "APP-1", "status": 200, "latency": 15.0},
        {"host": "APP-1", "status": 500, "latency": 45.0},
        {"host": "APP-2", "status": 200, "latency": 20.0},
        {"host": "APP-2", "status": 200, "latency": 30.0},
    ]
    lake.append_rows("http_logs", rows, chunk_size=10)

    # Count by host
    req_count = ColumnarQueryRequest(
        table_name="http_logs",
        group_by="host",
        aggregate_function="count",
    )
    res_count = lake.query(req_count)
    assert res_count.aggregations["APP-1"] == 2
    assert res_count.aggregations["APP-2"] == 2

    # Avg latency by host
    req_avg = ColumnarQueryRequest(
        table_name="http_logs",
        group_by="host",
        aggregate_function="avg",
        aggregate_column="latency",
    )
    res_avg = lake.query(req_avg)
    assert res_avg.aggregations["APP-1"] == 30.0
    assert res_avg.aggregations["APP-2"] == 25.0


# ------------------------------------------------------------------------------
# 3. Compaction Tests
# ------------------------------------------------------------------------------

def test_lake_compaction(lake):
    small_batches = [{"id": i, "val": f"event_{i}"} for i in range(20)]
    # Ingest 20 rows in 10 tiny chunks (2 rows per chunk)
    lake.append_rows("audit_stream", small_batches, chunk_size=2)
    assert len(lake.tables["audit_stream"]) == 10

    # Compact into target chunk size of 50
    report = lake.compact_table("audit_stream", target_chunk_size=50)
    assert report.segments_before == 10
    assert report.segments_after == 1
    assert len(lake.tables["audit_stream"]) == 1


# ------------------------------------------------------------------------------
# 4. REST API Endpoints Tests
# ------------------------------------------------------------------------------

def test_api_ingest_and_query_flow(client):
    rows = [
        {"endpoint": "PC-01", "event": "LOGON", "risk": 10},
        {"endpoint": "PC-02", "event": "FAILED_LOGON", "risk": 85},
    ]
    # Ingest
    ingest_resp = client.post("/api/v1/columnar/ingest/auth_events", json=rows)
    assert ingest_resp.status_code == 200
    assert ingest_resp.json()["rows_ingested"] == 2

    # Query
    query_payload = {
        "table_name": "auth_events",
        "filters": [{"column": "event", "operator": "equals", "value": "FAILED_LOGON"}],
        "limit": 10,
    }
    query_resp = client.post("/api/v1/columnar/query", json=query_payload)
    assert query_resp.status_code == 200
    data = query_resp.json()
    assert data["matched_rows_count"] == 1
    assert data["rows"][0]["endpoint"] == "PC-02"


def test_api_compact_and_stats(client):
    compact_resp = client.post("/api/v1/columnar/compact/auth_events")
    assert compact_resp.status_code == 200
    assert compact_resp.json()["table_name"] == "auth_events"

    tables_resp = client.get("/api/v1/columnar/tables")
    assert tables_resp.status_code == 200
    assert "auth_events" in tables_resp.json()["tables"]

    stats_resp = client.get("/api/v1/columnar/stats/summary")
    assert stats_resp.status_code == 200
    assert stats_resp.json()["status"] == "active"

    health_resp = client.get("/api/v1/columnar/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["service"] == "columnar-data-lake"
