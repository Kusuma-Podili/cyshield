"""
Unit and Integration Tests for Security Data Lakehouse Subsystem.
Verifies columnar chunks, min-max skipping, micro-batch ingestion, vectorized query execution, and REST APIs.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.lakehouse.engine import SecurityLakehouseEngine
from cybershield.lakehouse.schemas import (
    AggregationOperation,
    ColumnDataType,
    ColumnSchema,
    LakehouseIngestRequest,
    LakehousePredicate,
    LakehouseQueryRequest,
    PredicateOperator,
    QueryAggregation,
)
from cybershield.lakehouse.storage import ColumnarChunk, ColumnStatistics


@pytest.fixture
def lakehouse_engine():
    return SecurityLakehouseEngine(chunk_max_rows=50)


@pytest.fixture
def client():
    return TestClient(app)


def test_column_statistics_skipping():
    stat = ColumnStatistics("pid")
    stat.update(100)
    stat.update(200)
    stat.update(300)

    assert stat.min_value == 100
    assert stat.max_value == 300
    assert stat.total_count == 3

    # Predicate: pid > 400 -> can skip since max is 300
    p1 = LakehousePredicate(column="pid", operator=PredicateOperator.GREATER_THAN, value=400)
    assert stat.can_skip_predicate(p1) is True

    # Predicate: pid < 50 -> can skip since min is 100
    p2 = LakehousePredicate(column="pid", operator=PredicateOperator.LESS_THAN, value=50)
    assert stat.can_skip_predicate(p2) is True

    # Predicate: pid == 200 -> within range, cannot skip!
    p3 = LakehousePredicate(column="pid", operator=PredicateOperator.EQUALS, value=200)
    assert stat.can_skip_predicate(p3) is False


def test_columnar_chunk_append_and_scan():
    schema = [
        ColumnSchema(name="user", data_type=ColumnDataType.STRING),
        ColumnSchema(name="score", data_type=ColumnDataType.FLOAT),
    ]
    chunk = ColumnarChunk("CHK-TEST", "2026/09/12", schema)

    chunk.append_row({"user": "alice", "score": 95.5})
    chunk.append_row({"user": "bob", "score": 42.0})
    chunk.append_row({"user": "charlie", "score": 88.0})

    assert chunk.row_count == 3
    assert chunk.compressed_bytes > 0
    assert chunk.compressed_bytes < chunk.uncompressed_bytes

    # Scan with predicate: score > 80
    pred = LakehousePredicate(column="score", operator=PredicateOperator.GREATER_THAN, value=80.0)
    results = chunk.scan_columns(projected_columns=["user", "score"], predicates=[pred], limit=10)

    assert len(results) == 2
    users = [r["user"] for r in results]
    assert "alice" in users
    assert "charlie" in users
    assert "bob" not in users


def test_lakehouse_ingestion_and_rollover(lakehouse_engine):
    records = [{"user_name": f"test_user_{i}", "src_ip": "10.0.0.1", "status": "SUCCESS"} for i in range(120)]
    req = LakehouseIngestRequest(table_name="auth_logs", records=records)
    res = lakehouse_engine.ingest_batch(req)

    assert res["status"] == "ingested"
    assert res["records_ingested"] == 120
    tbl = lakehouse_engine.get_table_metadata("auth_logs")
    assert tbl.total_rows >= 200
    assert tbl.total_chunks >= 3
    assert tbl.compression_ratio > 1.0


def test_vectorized_query_with_aggregations(lakehouse_engine):
    # Query edr_events for powershell.exe
    query = LakehouseQueryRequest(
        table_name="edr_events",
        columns=["host_id", "process_name", "user_name"],
        predicates=[
            LakehousePredicate(column="process_name", operator=PredicateOperator.EQUALS, value="powershell.exe")
        ],
        aggregations=[
            QueryAggregation(column="process_name", operation=AggregationOperation.COUNT, output_alias="total_ps_events"),
            QueryAggregation(column="host_id", operation=AggregationOperation.DISTINCT_COUNT, output_alias="distinct_hosts"),
        ],
        limit=100,
    )
    result = lakehouse_engine.execute_query(query)

    assert result.table_name == "edr_events"
    assert result.rows_returned > 0
    assert all(r["process_name"] == "powershell.exe" for r in result.rows)
    assert result.aggregate_results is not None
    assert result.aggregate_results["total_ps_events"] == result.rows_returned
    assert result.aggregate_results["distinct_hosts"] >= 1
    assert result.execution_time_ms >= 0


def test_lakehouse_api_endpoints(client):
    # 1. List tables
    resp = client.get("/api/lakehouse/tables")
    assert resp.status_code == 200
    tables = resp.json()
    assert len(tables) >= 3

    # 2. Get specific table metadata
    resp = client.get("/api/lakehouse/tables/edr_events")
    assert resp.status_code == 200
    assert resp.json()["table_name"] == "edr_events"

    # 3. Ingest batch via API
    ingest_payload = {
        "table_name": "auth_logs",
        "records": [
            {"user_name": "secops_api", "src_ip": "10.10.1.99", "status": "SUCCESS", "auth_method": "FIDO2"}
        ]
    }
    resp = client.post("/api/lakehouse/ingest", json=ingest_payload)
    assert resp.status_code == 200
    assert resp.json()["records_ingested"] == 1

    # 4. Query via API
    query_payload = {
        "table_name": "auth_logs",
        "columns": ["user_name", "status"],
        "predicates": [
            {"column": "user_name", "operator": "==", "value": "secops_api"}
        ],
        "limit": 10,
    }
    resp = client.post("/api/lakehouse/query", json=query_payload)
    assert resp.status_code == 200
    q_res = resp.json()
    assert q_res["rows_returned"] == 1
    assert q_res["rows"][0]["user_name"] == "secops_api"

    # 5. Get overall stats
    resp = client.get("/api/lakehouse/stats")
    assert resp.status_code == 200
    stats = resp.json()
    assert stats["total_tables"] >= 3
    assert stats["total_rows"] > 100
    assert stats["overall_compression_ratio"] > 1.0
