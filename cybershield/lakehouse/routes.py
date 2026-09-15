"""
Security Data Lakehouse REST API Routes.
Exposes endpoints for managing lakehouse tables, micro-batch ingestion, and vectorized columnar queries.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.lakehouse.engine import SecurityLakehouseEngine
from cybershield.lakehouse.schemas import (
    LakehouseIngestRequest,
    LakehouseQueryRequest,
    LakehouseQueryResult,
    LakehouseTableMetadata,
)

lakehouse_router = APIRouter(prefix="/api/lakehouse", tags=["Security Data Lakehouse"])
lakehouse_engine = SecurityLakehouseEngine()


@lakehouse_router.get("/tables", response_model=List[LakehouseTableMetadata])
async def list_tables():
    """List registered lakehouse tables, row counts, and compression ratios."""
    return lakehouse_engine.list_tables()


@lakehouse_router.get("/tables/{table_name}", response_model=LakehouseTableMetadata)
async def get_table(table_name: str):
    """Retrieve metadata and schema for a lakehouse table."""
    tbl = lakehouse_engine.get_table_metadata(table_name)
    if not tbl:
        raise HTTPException(status_code=404, detail=f"Table '{table_name}' not found")
    return tbl


@lakehouse_router.post("/tables", response_model=LakehouseTableMetadata, status_code=status.HTTP_201_CREATED)
async def create_table(metadata: LakehouseTableMetadata):
    """Register a new columnar table in the security lakehouse."""
    return lakehouse_engine.create_table(metadata)


@lakehouse_router.post("/ingest")
async def ingest_batch(payload: LakehouseIngestRequest):
    """Ingest micro-batch of telemetry into partitioned columnar storage."""
    try:
        return lakehouse_engine.ingest_batch(payload)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@lakehouse_router.post("/query", response_model=LakehouseQueryResult)
async def execute_query(query: LakehouseQueryRequest):
    """Execute a high-performance vectorized query with predicate pushdown and partition pruning."""
    try:
        return lakehouse_engine.execute_query(query)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@lakehouse_router.get("/stats")
async def get_stats():
    """Get overall lakehouse storage volume, total rows, and compression ratios."""
    return lakehouse_engine.get_lakehouse_stats()
