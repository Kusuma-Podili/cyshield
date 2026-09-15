"""
CyberShield Enterprise - Columnar Storage & Fast Security Data Lake REST Routes
Provides endpoints for high-speed telemetry ingestion, vectorized query execution,
and automated storage compaction.
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List

from cybershield.columnar.schemas import (
    ColumnarQueryRequest,
    ColumnarQueryResult,
    StorageCompactionReport,
)
from cybershield.columnar.engine import ColumnarDataLakeEngine

router = APIRouter(prefix="/api/v1/columnar", tags=["Security Data Lake Columnar Engine"])

_lake_engine = ColumnarDataLakeEngine()


def get_lake_engine() -> ColumnarDataLakeEngine:
    return _lake_engine


@router.post("/ingest/{table_name}", response_model=Dict[str, Any])
def ingest_rows(
    table_name: str, rows: List[Dict[str, Any]], engine: ColumnarDataLakeEngine = Depends(get_lake_engine)
):
    """Ingest a batch of JSON security event rows into compressed columnar chunks."""
    try:
        chunks_created = engine.append_rows(table_name, rows)
        return {
            "status": "success",
            "table_name": table_name,
            "rows_ingested": len(rows),
            "chunks_created": chunks_created,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Ingestion failed: {str(e)}")


@router.post("/query", response_model=ColumnarQueryResult)
def execute_query(req: ColumnarQueryRequest, engine: ColumnarDataLakeEngine = Depends(get_lake_engine)):
    """Execute fast vectorized columnar query with Bloom filter and Min/Max page skipping."""
    try:
        result = engine.query(req)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Query execution failed: {str(e)}")


@router.post("/compact/{table_name}", response_model=StorageCompactionReport)
def compact_table(table_name: str, engine: ColumnarDataLakeEngine = Depends(get_lake_engine)):
    """Consolidate fragmented small chunks into optimized large columnar segments."""
    try:
        report = engine.compact_table(table_name)
        return report
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Compaction failed: {str(e)}")


@router.get("/tables", response_model=Dict[str, Any])
def list_tables(engine: ColumnarDataLakeEngine = Depends(get_lake_engine)):
    """List all registered lakehouse tables, chunk counts, and total rows."""
    stats = {}
    for tbl, chunks in engine.tables.items():
        total_rows = sum(c.row_count for c in chunks)
        stats[tbl] = {
            "chunks": len(chunks),
            "total_rows": total_rows,
            "columns": list(chunks[0].columns.keys()) if chunks else [],
        }
    return {"tables": stats}


@router.get("/stats/summary")
def get_stats_summary(engine: ColumnarDataLakeEngine = Depends(get_lake_engine)) -> Dict[str, Any]:
    """Retrieve aggregate lakehouse storage metrics."""
    total_chunks = sum(len(chunks) for chunks in engine.tables.values())
    total_rows = sum(sum(c.row_count for c in chunks) for chunks in engine.tables.values())
    return {
        "status": "active",
        "total_tables": len(engine.tables),
        "total_chunks": total_chunks,
        "total_rows": total_rows,
        "compression_types": ["zlib", "dictionary", "rle"],
        "bloom_filter_enabled": True,
    }


@router.get("/health")
def health():
    return {"status": "healthy", "service": "columnar-data-lake", "version": "1.0.0"}
