"""
Security Data Lakehouse Engine.
Coordinates schema catalogs, micro-batch chunk ingestion, partition pruning, and vectorized queries.
"""

import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from cybershield.lakehouse.schemas import (
    AggregationOperation,
    ColumnDataType,
    ColumnSchema,
    LakehouseIngestRequest,
    LakehousePredicate,
    LakehouseQueryRequest,
    LakehouseQueryResult,
    LakehouseTableMetadata,
    TablePartitionSpec,
)
from cybershield.lakehouse.storage import ColumnarChunk


DEFAULT_LAKEHOUSE_TABLES: List[LakehouseTableMetadata] = [
    LakehouseTableMetadata(
        table_name="edr_events",
        description="Endpoint Detection and Response process, file, and registry telemetry.",
        columns=[
            ColumnSchema(name="timestamp", data_type=ColumnDataType.TIMESTAMP),
            ColumnSchema(name="host_id", data_type=ColumnDataType.STRING),
            ColumnSchema(name="pid", data_type=ColumnDataType.INTEGER),
            ColumnSchema(name="process_name", data_type=ColumnDataType.STRING),
            ColumnSchema(name="command_line", data_type=ColumnDataType.STRING),
            ColumnSchema(name="user_name", data_type=ColumnDataType.STRING),
            ColumnSchema(name="action", data_type=ColumnDataType.STRING),
        ],
    ),
    LakehouseTableMetadata(
        table_name="network_flows",
        description="Deep packet inspection and Zeek/Suricata flow telemetry.",
        columns=[
            ColumnSchema(name="timestamp", data_type=ColumnDataType.TIMESTAMP),
            ColumnSchema(name="src_ip", data_type=ColumnDataType.STRING),
            ColumnSchema(name="dst_ip", data_type=ColumnDataType.STRING),
            ColumnSchema(name="src_port", data_type=ColumnDataType.INTEGER),
            ColumnSchema(name="dst_port", data_type=ColumnDataType.INTEGER),
            ColumnSchema(name="protocol", data_type=ColumnDataType.STRING),
            ColumnSchema(name="bytes_sent", data_type=ColumnDataType.INTEGER),
            ColumnSchema(name="bytes_recv", data_type=ColumnDataType.INTEGER),
        ],
    ),
    LakehouseTableMetadata(
        table_name="auth_logs",
        description="Unified corporate authentication, Kerberos, and SSO access logs.",
        columns=[
            ColumnSchema(name="timestamp", data_type=ColumnDataType.TIMESTAMP),
            ColumnSchema(name="user_name", data_type=ColumnDataType.STRING),
            ColumnSchema(name="src_ip", data_type=ColumnDataType.STRING),
            ColumnSchema(name="status", data_type=ColumnDataType.STRING),
            ColumnSchema(name="auth_method", data_type=ColumnDataType.STRING),
        ],
    ),
]


class SecurityLakehouseEngine:
    """Security Data Lakehouse Engine for Forensic Log Retention and Analytics."""

    def __init__(self, chunk_max_rows: int = 500):
        self.chunk_max_rows = chunk_max_rows
        self._tables: Dict[str, LakehouseTableMetadata] = {t.table_name: t for t in DEFAULT_LAKEHOUSE_TABLES}
        # Table chunks: table_name -> List[ColumnarChunk]
        self._chunks: Dict[str, List[ColumnarChunk]] = {t.table_name: [] for t in DEFAULT_LAKEHOUSE_TABLES}
        self._seed_sample_lakehouse_data()

    def _seed_sample_lakehouse_data(self):
        """Seed initial realistic telemetry in the lakehouse."""
        now = datetime.utcnow()
        # Seed EDR events
        edr_records = []
        for i in range(120):
            edr_records.append({
                "timestamp": (now - timedelta(minutes=i)).isoformat(),
                "host_id": f"HOST-{100 + (i % 5)}",
                "pid": 1000 + i,
                "process_name": "powershell.exe" if i % 20 == 0 else "svchost.exe",
                "command_line": "powershell.exe -enc ..." if i % 20 == 0 else "C:\\Windows\\system32\\svchost.exe -k netsvcs",
                "user_name": "SYSTEM" if i % 2 == 0 else "analyst_john",
                "action": "PROCESS_SPAWN",
            })
        self.ingest_batch(LakehouseIngestRequest(table_name="edr_events", records=edr_records))

        # Seed auth logs
        auth_records = []
        for i in range(80):
            auth_records.append({
                "timestamp": (now - timedelta(minutes=i * 2)).isoformat(),
                "user_name": f"user_{i % 10}",
                "src_ip": f"10.0.1.{50 + (i % 10)}",
                "status": "SUCCESS" if i % 7 != 0 else "FAILURE",
                "auth_method": "KERBEROS" if i % 2 == 0 else "MFA_PUSH",
            })
        self.ingest_batch(LakehouseIngestRequest(table_name="auth_logs", records=auth_records))

    def list_tables(self) -> List[LakehouseTableMetadata]:
        return list(self._tables.values())

    def get_table_metadata(self, table_name: str) -> Optional[LakehouseTableMetadata]:
        return self._tables.get(table_name)

    def create_table(self, metadata: LakehouseTableMetadata) -> LakehouseTableMetadata:
        self._tables[metadata.table_name] = metadata
        self._chunks[metadata.table_name] = []
        return metadata

    def ingest_batch(self, request: LakehouseIngestRequest) -> Dict[str, Any]:
        """Micro-batch ingestion into columnar chunks."""
        tbl = self._tables.get(request.table_name)
        if not tbl:
            raise ValueError(f"Table '{request.table_name}' does not exist in lakehouse catalog")

        table_chunks = self._chunks.setdefault(request.table_name, [])

        for row in request.records:
            # Find active chunk or create new
            if not table_chunks or table_chunks[-1].row_count >= self.chunk_max_rows:
                part_key = datetime.utcnow().strftime("%Y/%m/%d")
                new_chunk = ColumnarChunk(
                    chunk_id=f"CHK-{uuid.uuid4().hex[:8].upper()}",
                    partition_key=part_key,
                    schema=tbl.columns,
                )
                table_chunks.append(new_chunk)

            target_chunk = table_chunks[-1]
            target_chunk.append_row(row)

        # Update table statistics
        tbl.total_rows = sum(c.row_count for c in table_chunks)
        tbl.total_chunks = len(table_chunks)
        tbl.uncompressed_bytes = sum(c.uncompressed_bytes for c in table_chunks)
        tbl.compressed_bytes = sum(c.compressed_bytes for c in table_chunks)
        tbl.compression_ratio = (
            round(tbl.uncompressed_bytes / tbl.compressed_bytes, 2)
            if tbl.compressed_bytes > 0
            else 1.0
        )
        tbl.last_ingested_at = datetime.utcnow()

        return {
            "status": "ingested",
            "table_name": request.table_name,
            "records_ingested": len(request.records),
            "total_table_rows": tbl.total_rows,
            "total_chunks": tbl.total_chunks,
        }

    def execute_query(self, query: LakehouseQueryRequest) -> LakehouseQueryResult:
        """Execute a vectorized query with partition pruning and chunk skipping."""
        tbl = self._tables.get(query.table_name)
        if not tbl:
            raise ValueError(f"Table '{query.table_name}' not found")

        t0 = time.perf_counter()
        table_chunks = self._chunks.get(query.table_name, [])

        # Column projection: if None, select all columns
        projected_cols = query.columns or [c.name for c in tbl.columns]

        scanned_chunks = 0
        pruned_chunks = 0
        rows_scanned = 0
        matched_rows: List[Dict[str, Any]] = []

        for chunk in table_chunks:
            # Check partition / chunk skipping using column statistics
            if query.predicates and chunk.evaluate_predicates_skip(query.predicates):
                pruned_chunks += 1
                continue

            scanned_chunks += 1
            rows_scanned += chunk.row_count
            chunk_results = chunk.scan_columns(
                projected_columns=projected_cols,
                predicates=query.predicates,
                limit=query.limit - len(matched_rows),
            )
            matched_rows.extend(chunk_results)

            if len(matched_rows) >= query.limit:
                break

        # Compute aggregations if requested
        aggregates = None
        if query.aggregations:
            aggregates = {}
            for agg in query.aggregations:
                col_vals = [r.get(agg.column) for r in matched_rows if r.get(agg.column) is not None]
                if agg.operation == AggregationOperation.COUNT:
                    aggregates[agg.output_alias] = len(col_vals)
                elif agg.operation == AggregationOperation.DISTINCT_COUNT:
                    aggregates[agg.output_alias] = len(set(col_vals))
                elif agg.operation == AggregationOperation.SUM:
                    aggregates[agg.output_alias] = sum(float(x) for x in col_vals if isinstance(x, (int, float)))
                elif agg.operation == AggregationOperation.AVG:
                    nums = [float(x) for x in col_vals if isinstance(x, (int, float))]
                    aggregates[agg.output_alias] = (sum(nums) / len(nums)) if nums else 0.0
                elif agg.operation == AggregationOperation.MIN:
                    aggregates[agg.output_alias] = min(col_vals) if col_vals else None
                elif agg.operation == AggregationOperation.MAX:
                    aggregates[agg.output_alias] = max(col_vals) if col_vals else None

        duration_ms = (time.perf_counter() - t0) * 1000

        return LakehouseQueryResult(
            table_name=query.table_name,
            execution_time_ms=round(duration_ms, 2),
            total_chunks_available=len(table_chunks),
            chunks_scanned=scanned_chunks,
            chunks_pruned=pruned_chunks,
            rows_scanned=rows_scanned,
            rows_returned=len(matched_rows),
            columns=projected_cols,
            rows=matched_rows,
            aggregate_results=aggregates,
        )

    def get_lakehouse_stats(self) -> Dict[str, Any]:
        """Aggregate lakehouse metrics."""
        total_rows = sum(t.total_rows for t in self._tables.values())
        total_chunks = sum(t.total_chunks for t in self._tables.values())
        uncompressed = sum(t.uncompressed_bytes for t in self._tables.values())
        compressed = sum(t.compressed_bytes for t in self._tables.values())
        avg_compression = round(uncompressed / compressed, 2) if compressed > 0 else 1.0

        return {
            "total_tables": len(self._tables),
            "total_rows": total_rows,
            "total_chunks": total_chunks,
            "uncompressed_bytes": uncompressed,
            "compressed_bytes": compressed,
            "overall_compression_ratio": avg_compression,
            "tables": [t.table_name for t in self._tables.values()],
        }
