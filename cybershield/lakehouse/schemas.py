"""
Security Data Lakehouse Schemas and Models.
Defines columnar table catalog, partition schemas, vector query requests, and lakehouse telemetry.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ColumnDataType(str, Enum):
    STRING = "STRING"
    INTEGER = "INTEGER"
    FLOAT = "FLOAT"
    BOOLEAN = "BOOLEAN"
    TIMESTAMP = "TIMESTAMP"
    JSON = "JSON"


class ColumnSchema(BaseModel):
    name: str
    data_type: ColumnDataType
    nullable: bool = True
    is_partition_key: bool = False


class TablePartitionSpec(BaseModel):
    partition_columns: List[str] = Field(default_factory=lambda: ["year", "month", "day"])


class LakehouseTableMetadata(BaseModel):
    table_name: str
    description: str
    columns: List[ColumnSchema]
    partition_spec: TablePartitionSpec = Field(default_factory=TablePartitionSpec)
    total_rows: int = 0
    total_chunks: int = 0
    uncompressed_bytes: int = 0
    compressed_bytes: int = 0
    compression_ratio: float = 1.0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_ingested_at: Optional[datetime] = None


class PredicateOperator(str, Enum):
    EQUALS = "=="
    NOT_EQUALS = "!="
    GREATER_THAN = ">"
    GREATER_EQUAL = ">="
    LESS_THAN = "<"
    LESS_EQUAL = "<="
    IN = "IN"
    CONTAINS = "CONTAINS"


class LakehousePredicate(BaseModel):
    """Filter predicate pushed down into columnar chunks for partition pruning."""
    column: str
    operator: PredicateOperator
    value: Any


class AggregationOperation(str, Enum):
    COUNT = "COUNT"
    DISTINCT_COUNT = "DISTINCT_COUNT"
    SUM = "SUM"
    AVG = "AVG"
    MIN = "MIN"
    MAX = "MAX"


class QueryAggregation(BaseModel):
    column: str
    operation: AggregationOperation
    output_alias: str


class LakehouseQueryRequest(BaseModel):
    """Vectorized query against columnar lakehouse."""
    table_name: str
    columns: Optional[List[str]] = None  # None selects all columns (projection)
    predicates: List[LakehousePredicate] = Field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    group_by: Optional[List[str]] = None
    aggregations: Optional[List[QueryAggregation]] = None
    limit: int = 500


class LakehouseQueryResult(BaseModel):
    """Query result containing records, vector metrics, and partition pruning statistics."""
    table_name: str
    execution_time_ms: float
    total_chunks_available: int
    chunks_scanned: int
    chunks_pruned: int
    rows_scanned: int
    rows_returned: int
    columns: List[str]
    rows: List[Dict[str, Any]]
    aggregate_results: Optional[Dict[str, Any]] = None


class LakehouseIngestRequest(BaseModel):
    """Micro-batch ingestion payload."""
    table_name: str
    records: List[Dict[str, Any]]
