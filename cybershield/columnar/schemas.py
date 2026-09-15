"""
CyberShield Enterprise - Columnar Storage & Fast Security Data Lake Schemas
Provides data models for pure-Python zero-dependency columnar storage,
dictionary encoding, bloom filter chunk indexing, and vectorized aggregations.
"""

from typing import List, Dict, Optional, Any, Union
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class ColumnDataType(str, Enum):
    INT64 = "int64"
    FLOAT64 = "float64"
    STRING = "string"
    TIMESTAMP = "timestamp"
    BOOLEAN = "boolean"
    JSON = "json"


class CompressionType(str, Enum):
    NONE = "none"
    ZLIB = "zlib"
    RLE = "rle"
    DICTIONARY = "dictionary"


class ColumnMetadata(BaseModel):
    name: str = Field(..., description="Column header name")
    data_type: ColumnDataType = Field(..., description="Primitive data type")
    compression: CompressionType = Field(CompressionType.NONE, description="Compression applied")
    min_value: Optional[Any] = Field(None, description="Minimum value in chunk")
    max_value: Optional[Any] = Field(None, description="Maximum value in chunk")
    null_count: int = Field(0, description="Number of nulls in chunk")
    distinct_count: int = Field(0, description="Distinct value cardinality")


class ChunkIndex(BaseModel):
    chunk_id: str = Field(..., description="Unique chunk segment identifier")
    row_count: int = Field(..., description="Number of rows in chunk")
    compressed_bytes: int = Field(..., description="Total byte size on disk")
    uncompressed_bytes: int = Field(..., description="Total in-memory byte size")
    bloom_filter_bits: Optional[str] = Field(None, description="Hex string of bit array for member lookup")
    columns: Dict[str, ColumnMetadata] = Field(default_factory=dict, description="Column statistics")


class QueryFilterPredicate(BaseModel):
    column: str = Field(..., description="Target column name")
    operator: str = Field("equals", description="'equals', 'contains', 'greater_than', 'less_than', 'in'")
    value: Any = Field(..., description="Filter target value")


class ColumnarQueryRequest(BaseModel):
    table_name: str = Field("security_events", description="Target lakehouse table")
    select_columns: List[str] = Field(default_factory=list, description="Columns to project, empty for all")
    filters: List[QueryFilterPredicate] = Field(default_factory=list, description="Filter conditions")
    group_by: Optional[str] = Field(None, description="Optional column to group by")
    aggregate_function: Optional[str] = Field(None, description="'count', 'sum', 'avg', 'min', 'max'")
    aggregate_column: Optional[str] = Field(None, description="Target column for aggregate calculation")
    limit: int = Field(100, description="Maximum rows to return")


class ColumnarQueryResult(BaseModel):
    execution_time_ms: float = Field(..., description="Query latency in milliseconds")
    total_chunks_scanned: int = Field(..., description="Chunks inspected")
    chunks_skipped_by_index: int = Field(..., description="Chunks skipped via bloom filter/min-max")
    matched_rows_count: int = Field(..., description="Total matching rows")
    columns: List[str] = Field(..., description="Output column headers")
    rows: List[Dict[str, Any]] = Field(default_factory=list, description="Query results")
    aggregations: Optional[Dict[str, Any]] = Field(None, description="Grouped aggregation results")


class StorageCompactionReport(BaseModel):
    table_name: str = Field(..., description="Table compacted")
    segments_before: int = Field(..., description="Small files before compaction")
    segments_after: int = Field(..., description="Consolidated segments after")
    space_saved_bytes: int = Field(..., description="Disk space reclaimed")
    compression_ratio: float = Field(..., description="Raw bytes / compressed bytes ratio")
