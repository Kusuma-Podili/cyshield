"""
Columnar Storage and Partition Pruning for Security Data Lakehouse.
Provides chunk-level statistics, column-oriented vectors, and fast predicate pushdown skipping.
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from cybershield.lakehouse.schemas import (
    ColumnSchema,
    LakehousePredicate,
    PredicateOperator,
)


class ColumnStatistics:
    """Statistics per column in a chunk used for zone-map / min-max data skipping."""

    def __init__(self, column_name: str):
        self.column_name = column_name
        self.min_value: Any = None
        self.max_value: Any = None
        self.null_count: int = 0
        self.total_count: int = 0

    def update(self, value: Any) -> None:
        self.total_count += 1
        if value is None:
            self.null_count += 1
            return

        try:
            if self.min_value is None or value < self.min_value:
                self.min_value = value
            if self.max_value is None or value > self.max_value:
                self.max_value = value
        except Exception:
            # Fallback for unorderable types
            pass

    def can_skip_predicate(self, pred: LakehousePredicate) -> bool:
        """Evaluate whether entire chunk can be skipped using min-max statistics."""
        if self.total_count == 0:
            return True
        if self.min_value is None or self.max_value is None:
            return False

        op = pred.operator
        val = pred.value

        try:
            if op == PredicateOperator.EQUALS:
                return val < self.min_value or val > self.max_value
            elif op == PredicateOperator.GREATER_THAN:
                return self.max_value <= val
            elif op == PredicateOperator.GREATER_EQUAL:
                return self.max_value < val
            elif op == PredicateOperator.LESS_THAN:
                return self.min_value >= val
            elif op == PredicateOperator.LESS_EQUAL:
                return self.min_value > val
        except Exception:
            return False

        return False


class ColumnarChunk:
    """In-memory columnar chunk representing an immutable Parquet-style file."""

    def __init__(self, chunk_id: str, partition_key: str, schema: List[ColumnSchema]):
        self.chunk_id = chunk_id
        self.partition_key = partition_key
        self.schema = schema
        self.columns_data: Dict[str, List[Any]] = {col.name: [] for col in schema}
        self.stats: Dict[str, ColumnStatistics] = {col.name: ColumnStatistics(col.name) for col in schema}
        self.row_count: int = 0
        self.uncompressed_bytes: int = 0
        self.compressed_bytes: int = 0

    def append_row(self, row: Dict[str, Any]) -> None:
        """Append row into columnar arrays and update min-max stats."""
        raw_size = 0
        for col in self.schema:
            val = row.get(col.name)
            self.columns_data[col.name].append(val)
            self.stats[col.name].update(val)
            raw_size += len(str(val)) if val is not None else 1

        self.row_count += 1
        self.uncompressed_bytes += max(16, raw_size)
        # Simulate columnar dictionary compression (approx 65% space savings)
        self.compressed_bytes = max(1, int(self.uncompressed_bytes * 0.35))

    def evaluate_predicates_skip(self, predicates: List[LakehousePredicate]) -> bool:
        """Check if entire chunk can be pruned using column statistics."""
        for pred in predicates:
            stat = self.stats.get(pred.column)
            if stat and stat.can_skip_predicate(pred):
                return True  # Skip entire chunk!
        return False

    def scan_columns(
        self,
        projected_columns: List[str],
        predicates: List[LakehousePredicate],
        limit: int,
    ) -> List[Dict[str, Any]]:
        """Vectorized scan of chunk rows matching predicates."""
        matched_rows: List[Dict[str, Any]] = []

        for i in range(self.row_count):
            # Check row against predicates
            row_matches = True
            for pred in predicates:
                col_val = self.columns_data.get(pred.column, [None] * self.row_count)[i]
                if not self._eval_single_predicate(col_val, pred.operator, pred.value):
                    row_matches = False
                    break

            if row_matches:
                row_dict = {}
                for col in projected_columns:
                    col_arr = self.columns_data.get(col)
                    row_dict[col] = col_arr[i] if col_arr else None
                matched_rows.append(row_dict)
                if len(matched_rows) >= limit:
                    break

        return matched_rows

    @staticmethod
    def _eval_single_predicate(val: Any, op: PredicateOperator, target: Any) -> bool:
        if val is None:
            return False
        try:
            if op == PredicateOperator.EQUALS:
                return str(val).lower() == str(target).lower()
            elif op == PredicateOperator.NOT_EQUALS:
                return str(val).lower() != str(target).lower()
            elif op == PredicateOperator.GREATER_THAN:
                return float(val) > float(target)
            elif op == PredicateOperator.GREATER_EQUAL:
                return float(val) >= float(target)
            elif op == PredicateOperator.LESS_THAN:
                return float(val) < float(target)
            elif op == PredicateOperator.LESS_EQUAL:
                return float(val) <= float(target)
            elif op == PredicateOperator.CONTAINS:
                return str(target).lower() in str(val).lower()
            elif op == PredicateOperator.IN:
                if isinstance(target, list):
                    return val in target or str(val) in [str(x) for x in target]
                return str(val) in str(target)
        except Exception:
            return False
        return False
