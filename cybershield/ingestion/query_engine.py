"""CyberShield Query Language (CS-QL) Lexer, Parser & Execution Engine.

Enables threat hunters to perform fast filter and aggregation operations
over millions of historical events without external database engines.
Supports field lookups, regex searches, boolean logic, and pipe aggregations.
"""

from __future__ import annotations

import re
import operator
import logging
from typing import List, Dict, Any, Optional, Callable, Tuple
from collections import Counter

from cybershield.core.models import NormalizedEvent, Alert
from cybershield.core.exceptions import QuerySyntaxError, QueryExecutionError

logger = logging.getLogger("cybershield.ingestion.csql")


class CSQLLexer:
    """Tokenizes a CS-QL query string into filter and pipeline components."""

    @classmethod
    def split_pipes(cls, query: str) -> Tuple[str, List[str]]:
        """Split a query into initial filter predicate and subsequent pipe stages."""
        parts = [p.strip() for p in query.split("|")]
        filter_expr = parts[0]
        pipeline_stages = parts[1:] if len(parts) > 1 else []
        return filter_expr, pipeline_stages


class CSQLEvaluator:
    """Evaluates predicate expressions against NormalizedEvent or Alert instances."""

    OP_MAP = {
        "==": operator.eq,
        "!=": operator.ne,
        ">": operator.gt,
        ">=": operator.ge,
        "<": operator.lt,
        "<=": operator.le,
        "contains": lambda a, b: str(b).lower() in str(a).lower(),
        "=~": lambda a, b: bool(re.search(str(b), str(a), re.IGNORECASE)),
        "startswith": lambda a, b: str(a).lower().startswith(str(b).lower()),
        "endswith": lambda a, b: str(a).lower().endswith(str(b).lower()),
    }

    @classmethod
    def extract_attr(cls, obj: Any, field_name: str) -> Any:
        """Fetch attribute or metadata field from event, alert, or dictionary."""
        if isinstance(obj, dict):
            return obj.get(field_name)
        if hasattr(obj, field_name):
            val = getattr(obj, field_name)
            if hasattr(val, "value"):  # Enum support
                return val.value
            return val
        if hasattr(obj, "metadata") and isinstance(obj.metadata, dict):
            return obj.metadata.get(field_name)
        return None

    @classmethod
    def evaluate_predicate(cls, obj: Any, predicate: str) -> bool:
        """Evaluate a single predicate string against an object."""
        pred = predicate.strip()
        if not pred or pred == "*":
            return True

        # Check for simple conjunctions: 'A and B'
        if " and " in pred.lower():
            sub_preds = re.split(r"\s+and\s+", pred, flags=re.IGNORECASE)
            return all(cls.evaluate_predicate(obj, p) for p in sub_preds)

        # Check for disjunctions: 'A or B'
        if " or " in pred.lower():
            sub_preds = re.split(r"\s+or\s+", pred, flags=re.IGNORECASE)
            return any(cls.evaluate_predicate(obj, p) for p in sub_preds)

        # Parse comparison: <field> <op> <value>
        # Match e.g. source_ip == "192.168.1.10" or process_name contains "powershell"
        match = re.match(
            r"^([a-zA-Z0-9_\.\-]+)\s*(==|!=|>=|<=|>|<|contains|=~|startswith|endswith)\s*(.+)$",
            pred
        )
        if not match:
            # Check free-text search across all attributes
            search_term = pred.strip("'\"").lower()
            raw_str = getattr(obj, "raw_payload", None) or getattr(obj, "description", None) or str(obj)
            return search_term in raw_str.lower()

        field_name, op_str, val_str = match.groups()
        op_str = op_str.strip()
        val_str = val_str.strip().strip("'\"")

        actual_val = cls.extract_attr(obj, field_name)
        if actual_val is None:
            return op_str == "!="

        # Type cast numerical comparisons if both are digits
        if str(actual_val).isdigit() and val_str.isdigit():
            actual_val = int(actual_val)
            val_str = int(val_str)
        else:
            actual_val = str(actual_val)
            val_str = str(val_str)

        cmp_func = cls.OP_MAP.get(op_str)
        if not cmp_func:
            return False

        try:
            return cmp_func(actual_val, val_str)
        except Exception:
            return False


class CSQLEngine:
    """Executes full CS-QL queries with aggregation and sorting."""

    @classmethod
    def execute(cls, query: str, items: List[Any]) -> List[Dict[str, Any]]:
        """Convenience query executor returning list of matching dictionaries."""
        res = cls.execute_events(items, query)
        return res.get("results", [])

    @classmethod
    def execute_events(cls, events: List[Any], query_string: str) -> Dict[str, Any]:
        """Execute CS-QL query across a list of NormalizedEvents or dictionaries."""
        filter_expr, pipeline = CSQLLexer.split_pipes(query_string)

        # 1. Filtering stage
        filtered = [evt for evt in events if CSQLEvaluator.evaluate_predicate(evt, filter_expr)]

        # 2. Pipeline processing (stats, sort, limit)
        aggregation_result: Optional[Dict[str, int]] = None
        limit_val: Optional[int] = None
        sort_field: Optional[str] = None
        sort_desc: bool = False

        for stage in pipeline:
            stage_clean = stage.strip()
            # Stats count by <field>
            if stage_clean.startswith("stats count by"):
                group_field = stage_clean.replace("stats count by", "").strip()
                counts: Counter = Counter()
                for e in filtered:
                    v = CSQLEvaluator.extract_attr(e, group_field) or "unknown"
                    counts[str(v)] += 1
                aggregation_result = dict(counts.most_common(50))

            # Sort by <field> [asc|desc]
            elif stage_clean.startswith("sort by"):
                parts = stage_clean.replace("sort by", "").strip().split()
                sort_field = parts[0]
                sort_desc = len(parts) > 1 and parts[1].lower() == "desc"

            # Limit <N>
            elif stage_clean.startswith("limit"):
                n_str = stage_clean.replace("limit", "").strip()
                if n_str.isdigit():
                    limit_val = int(n_str)

        # Apply sorting
        if sort_field:
            filtered.sort(
                key=lambda x: str(CSQLEvaluator.extract_attr(x, sort_field) or ""),
                reverse=sort_desc
            )

        # Apply limit
        total_matched = len(filtered)
        if limit_val is not None:
            filtered = filtered[:limit_val]

        return {
            "query": query_string,
            "total_matched": total_matched,
            "returned_count": len(filtered),
            "aggregation": aggregation_result,
            "results": [e.model_dump(mode="json") if hasattr(e, "model_dump") else e for e in filtered],
        }

    @classmethod
    def execute_alerts(cls, alerts: List[Alert], query_string: str) -> Dict[str, Any]:
        """Execute CS-QL query across a list of security Alerts."""
        filter_expr, pipeline = CSQLLexer.split_pipes(query_string)
        filtered = [alt for alt in alerts if CSQLEvaluator.evaluate_predicate(alt, filter_expr)]

        aggregation_result: Optional[Dict[str, int]] = None
        limit_val: Optional[int] = None

        for stage in pipeline:
            stage_clean = stage.strip()
            if stage_clean.startswith("stats count by"):
                group_field = stage_clean.replace("stats count by", "").strip()
                counts: Counter = Counter()
                for a in filtered:
                    v = CSQLEvaluator.extract_attr(a, group_field) or "unknown"
                    counts[str(v)] += 1
                aggregation_result = dict(counts.most_common(50))
            elif stage_clean.startswith("limit"):
                n_str = stage_clean.replace("limit", "").strip()
                if n_str.isdigit():
                    limit_val = int(n_str)

        total_matched = len(filtered)
        if limit_val is not None:
            filtered = filtered[:limit_val]

        return {
            "query": query_string,
            "total_matched": total_matched,
            "returned_count": len(filtered),
            "aggregation": aggregation_result,
            "results": [a.model_dump(mode="json") if hasattr(a, "model_dump") else a for a in filtered],
        }


# Alias for backwards and service compatibility
CSQLQueryEngine = CSQLEngine
