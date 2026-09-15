"""
Temporal Event Buffer for Complex Event Processing (CEP).
Provides time-indexed in-memory buffering, sliding/tumbling window slicing, and group-by indexing.
"""

from collections import defaultdict
from datetime import datetime, timedelta
import threading
from typing import Any, Dict, List, Optional, Tuple


class TemporalEventBuffer:
    """Thread-safe sliding window event buffer with temporal indexing."""

    def __init__(self, max_retention_seconds: int = 3600):
        self._max_retention_seconds = max_retention_seconds
        self._lock = threading.RLock()
        self._events: List[Dict[str, Any]] = []
        # Partition index: (partition_name, key_value) -> List[event_ref]
        self._partition_index: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)

    def add_event(self, event: Dict[str, Any]) -> None:
        """Add event to temporal buffer and index its group fields."""
        with self._lock:
            # Ensure timestamp
            if "timestamp" not in event or not isinstance(event["timestamp"], datetime):
                if isinstance(event.get("timestamp"), str):
                    try:
                        event["timestamp"] = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")).replace(tzinfo=None)
                    except Exception:
                        event["timestamp"] = datetime.utcnow()
                else:
                    event["timestamp"] = datetime.utcnow()

            self._events.append(event)

            # Index common fields for fast group-by retrieval
            for key in ["src_ip", "source_ip", "dest_ip", "destination_ip", "username", "user_name", "host_id", "hostname"]:
                val = event.get(key)
                if val:
                    self._partition_index[(key, str(val))].append(event)

            # Cleanup expired events periodically
            self._purge_expired(datetime.utcnow())

    def add_batch(self, events: List[Dict[str, Any]]) -> None:
        """Batch ingestion into buffer."""
        for evt in events:
            self.add_event(evt)

    def _purge_expired(self, current_time: datetime) -> None:
        """Evict events older than max retention."""
        cutoff = current_time - timedelta(seconds=self._max_retention_seconds)
        if not self._events:
            return

        # Simple linear prune
        valid_idx = 0
        for i, evt in enumerate(self._events):
            if evt["timestamp"] >= cutoff:
                valid_idx = i
                break
        else:
            # All events expired
            valid_idx = len(self._events)

        if valid_idx > 0:
            expired = self._events[:valid_idx]
            self._events = self._events[valid_idx:]

            # Remove from partition indexes
            expired_set = {id(e) for e in expired}
            for key in list(self._partition_index.keys()):
                self._partition_index[key] = [
                    e for e in self._partition_index[key] if id(e) not in expired_set
                ]
                if not self._partition_index[key]:
                    del self._partition_index[key]

    def get_window(
        self,
        window_seconds: int,
        group_by_field: Optional[str] = None,
        group_by_value: Optional[str] = None,
        as_of_time: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve events matching temporal window and optional grouping key."""
        with self._lock:
            candidate_events: List[Dict[str, Any]]
            if group_by_field and group_by_value:
                candidate_events = self._partition_index.get((group_by_field, str(group_by_value)), [])
            else:
                candidate_events = self._events

            if not candidate_events:
                return []

            if as_of_time:
                ref_time = as_of_time
            else:
                max_evt = max(e["timestamp"] for e in candidate_events)
                ref_time = max(datetime.utcnow(), max_evt)

            cutoff = ref_time - timedelta(seconds=window_seconds)
            return [e for e in candidate_events if cutoff <= e["timestamp"] <= (ref_time + timedelta(seconds=2))]

    def get_all_group_values(self, field: str) -> List[str]:
        """List distinct active values for a grouping field."""
        with self._lock:
            vals = set()
            for (f, v) in self._partition_index.keys():
                if f == field:
                    vals.add(v)
            return list(vals)

    def total_events(self) -> int:
        with self._lock:
            return len(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._partition_index.clear()
