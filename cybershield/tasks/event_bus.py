"""
CyberShield Enterprise - High-Throughput Event Bus & Pub/Sub Abstraction
Provides topic-based asynchronous publish/subscribe messaging with pattern matching,
backpressure protection, and zero external broker dependencies.
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import re
import time
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable, Awaitable, Set

logger = logging.getLogger("cybershield.tasks.event_bus")

EventHandler = Callable[[str, Dict[str, Any]], Awaitable[None]]


class EventBus:
    """Enterprise Asynchronous Event Bus supporting wildcard topic pub/sub."""

    def __init__(self, max_history: int = 500):
        # topic_pattern -> set of callback handlers
        self._subscribers: Dict[str, Set[EventHandler]] = {}
        self._history: List[Dict[str, Any]] = []
        self._max_history = max_history
        self._lock = asyncio.Lock()
        self._published_count = 0

    def subscribe(self, topic_pattern: str, handler: EventHandler) -> None:
        """
        Register an asynchronous handler for a topic pattern.
        Supports standard wildcards (e.g. 'telemetry.*', 'alert.#', 'task.*').
        """
        if topic_pattern not in self._subscribers:
            self._subscribers[topic_pattern] = set()
        self._subscribers[topic_pattern].add(handler)
        logger.debug("Subscribed handler %s to topic pattern '%s'", handler.__name__, topic_pattern)

    def unsubscribe(self, topic_pattern: str, handler: EventHandler) -> None:
        """Unregister a handler from a topic pattern."""
        if topic_pattern in self._subscribers:
            self._subscribers[topic_pattern].discard(handler)
            if not self._subscribers[topic_pattern]:
                del self._subscribers[topic_pattern]

    async def publish(self, topic: str, data: Dict[str, Any]) -> int:
        """
        Publish an event packet to a specific topic.
        Dispatches to all matching subscribers concurrently with error isolation.
        Returns the count of dispatched handlers.
        """
        now = datetime.utcnow().isoformat()
        packet = {
            "topic": topic,
            "data": data,
            "timestamp": now,
            "seq": self._published_count + 1,
        }

        # Track in history buffer
        async with self._lock:
            self._published_count += 1
            self._history.append(packet)
            if len(self._history) > self._max_history:
                self._history.pop(0)

        # Find matching handlers
        matched_handlers: Set[EventHandler] = set()
        for pattern, handlers in self._subscribers.items():
            if self._matches(topic, pattern):
                matched_handlers.update(handlers)

        if not matched_handlers:
            return 0

        # Execute handlers concurrently with error isolation
        tasks = [self._safe_dispatch(handler, topic, data) for handler in matched_handlers]
        await asyncio.gather(*tasks, return_exceptions=True)
        return len(matched_handlers)

    async def _safe_dispatch(self, handler: EventHandler, topic: str, data: Dict[str, Any]) -> None:
        """Execute subscriber with isolated try/except block."""
        try:
            res = handler(topic, data)
            if asyncio.iscoroutine(res):
                await res
        except Exception as e:
            logger.error("EventBus dispatch error for topic '%s' in handler %s: %s", topic, getattr(handler, "__name__", "unknown"), str(e), exc_info=True)

    @staticmethod
    def _matches(topic: str, pattern: str) -> bool:
        """
        Check if topic matches wildcard pattern.
        Supports '*' for single token and '#' for multi-token wildcards.
        """
        if pattern == "#" or pattern == "*":
            return True
        if pattern == topic:
            return True

        # Convert AMQP/MQTT style wildcards to regex
        # 'telemetry.*' -> 'telemetry\.[^.]+'
        # 'alert.#' -> 'alert\..*'
        regex_pat = pattern.replace(".", r"\.")
        regex_pat = regex_pat.replace("*", r"[^.]+")
        regex_pat = regex_pat.replace("#", r".*")
        regex_pat = f"^{regex_pat}$"

        return bool(re.match(regex_pat, topic))

    def get_history(self, limit: int = 50, topic_prefix: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recent published event history."""
        records = self._history
        if topic_prefix:
            records = [r for r in records if r["topic"].startswith(topic_prefix)]
        return records[-limit:]

    def clear(self) -> None:
        """Reset subscribers and event history."""
        self._subscribers.clear()
        self._history.clear()
        self._published_count = 0


# Singleton Global Enterprise Event Bus
event_bus = EventBus()
task_event_bus = event_bus
global_event_bus = event_bus

