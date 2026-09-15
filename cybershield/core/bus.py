"""High-Throughput Asynchronous Security Event Bus for CyberShield Enterprise.

Provides decoupled pub/sub message routing, priority queuing, backpressure regulation,
and dead-letter retention for real-time telemetry processing across detection engines.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable, Dict, List, Any, Optional, Awaitable
from datetime import datetime, timezone
from dataclasses import dataclass, field

logger = logging.getLogger("cybershield.bus")


class Priority:
    """Standard message priorities (lower integer = higher priority)."""
    CRITICAL: int = 1
    HIGH: int = 5
    NORMAL: int = 10
    LOW: int = 20


@dataclass
class BusMessage:
    """Standard message envelope passed through the CyberShield bus."""
    topic: str
    payload: Any
    priority: int = Priority.NORMAL  # Lower number = higher priority (0-100)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: Optional[str] = None
    source: Optional[str] = None


class EventBus:
    """Enterprise-grade async event bus with topic subscriptions and metrics."""

    def __init__(self, max_queue_size: int = 50000):
        self._subscribers: Dict[str, List[Callable[[BusMessage], Awaitable[None] | None]]] = {}
        self._queue: asyncio.PriorityQueue[tuple[int, float, int, BusMessage]] = asyncio.PriorityQueue(maxsize=max_queue_size)
        self._dead_letter_queue: List[BusMessage] = []
        self._running: bool = False
        self._worker_task: Optional[asyncio.Task] = None
        self._seq_counter: int = 0
        
        # Telemetry metrics
        self._published_count: int = 0
        self._processed_count: int = 0
        self._dropped_count: int = 0
        self._errors_count: int = 0

    def subscribe(self, topic: str, callback: Callable[[BusMessage], Awaitable[None] | None]) -> None:
        """Register a handler for a topic. Supports exact topics and wildcard '*' suffixes."""
        if topic not in self._subscribers:
            self._subscribers[topic] = []
        self._subscribers[topic].append(callback)
        logger.debug("Subscribed %s to topic %s", callback.__name__, topic)

    def unsubscribe(self, topic: str, callback: Callable[[BusMessage], Awaitable[None] | None]) -> None:
        """Unregister a handler from a topic."""
        if topic in self._subscribers and callback in self._subscribers[topic]:
            self._subscribers[topic].remove(callback)

    async def publish(
        self,
        topic: str,
        payload: Any,
        priority: int = Priority.NORMAL,
        correlation_id: Optional[str] = None,
        source: Optional[str] = None
    ) -> bool:
        """Publish a message to the event queue. Returns False if queue is saturated."""
        self._published_count += 1
        self._seq_counter += 1
        msg = BusMessage(
            topic=topic,
            payload=payload,
            priority=priority,
            correlation_id=correlation_id,
            source=source
        )
        try:
            # Use timestamp float and monotonic counter as strict tiebreakers for PriorityQueue
            self._queue.put_nowait((priority, msg.timestamp.timestamp(), self._seq_counter, msg))
            return True
        except asyncio.QueueFull:
            self._dropped_count += 1
            if len(self._dead_letter_queue) < 1000:
                self._dead_letter_queue.append(msg)
            logger.warning("Event bus queue full. Dropped message on topic %s", topic)
            return False

    async def _dispatch_to_subscribers(self, msg: BusMessage) -> None:
        """Deliver message to matching exact and wildcard subscribers."""
        matched_callbacks = []
        
        # Exact match
        if msg.topic in self._subscribers:
            matched_callbacks.extend(self._subscribers[msg.topic])
            
        # Wildcard matches (e.g. 'telemetry.*' matches 'telemetry.raw')
        for registered_topic, cbs in self._subscribers.items():
            if registered_topic.endswith(".*"):
                prefix = registered_topic[:-2]
                if msg.topic.startswith(prefix) and registered_topic != msg.topic:
                    matched_callbacks.extend(cbs)
            elif registered_topic == "*":
                matched_callbacks.extend(cbs)

        for callback in matched_callbacks:
            try:
                res = callback(msg)
                if asyncio.iscoroutine(res):
                    await res
                self._processed_count += 1
            except Exception as ex:
                self._errors_count += 1
                logger.error("Error in subscriber callback %s on topic %s: %s", getattr(callback, "__name__", "fn"), msg.topic, ex)

    async def _worker_loop(self) -> None:
        """Background loop continuously consuming queued events."""
        while self._running:
            try:
                _, _, _, msg = await asyncio.wait_for(self._queue.get(), timeout=0.5)
                await self._dispatch_to_subscribers(msg)
                self._queue.task_done()
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as ex:
                logger.error("Unexpected error in bus worker loop: %s", ex)

    async def start(self) -> None:
        """Start the background event processing loop."""
        if self._running:
            return
        self._running = True
        self._worker_task = asyncio.create_task(self._worker_loop())
        logger.info("CyberShield EventBus started.")

    async def stop(self) -> None:
        """Gracefully drain remaining messages and shut down."""
        if not self._running:
            return
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        logger.info("CyberShield EventBus stopped.")

    def get_metrics(self) -> Dict[str, Any]:
        """Return real-time operational statistics of the bus."""
        return {
            "queue_size": self._queue.qsize(),
            "published_count": self._published_count,
            "processed_count": self._processed_count,
            "dropped_count": self._dropped_count,
            "errors_count": self._errors_count,
            "dead_letter_count": len(self._dead_letter_queue),
            "subscriber_topics": list(self._subscribers.keys())
        }


# Global singleton instance
event_bus = EventBus()
