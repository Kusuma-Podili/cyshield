"""Real-Time WebSocket Hub & Event Broadcaster for CyberShield Enterprise.

Maintains persistent duplex WebSocket connections to SOC analyst consoles.
Subscribes to the core event bus and broadcasts live alerts, telemetry events,
and SOAR execution updates instantly without polling.
"""

from __future__ import annotations

import json
import logging
import asyncio
from typing import List, Set, Any
from fastapi import WebSocket, WebSocketDisconnect

from cybershield.core.bus import event_bus, BusMessage

logger = logging.getLogger("cybershield.api.websocket")


class WebSocketHub:
    """Enterprise WebSocket connection manager and multiplexer."""

    def __init__(self):
        self._active_connections: Set[WebSocket] = set()
        self._is_subscribed: bool = False

    def setup_event_bus_listener(self) -> None:
        """Hook into the CyberShield EventBus to stream live events to WebSockets."""
        if self._is_subscribed:
            return

        async def _bus_broadcaster(msg: BusMessage) -> None:
            # Serialize payload cleanly
            payload_data = msg.payload
            if hasattr(payload_data, "model_dump"):
                payload_json = payload_data.model_dump(mode="json")
            elif hasattr(payload_data, "__dict__"):
                payload_json = getattr(payload_data, "__dict__", str(payload_data))
            else:
                payload_json = payload_data

            packet = {
                "type": msg.topic,
                "timestamp": msg.timestamp.isoformat(),
                "priority": msg.priority,
                "data": payload_json,
            }
            await self.broadcast(packet)

        event_bus.subscribe("alert.new", _bus_broadcaster)
        event_bus.subscribe("incident.updated", _bus_broadcaster)
        event_bus.subscribe("soar.started", _bus_broadcaster)
        event_bus.subscribe("soar.completed", _bus_broadcaster)
        event_bus.subscribe("telemetry.normalized", _bus_broadcaster)
        event_bus.subscribe("telemetry.flow", _bus_broadcaster)

        self._is_subscribed = True
        logger.info("WebSocketHub subscribed to live security event bus topics.")

    async def connect(self, websocket: WebSocket) -> None:
        """Register a new active WebSocket client."""
        await websocket.accept()
        self._active_connections.add(websocket)
        logger.info("New SOC analyst console connected via WebSocket. Active: %d", len(self._active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a disconnected WebSocket client."""
        self._active_connections.discard(websocket)
        logger.info("SOC analyst console disconnected. Active: %d", len(self._active_connections))

    async def broadcast(self, message: Any) -> None:
        """Send message payload to all active client connections."""
        if not self._active_connections:
            return

        text_data = json.dumps(message, default=str)
        dead_connections: List[WebSocket] = []

        for connection in list(self._active_connections):
            try:
                await connection.send_text(text_data)
            except Exception:
                dead_connections.append(connection)

        for dead in dead_connections:
            self._active_connections.discard(dead)

    @property
    def client_count(self) -> int:
        return len(self._active_connections)


# Global singleton WebSocket hub
ws_hub = WebSocketHub()
