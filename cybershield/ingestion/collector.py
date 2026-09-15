"""Telemetry Ingestion Pipeline & Event Normalization Collector.

Buffers streaming logs, coordinates multi-engine detection dispatch (Sigma, UEBA,
Payload, Anomaly), feeds alerts into the correlation engine, and retains event history
for fast CS-QL query retrieval.
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from cybershield.core.models import (
    NormalizedEvent,
    Alert,
    Incident,
    NetworkFlow,
    LogSourceType,
    generate_id,
    now_utc,
)
from cybershield.core.bus import event_bus
from cybershield.ingestion.parsers import UniversalTelemetryDispatcher
from cybershield.engines.sigma_engine import sigma_engine
from cybershield.engines.payload import payload_engine
from cybershield.engines.anomaly import anomaly_engine
from cybershield.engines.correlation import correlation_engine
from cybershield.engines.ueba import ueba_engine

logger = logging.getLogger("cybershield.ingestion.collector")


class TelemetryCollector:
    """Central ingest collector orchestrating parsing, AI inference, and bus routing."""

    def __init__(self, in_memory_event_capacity: int = 100000, in_memory_alert_capacity: int = 10000):
        self._event_buffer: deque[NormalizedEvent] = deque(maxlen=in_memory_event_capacity)
        self._alert_buffer: deque[Alert] = deque(maxlen=in_memory_alert_capacity)
        self._flow_buffer: deque[NetworkFlow] = deque(maxlen=in_memory_event_capacity)
        
        # Performance metrics
        self._total_ingested_events: int = 0
        self._total_generated_alerts: int = 0
        self._total_escalated_incidents: int = 0

    async def ingest_raw(self, raw_data: str | Dict[str, Any]) -> NormalizedEvent:
        """Parse raw log entry, pass to detection engines, and store."""
        event = UniversalTelemetryDispatcher.parse_auto(raw_data)
        return await self.ingest_event(event)

    async def ingest_event(self, event: NormalizedEvent) -> NormalizedEvent:
        """Process a pre-constructed NormalizedEvent through detection engines."""
        self._total_ingested_events += 1
        self._event_buffer.append(event)

        # 1. Evaluate Sigma detection rules
        sigma_alerts = sigma_engine.evaluate_event(event)
        for alert in sigma_alerts:
            await self._handle_alert(alert)

        # 2. Evaluate Payload / Injection Classifier
        payload_alert = payload_engine.process_and_alert(event)
        if payload_alert:
            await self._handle_alert(payload_alert)

        # 3. Evaluate User & Entity Behavior Analytics
        ueba_alert = ueba_engine.process_and_alert(event)
        if ueba_alert:
            await self._handle_alert(ueba_alert)

        # Publish normalized event to bus
        await event_bus.publish("telemetry.normalized", event, priority=20)
        return event

    async def ingest_network_flow(self, flow: NetworkFlow) -> Tuple[NetworkFlow, Optional[Alert]]:
        """Process network flow through the Isolation Forest anomaly detector."""
        self._flow_buffer.append(flow)
        alert = anomaly_engine.process_and_alert(flow)
        if alert:
            await self._handle_alert(alert)
        await event_bus.publish("telemetry.flow", flow, priority=15)
        return flow, alert

    async def _handle_alert(self, alert: Alert) -> None:
        """Route generated alert through correlation, incident builder, and event bus."""
        self._total_generated_alerts += 1
        self._alert_buffer.append(alert)

        # Correlate alert across time and MITRE attack graph
        cluster, incident = correlation_engine.correlate_alert(alert)
        if incident:
            alert.associated_incident_id = incident.incident_id
            self._total_escalated_incidents += 1
            await event_bus.publish("incident.updated", incident, priority=1)

        # Broadcast alert to SOC bus
        priority_val = 2 if alert.severity.value == "CRITICAL" else 5
        await event_bus.publish("alert.new", alert, priority=priority_val)

    def get_recent_events(self, limit: int = 100) -> List[NormalizedEvent]:
        """Fetch the most recent normalized events."""
        limit = min(limit, len(self._event_buffer))
        return list(self._event_buffer)[-limit:]

    def get_recent_alerts(self, limit: int = 100) -> List[Alert]:
        """Fetch the most recent security alerts."""
        limit = min(limit, len(self._alert_buffer))
        return list(self._alert_buffer)[-limit:]

    def get_metrics(self) -> Dict[str, Any]:
        """Telemetry ingestion rates and counts."""
        return {
            "total_ingested_events": self._total_ingested_events,
            "total_generated_alerts": self._total_generated_alerts,
            "total_escalated_incidents": self._total_escalated_incidents,
            "events_in_memory": len(self._event_buffer),
            "alerts_in_memory": len(self._alert_buffer),
            "flows_in_memory": len(self._flow_buffer),
        }


# Global singleton collector
collector = TelemetryCollector()
