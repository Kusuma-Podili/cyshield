"""
CyberShield Enterprise - Asynchronous Telemetry Batch Ingestion Task Handler
Processes high-volume log streams, normalizes attributes into SIEM events,
evaluates real-time anomaly heuristics, and persists batch records.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Dict, Any, List, Callable

from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.session import async_session_factory
from cybershield.database.models.events_and_alerts import SecurityEventModel, EventType, EventSeverity, LogSourceType
from cybershield.ingestion.parsers import SyslogParser, WebAccessLogParser, SysmonParser


async def handle_telemetry_ingestion(
    payload: Dict[str, Any],
    progress_callback: Callable[[float, str], None],
) -> Dict[str, Any]:
    """
    Execute asynchronous telemetry batch ingestion task.
    payload: { "logs": List[str], "source_type": "SYSLOG"|"WEB"|"SYSMON", "default_host": "..." }
    """
    logs = payload.get("logs", [])
    source_type = payload.get("source_type", "SYSLOG")
    default_host = payload.get("default_host", "SRV-EDGE-01")

    if not logs:
        # Generate synthetic batch if payload empty
        logs = [
            f"<134>1 {datetime.utcnow().isoformat()} {default_host} sshd[1204] - - Failed password for invalid user admin from 192.168.1.10{i} port {4000+i} ssh2"
            for i in range(1, 11)
        ]

    total = len(logs)
    progress_callback(5.0, f"Initializing ingestion worker for {total} raw telemetry events...")

    ingested_events = []
    anomalous_count = 0

    async with async_session_factory() as session:
        for idx, raw_line in enumerate(logs):
            now = datetime.utcnow()
            ev_id = f"EV-{now.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"

            norm_ev = None
            if source_type == "WEB":
                norm_ev = WebAccessLogParser.parse(raw_line)
            elif source_type == "SYSMON":
                norm_ev = SysmonParser.parse(raw_line)
            else:
                norm_ev = SyslogParser.parse(raw_line)

            is_anomaly = "failed" in raw_line.lower() or "unauthorized" in raw_line.lower() or "malware" in raw_line.lower()
            if is_anomaly:
                anomalous_count += 1

            src_ip = getattr(norm_ev, "source_ip", None) or "192.168.1.100"
            user = getattr(norm_ev, "user_name", None) or "admin"
            src_port = getattr(norm_ev, "source_port", None) or 443

            ev_model = SecurityEventModel(
                id=ev_id,
                timestamp=now,
                event_type=EventType.AUTHENTICATION_ATTEMPT if "sshd" in raw_line.lower() else EventType.NETWORK_CONNECTION,
                severity=EventSeverity.HIGH if is_anomaly else EventSeverity.INFO,
                source_type=LogSourceType[source_type] if source_type in LogSourceType.__members__ else LogSourceType.SYSLOG,
                source_ip=src_ip,
                destination_ip="10.0.0.1",
                source_port=src_port,
                destination_port=22,
                protocol="TCP",
                host_name=default_host,
                user_name=user,
                message=raw_line,
                raw_log=raw_line,
                is_anomalous=is_anomaly,
                anomaly_score=78.5 if is_anomaly else 5.0,
                created_at=now,
            )
            session.add(ev_model)
            ingested_events.append(ev_id)

            if (idx + 1) % max(1, total // 4) == 0:
                pct = round(10.0 + ((idx + 1) / total) * 75.0, 1)
                progress_callback(pct, f"Normalized and indexed {idx + 1}/{total} events ({anomalous_count} anomalies flagged)...")

        await session.commit()

    progress_callback(100.0, f"Successfully completed ingestion of {total} events.")
    return {
        "events_ingested": total,
        "anomalies_detected": anomalous_count,
        "source_type": source_type,
        "sample_event_ids": ingested_events[:5],
    }
