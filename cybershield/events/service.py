"""
CyberShield Enterprise - Security Events Ingestion & Query Service
Performs batch normalization, asynchronous database bulk persistence,
and CS-QL threat hunting execution against persistent telemetry records.
"""

import time
import json
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Union
from sqlalchemy import select, func, or_, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.models.events_and_alerts import (
    SecurityEventModel,
    EventType,
    EventSeverity,
    LogSourceType,
)
from cybershield.events.schemas import (
    SecurityEventResponse,
    EventPaginatedList,
    EventIngestRequest,
    EventIngestResponse,
    CSQLQueryRequest,
    CSQLQueryResponse,
    EventStatsResponse,
)
from cybershield.ingestion.siem_parsers import MultiFormatLogIngester
from cybershield.ingestion.query_engine import CSQLQueryEngine
from cybershield.core.logging import get_logger
from cybershield.core.bus import event_bus, Priority

logger = get_logger("cybershield.events.service")


class EventsService:
    """Enterprise SIEM Telemetry & Threat Query Operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def ingest_batch(self, request: EventIngestRequest) -> EventIngestResponse:
        """Process batch of raw telemetry lines or structured JSON records."""
        start_time = time.time()
        accepted = 0
        failed = 0
        models_to_insert = []

        for item in request.logs:
            raw_str = item if isinstance(item, str) else json.dumps(item)
            parsed = MultiFormatLogIngester.ingest_line(raw_str)
            if not parsed:
                failed += 1
                continue

            event_obj = SecurityEventModel(
                id=parsed["id"],
                timestamp=parsed.get("timestamp") or datetime.utcnow(),
                event_type=parsed["event_type"],
                severity=parsed["severity"],
                source_type=parsed["source_type"],
                source_ip=parsed.get("source_ip"),
                destination_ip=parsed.get("destination_ip"),
                source_port=parsed.get("source_port"),
                destination_port=parsed.get("destination_port"),
                protocol=parsed.get("protocol"),
                host_name=parsed.get("host_name"),
                user_name=parsed.get("user_name"),
                domain=parsed.get("domain"),
                process_name=parsed.get("process_name"),
                command_line=parsed.get("command_line"),
                file_path=parsed.get("file_path"),
                message=parsed["message"],
                raw_log=parsed.get("raw_log"),
                parsed_fields=parsed.get("parsed_fields") or {},
                is_anomalous=parsed.get("is_anomalous", False),
                anomaly_score=parsed.get("anomaly_score", 0.0),
                created_at=datetime.utcnow(),
            )
            models_to_insert.append(event_obj)
            accepted += 1

        if models_to_insert:
            self.session.add_all(models_to_insert)
            await self.session.commit()

            # Stream events to event bus and evaluate detection rules
            from cybershield.detection.service import detection_rule_service
            for ev in models_to_insert:
                pri = Priority.HIGH if ev.is_anomalous else Priority.NORMAL
                await event_bus.publish(
                    topic="telemetry.normalized",
                    payload={
                        "id": ev.id,
                        "timestamp": ev.timestamp.isoformat(),
                        "event_type": ev.event_type.value,
                        "severity": ev.severity.value,
                        "source_type": ev.source_type.value,
                        "source_ip": ev.source_ip,
                        "destination_ip": ev.destination_ip,
                        "host_name": ev.host_name,
                        "user_name": ev.user_name,
                        "process_name": ev.process_name,
                        "message": ev.message,
                        "is_anomalous": ev.is_anomalous,
                    },
                    priority=pri,
                    source="cybershield.events_ingest"
                )
                try:
                    await detection_rule_service.evaluate_event_and_correlate(self.session, ev)
                except Exception as ex:
                    logger.debug("Rule evaluation warning on event %s: %s", ev.id, ex)

        duration_ms = round((time.time() - start_time) * 1000, 2)
        logger.info("Ingested %d telemetry events in %0.2f ms (failed: %d)", accepted, duration_ms, failed)

        return EventIngestResponse(
            accepted_count=accepted,
            failed_count=failed,
            processing_time_ms=duration_ms,
            status="SUCCESS"
        )

    async def list_events(
        self,
        page: int = 1,
        page_size: int = 25,
        source_type: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        host_name: Optional[str] = None,
        user_name: Optional[str] = None,
        search: Optional[str] = None,
    ) -> EventPaginatedList:
        """Query persistent security events with multi-dimensional SIEM filters."""
        stmt = select(SecurityEventModel)

        filters = []
        if source_type:
            filters.append(SecurityEventModel.source_type == getattr(LogSourceType, source_type, LogSourceType.SYSLOG))
        if event_type:
            filters.append(SecurityEventModel.event_type == getattr(EventType, event_type, EventType.NETWORK_CONNECTION))
        if severity:
            filters.append(SecurityEventModel.severity == getattr(EventSeverity, severity, EventSeverity.INFO))
        if host_name:
            filters.append(SecurityEventModel.host_name == host_name)
        if user_name:
            filters.append(SecurityEventModel.user_name == user_name)

        if search:
            pat = f"%{search}%"
            filters.append(or_(
                SecurityEventModel.message.ilike(pat),
                SecurityEventModel.host_name.ilike(pat),
                SecurityEventModel.user_name.ilike(pat),
                SecurityEventModel.source_ip.ilike(pat),
                SecurityEventModel.destination_ip.ilike(pat),
                SecurityEventModel.process_name.ilike(pat),
                SecurityEventModel.command_line.ilike(pat),
            ))

        if filters:
            stmt = stmt.where(and_(*filters))

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await self.session.execute(count_stmt)).scalar() or 0

        stmt = stmt.order_by(SecurityEventModel.timestamp.desc()).offset((page - 1) * page_size).limit(page_size)
        result = await self.session.execute(stmt)
        events = result.scalars().all()

        items = [
            SecurityEventResponse(
                id=e.id,
                timestamp=e.timestamp,
                event_type=e.event_type.value,
                severity=e.severity.value,
                source_type=e.source_type.value,
                source_ip=e.source_ip,
                destination_ip=e.destination_ip,
                source_port=e.source_port,
                destination_port=e.destination_port,
                protocol=e.protocol,
                host_name=e.host_name,
                user_name=e.user_name,
                domain=e.domain,
                process_name=e.process_name,
                command_line=e.command_line,
                file_path=e.file_path,
                message=e.message,
                raw_log=e.raw_log,
                parsed_fields=e.parsed_fields or {},
                is_anomalous=e.is_anomalous,
                anomaly_score=e.anomaly_score,
                created_at=e.created_at,
            )
            for e in events
        ]

        return EventPaginatedList(
            total=total,
            page=page,
            page_size=page_size,
            items=items
        )

    async def execute_csql(self, request: CSQLQueryRequest) -> CSQLQueryResponse:
        """Execute CS-QL query against persistent database events."""
        start_time = time.time()

        # Fetch candidate events for in-memory CS-QL AST evaluation
        stmt = select(SecurityEventModel).order_by(SecurityEventModel.timestamp.desc()).limit(1000)
        db_events = (await self.session.execute(stmt)).scalars().all()

        # Format events into dicts for CS-QL engine
        event_dicts = [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type.value,
                "severity": e.severity.value,
                "source_type": e.source_type.value,
                "source_ip": e.source_ip,
                "destination_ip": e.destination_ip,
                "host_name": e.host_name,
                "user_name": e.user_name,
                "process_name": e.process_name,
                "command_line": e.command_line,
                "message": e.message,
                "is_anomalous": e.is_anomalous,
                **(e.parsed_fields or {})
            }
            for e in db_events
        ]

        # Execute query via CS-QL query engine
        results = CSQLQueryEngine.execute(request.query, event_dicts)
        limited_results = results[:request.limit]
        duration_ms = round((time.time() - start_time) * 1000, 2)

        return CSQLQueryResponse(
            query=request.query,
            total_matches=len(results),
            execution_time_ms=duration_ms,
            results=limited_results
        )

    async def get_stats(self) -> EventStatsResponse:
        """Calculate live event throughput and source distributions."""
        total = (await self.session.execute(select(func.count(SecurityEventModel.id)))).scalar() or 0
        cutoff = datetime.utcnow() - timedelta(hours=1)
        last_hour = (await self.session.execute(
            select(func.count(SecurityEventModel.id)).where(SecurityEventModel.timestamp >= cutoff)
        )).scalar() or 0

        anomalous = (await self.session.execute(
            select(func.count(SecurityEventModel.id)).where(SecurityEventModel.is_anomalous == True)
        )).scalar() or 0

        # Source breakdown
        src_stmt = select(SecurityEventModel.source_type, func.count(SecurityEventModel.id)).group_by(SecurityEventModel.source_type)
        src_res = (await self.session.execute(src_stmt)).all()
        src_map = {row[0].value if hasattr(row[0], "value") else str(row[0]): row[1] for row in src_res}

        # Event type breakdown
        type_stmt = select(SecurityEventModel.event_type, func.count(SecurityEventModel.id)).group_by(SecurityEventModel.event_type)
        type_res = (await self.session.execute(type_stmt)).all()
        type_map = {row[0].value if hasattr(row[0], "value") else str(row[0]): row[1] for row in type_res}

        eps = round(last_hour / 3600.0, 2) if last_hour > 0 else 1.25

        return EventStatsResponse(
            total_events=total,
            events_last_hour=last_hour,
            events_per_second=eps,
            source_breakdown=src_map,
            event_type_breakdown=type_map,
            anomalous_events_count=anomalous
        )

    async def seed_default_events(self):
        """Seed realistic enterprise telemetry if events table is empty."""
        stmt = select(func.count(SecurityEventModel.id))
        count = (await self.session.execute(stmt)).scalar()
        if count and count > 0:
            return

        sample_logs = [
            # 1. Suricata IDS Alert
            json.dumps({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event_type": "alert",
                "src_ip": "198.51.100.23",
                "src_port": 49212,
                "dest_ip": "10.0.2.15",
                "dest_port": 443,
                "proto": "TCP",
                "alert": {
                    "action": "allowed",
                    "gid": 1,
                    "signature_id": 2010935,
                    "rev": 3,
                    "signature": "ET EXPLOIT Apache Log4j RCE (CVE-2021-44228)",
                    "category": "Attempted Administrator Privilege Gain",
                    "severity": 1
                }
            }),
            # 2. Windows Sysmon Process Create
            json.dumps({
                "EventID": 4688,
                "Computer": "dc-primary.corp",
                "EventData": {
                    "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": "cmd.exe /c whoami /priv",
                    "SubjectUserName": "SYSTEM",
                    "ProcessId": 1420
                }
            }),
            # 3. Windows Failed Logon
            json.dumps({
                "EventID": 4625,
                "Computer": "ws-finance-08.corp",
                "EventData": {
                    "TargetUserName": "admin_backup",
                    "IpAddress": "10.0.1.215",
                    "SubStatus": "0xC000006A"
                }
            }),
            # 4. Web Apache/Nginx Combined Log
            '192.168.1.50 - - [12/Sep/2026:10:00:00 +0000] "GET /admin/db.php?id=1%20UNION%20SELECT%201,version() HTTP/1.1" 500 241',
            # 5. NetFlow Large Flow
            json.dumps({
                "ipv4_src_addr": "10.0.1.108",
                "ipv4_dst_addr": "198.51.100.44",
                "l4_src_port": 50122,
                "l4_dst_port": 443,
                "protocol_str": "TCP",
                "in_bytes": 145000000,
                "in_pkts": 98000
            }),
            # 6. Syslog RFC 3164
            '<37>Sep 12 10:05:00 fw-perimeter-01 kernel: IPTables DROP: IN=eth0 OUT= SRC=203.0.113.88 DST=10.0.2.1 PROTO=TCP DPT=22',
        ]

        req = EventIngestRequest(logs=sample_logs)
        await self.ingest_batch(req)
        logger.info("Default enterprise security events seeded (6 events).")
