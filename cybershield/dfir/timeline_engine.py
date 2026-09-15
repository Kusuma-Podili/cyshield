"""Unified Digital Forensics Super-Timeline Engine.

Aggregates parsed events across heterogeneous artifacts (EVTX, MFT, Prefetch, auditd),
maintains chronological ordering, and correlates multi-stage attacker actions across the kill-chain.
"""

from __future__ import annotations

import base64
import binascii
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cybershield.dfir.schemas import (
    ArtifactType,
    ForensicFinding,
    TimelineEvent,
    DFIRAnalysisResult,
    ArtifactAnalyzeRequest,
    SuperTimelineRequest,
    SuperTimelineResponse,
)
from cybershield.dfir.evtx_parser import EVTXParser
from cybershield.dfir.prefetch_parser import PrefetchParser
from cybershield.dfir.mft_parser import MFTParser
from cybershield.dfir.auditd_parser import AuditdParser


class TimelineEngine:
    """Master DFIR aggregator and super-timeline synthesizer."""

    _timeline_store: List[TimelineEvent] = []
    _findings_store: List[ForensicFinding] = []

    @classmethod
    def _extract_payload_bytes(cls, req: ArtifactAnalyzeRequest) -> bytes:
        """Convert input hex, base64, or text payload into binary bytes."""
        if req.payload_hex:
            clean = "".join(req.payload_hex.split())
            return binascii.unhexlify(clean)
        elif req.payload_base64:
            return base64.b64decode(req.payload_base64)
        elif req.payload_text:
            return req.payload_text.encode("utf-8")
        return b""

    @classmethod
    def analyze_artifact(cls, req: ArtifactAnalyzeRequest) -> DFIRAnalysisResult:
        """Analyze a host forensic artifact and merge findings into super-timeline."""
        t0 = time.perf_counter()

        try:
            raw_bytes = cls._extract_payload_bytes(req)
        except Exception as e:
            return DFIRAnalysisResult(
                success=False,
                artifact_type=req.artifact_type,
                filename=req.filename,
                error_message=f"Failed to decode artifact bytes: {str(e)}",
                execution_time_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            )

        events: List[TimelineEvent] = []
        findings: List[ForensicFinding] = []

        try:
            if req.artifact_type == ArtifactType.EVTX:
                events, findings = EVTXParser.parse_records(raw_bytes, req.filename)
            elif req.artifact_type == ArtifactType.PREFETCH:
                events, findings = PrefetchParser.parse_file(raw_bytes, req.filename)
            elif req.artifact_type == ArtifactType.MFT:
                events, findings = MFTParser.parse_record(raw_bytes, req.filename)
            elif req.artifact_type == ArtifactType.AUDITD:
                text_str = req.payload_text or raw_bytes.decode("utf-8", errors="replace")
                events, findings = AuditdParser.parse_log(text_str, req.filename)
            else:
                # Generic fallback
                events.append(
                    TimelineEvent(
                        timestamp=datetime.now(timezone.utc),
                        event_type=f"{req.artifact_type.value}_RECORD",
                        source_artifact=req.artifact_type,
                        entity_name=req.filename,
                        action="Artifact Imported",
                        details={"length": len(raw_bytes)},
                        is_suspicious=False,
                    )
                )
        except Exception as ex:
            return DFIRAnalysisResult(
                success=False,
                artifact_type=req.artifact_type,
                filename=req.filename,
                error_message=f"Forensic parsing error: {str(ex)}",
                execution_time_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            )

        # Merge into global timeline store
        cls._timeline_store.extend(events)
        cls._findings_store.extend(findings)

        # Sort timeline chronologically
        cls._timeline_store.sort(key=lambda ev: ev.timestamp)

        duration_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        # Summary Metrics
        gathered_iocs = set()
        for f in findings:
            gathered_iocs.update(f.iocs)

        summary = {
            "parsed_records": len(events),
            "threat_findings": len(findings),
            "unique_iocs": list(gathered_iocs),
            "suspicious_events": sum(1 for e in events if e.is_suspicious),
        }

        return DFIRAnalysisResult(
            success=True,
            artifact_type=req.artifact_type,
            filename=req.filename,
            parsed_records_count=len(events),
            findings_count=len(findings),
            timeline_events_count=len(events),
            execution_time_ms=duration_ms,
            findings=findings,
            timeline=events,
            summary=summary,
        )

    @classmethod
    def get_super_timeline(cls, req: SuperTimelineRequest) -> SuperTimelineResponse:
        """Query synthesized super-timeline with filtering."""
        filtered = list(cls._timeline_store)

        if req.start_time:
            filtered = [e for e in filtered if e.timestamp >= req.start_time]
        if req.end_time:
            filtered = [e for e in filtered if e.timestamp <= req.end_time]
        if req.artifact_types:
            filtered = [e for e in filtered if e.source_artifact in req.artifact_types]
        if req.only_suspicious:
            filtered = [e for e in filtered if e.is_suspicious]

        suspicious_count = sum(1 for e in filtered if e.is_suspicious)

        return SuperTimelineResponse(
            total_events=len(filtered),
            suspicious_events=suspicious_count,
            timeline=filtered,
        )

    @classmethod
    def get_all_findings(cls) -> List[ForensicFinding]:
        """Return all historical forensic findings across analyzed artifacts."""
        return list(cls._findings_store)
