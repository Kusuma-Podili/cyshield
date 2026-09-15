"""NTFS Master File Table ($MFT) Record Parser & Timestomping Detector.

Dissects 1024-byte $MFT file records, parses $STANDARD_INFORMATION and $FILE_NAME attributes,
and detects anti-forensics timestomping (T1070.006) by comparing $SI vs $FN MACB timestamps.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from cybershield.dfir.schemas import (
    ArtifactType,
    ForensicFinding,
    FindingSeverity,
    TimelineEvent,
)
from cybershield.dfir.evtx_parser import filetime_to_datetime


class MFTParser:
    """Dissects NTFS $MFT records and detects timestomping anomalies."""

    @classmethod
    def parse_record(
        cls,
        raw_bytes: bytes,
        filename: str = "$MFT",
    ) -> Tuple[List[TimelineEvent], List[ForensicFinding]]:
        """Parse 1024-byte NTFS $MFT record or multi-record dump."""
        events: List[TimelineEvent] = []
        findings: List[ForensicFinding] = []

        offset = 0
        record_idx = 0

        while offset + 1024 <= len(raw_bytes):
            rec_bytes = raw_bytes[offset : offset + 1024]
            offset += 1024
            record_idx += 1

            if not rec_bytes.startswith(b"FILE"):
                continue

            first_attr_off = struct.unpack("<H", rec_bytes[20:22])[0]
            flags = struct.unpack("<H", rec_bytes[22:24])[0]
            is_directory = bool(flags & 0x02)

            # Traverse Attributes
            attr_off = first_attr_off
            si_timestamps: Dict[str, datetime] = {}
            fn_timestamps: Dict[str, datetime] = {}
            parsed_filename = f"Record_{record_idx}"

            while attr_off + 16 <= 1024:
                attr_type = struct.unpack("<I", rec_bytes[attr_off : attr_off + 4])[0]
                if attr_type == 0xFFFFFFFF or attr_type == 0:
                    break

                attr_len = struct.unpack("<I", rec_bytes[attr_off + 4 : attr_off + 8])[0]
                if attr_len == 0 or attr_off + attr_len > 1024:
                    break

                non_resident = rec_bytes[attr_off + 8]
                content_off = struct.unpack("<H", rec_bytes[attr_off + 20 : attr_off + 22])[0] if non_resident == 0 else 0

                # 0x10: $STANDARD_INFORMATION ($SI)
                if attr_type == 0x10 and non_resident == 0:
                    data_start = attr_off + content_off
                    if data_start + 32 <= 1024:
                        c_time = struct.unpack("<Q", rec_bytes[data_start : data_start + 8])[0]
                        m_time = struct.unpack("<Q", rec_bytes[data_start + 8 : data_start + 16])[0]
                        a_time = struct.unpack("<Q", rec_bytes[data_start + 16 : data_start + 24])[0]
                        si_timestamps["created"] = filetime_to_datetime(c_time)
                        si_timestamps["modified"] = filetime_to_datetime(m_time)
                        si_timestamps["accessed"] = filetime_to_datetime(a_time)

                # 0x30: $FILE_NAME ($FN)
                elif attr_type == 0x30 and non_resident == 0:
                    data_start = attr_off + content_off
                    if data_start + 66 <= 1024:
                        c_time = struct.unpack("<Q", rec_bytes[data_start + 8 : data_start + 16])[0]
                        m_time = struct.unpack("<Q", rec_bytes[data_start + 16 : data_start + 24])[0]
                        fn_timestamps["created"] = filetime_to_datetime(c_time)
                        fn_timestamps["modified"] = filetime_to_datetime(m_time)

                        name_len = rec_bytes[data_start + 64]
                        name_bytes = rec_bytes[data_start + 66 : data_start + 66 + (name_len * 2)]
                        try:
                            parsed_filename = name_bytes.decode("utf-16le", errors="ignore")
                        except Exception:
                            pass

                attr_off += attr_len

            # Check Timestomping Heuristics:
            # If $SI created timestamp is significantly older than $FN created timestamp
            is_timestomped = False
            if "created" in si_timestamps and "created" in fn_timestamps:
                si_c = si_timestamps["created"]
                fn_c = fn_timestamps["created"]
                # In normal NTFS, $FN creation time matches or precedes $SI creation time.
                # If $SI created is set into the past relative to $FN by more than 10 minutes:
                diff_seconds = (fn_c - si_c).total_seconds()
                if diff_seconds > 600:  # 10 minutes discrepancy
                    is_timestomped = True
                    findings.append(
                        ForensicFinding(
                            finding_id=f"DFIR-TIMESTOMP-{record_idx}",
                            severity=FindingSeverity.CRITICAL,
                            title=f"Anti-Forensics Timestomping Detected on '{parsed_filename}'",
                            description=(
                                f"Discrepancy detected between $STANDARD_INFORMATION ({si_c.isoformat()}) and "
                                f"$FILE_NAME ({fn_c.isoformat()}). File timestamps were retroactively altered by {round(diff_seconds / 60)} minutes."
                            ),
                            timestamp=fn_c,
                            artifact_source=ArtifactType.MFT,
                            mitre_technique="T1070.006",
                            iocs=[parsed_filename],
                            evidence_snippet={
                                "file_name": parsed_filename,
                                "si_created": si_c.isoformat(),
                                "fn_created": fn_c.isoformat(),
                                "record_index": record_idx,
                            },
                        )
                    )

            target_ts = si_timestamps.get("created", datetime.now(timezone.utc))
            events.append(
                TimelineEvent(
                    timestamp=target_ts,
                    event_type="MFT_FILE_CREATION",
                    source_artifact=ArtifactType.MFT,
                    entity_name=parsed_filename,
                    action="File Created on NTFS Volume" if not is_directory else "Directory Created",
                    details={
                        "record_index": record_idx,
                        "si_created": si_timestamps.get("created", target_ts).isoformat(),
                        "fn_created": fn_timestamps.get("created", target_ts).isoformat(),
                        "is_timestomped": is_timestomped,
                    },
                    is_suspicious=is_timestomped,
                    finding_id=f"DFIR-TIMESTOMP-{record_idx}" if is_timestomped else None,
                )
            )

        # Fallback if no full 1024-byte records were passed
        if not events and raw_bytes:
            events.append(
                TimelineEvent(
                    timestamp=datetime.now(timezone.utc),
                    event_type="MFT_SUMMARY",
                    source_artifact=ArtifactType.MFT,
                    entity_name=filename,
                    action="MFT Evidence Analyzed",
                    details={"size_bytes": len(raw_bytes)},
                    is_suspicious=False,
                )
            )

        return events, findings
