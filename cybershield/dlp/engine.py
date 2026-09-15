"""
Data Loss Prevention (DLP) Engine.
Coordinates real-time content inspection, redaction masking, policy enforcement, and incident metrics.
"""

import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from cybershield.dlp.rules import BUILTIN_DLP_RULES, DLPPatternMatcher
from cybershield.dlp.schemas import (
    DLPEnforcementAction,
    DLPInspectRequest,
    DLPInspectResult,
    DLPRule,
)


class DataLossPreventionEngine:
    """Enterprise Data Loss Prevention and Content Inspection Engine."""

    def __init__(self):
        self._rules: Dict[str, DLPRule] = {r.id: r for r in BUILTIN_DLP_RULES}
        self._inspection_history: List[DLPInspectResult] = []
        self._blocked_count = 0
        self._masked_count = 0
        self._total_scans = 0

    def list_rules(self) -> List[DLPRule]:
        return list(self._rules.values())

    def inspect_content(self, request: DLPInspectRequest) -> DLPInspectResult:
        """Scan content for confidential data and enforce DLP policy."""
        t0 = time.perf_counter()
        self._total_scans += 1

        matches = DLPPatternMatcher.scan_text(request.content)
        has_violations = len(matches) > 0
        action_taken = DLPEnforcementAction.ALLOW
        sanitized = None

        if has_violations:
            if request.action_if_matched == DLPEnforcementAction.BLOCK:
                action_taken = DLPEnforcementAction.BLOCK
                self._blocked_count += 1
            elif request.action_if_matched == DLPEnforcementAction.MASK:
                action_taken = DLPEnforcementAction.MASK
                sanitized = DLPPatternMatcher.mask_text(request.content)
                self._masked_count += 1
            else:
                action_taken = DLPEnforcementAction.ALERT_ONLY

        duration_ms = (time.perf_counter() - t0) * 1000

        result = DLPInspectResult(
            inspection_id=f"DLP-INSP-{uuid.uuid4().hex[:8].upper()}",
            timestamp=datetime.utcnow(),
            has_violations=has_violations,
            action_taken=action_taken,
            matches_count=len(matches),
            matches=matches,
            sanitized_content=sanitized,
            execution_time_ms=round(duration_ms, 2),
        )

        self._inspection_history.append(result)
        if len(self._inspection_history) > 1000:
            self._inspection_history = self._inspection_history[-1000:]

        return result

    def mask_content(self, text: str) -> str:
        """Redact sensitive patterns in text."""
        return DLPPatternMatcher.mask_text(text)

    def get_incidents(self, limit: int = 50) -> List[DLPInspectResult]:
        """Retrieve recent DLP violation inspections."""
        violations = [i for i in self._inspection_history if i.has_violations]
        return list(reversed(violations))[:limit]

    def get_stats(self) -> Dict[str, Any]:
        """Telemetry on DLP inspections and prevented data exfiltrations."""
        by_type: Dict[str, int] = {}
        for insp in self._inspection_history:
            for m in insp.matches:
                t = m.data_type.value
                by_type[t] = by_type.get(t, 0) + 1

        return {
            "total_inspections": self._total_scans,
            "total_violations_detected": sum(len(i.matches) for i in self._inspection_history),
            "blocked_transmissions": self._blocked_count,
            "masked_transmissions": self._masked_count,
            "violations_by_data_type": by_type,
            "active_rules_count": len(self._rules),
        }
