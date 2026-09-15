"""
Temporal Correlation Engine (CEP).
Evaluates complex multi-event attack patterns, sliding window aggregates, and sequence chains.
"""

import re
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from cybershield.correlation.rules_catalog import DEFAULT_CORRELATION_RULES
from cybershield.correlation.schemas import (
    AggregationFunction,
    ConditionOperator,
    CorrelatedIncidentAlert,
    CorrelationRule,
    EventFilter,
    SequenceStep,
)
from cybershield.correlation.window_buffer import TemporalEventBuffer


class TemporalCorrelationEngine:
    """Complex Event Processing Engine for Real-Time Threat Correlation."""

    def __init__(self, buffer_retention_seconds: int = 3600):
        self._buffer = TemporalEventBuffer(max_retention_seconds=buffer_retention_seconds)
        self._rules: Dict[str, CorrelationRule] = {r.id: r for r in DEFAULT_CORRELATION_RULES}
        self._emitted_alerts: List[CorrelatedIncidentAlert] = []
        # Cooldown tracker: (rule_id, group_key) -> last_alert_time
        self._cooldown_tracker: Dict[tuple, datetime] = {}
        self._cooldown_seconds = 120

    def get_buffer(self) -> TemporalEventBuffer:
        return self._buffer

    def register_rule(self, rule: CorrelationRule) -> CorrelationRule:
        self._rules[rule.id] = rule
        return rule

    def get_rule(self, rule_id: str) -> Optional[CorrelationRule]:
        return self._rules.get(rule_id)

    def list_rules(self) -> List[CorrelationRule]:
        return list(self._rules.values())

    def delete_rule(self, rule_id: str) -> bool:
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False

    @staticmethod
    def _matches_filter(event: Dict[str, Any], flt: EventFilter) -> bool:
        """Evaluate a single field filter against an event dictionary."""
        val = event.get(flt.field)
        if val is None:
            return False

        op = flt.operator
        target = flt.value

        if op == ConditionOperator.EQUALS:
            return str(val).lower() == str(target).lower()
        elif op == ConditionOperator.NOT_EQUALS:
            return str(val).lower() != str(target).lower()
        elif op == ConditionOperator.CONTAINS:
            return str(target).lower() in str(val).lower()
        elif op == ConditionOperator.REGEX:
            try:
                return bool(re.search(str(target), str(val), re.IGNORECASE))
            except Exception:
                return False
        elif op == ConditionOperator.GREATER_THAN:
            try:
                return float(val) > float(target)
            except Exception:
                return False
        elif op == ConditionOperator.LESS_THAN:
            try:
                return float(val) < float(target)
            except Exception:
                return False
        elif op == ConditionOperator.IN:
            if isinstance(target, list):
                return val in target or str(val) in [str(x) for x in target]
            return str(val) in str(target)
        return False

    def _matches_step(self, event: Dict[str, Any], step: SequenceStep) -> bool:
        """Check if an event matches all filters for a step."""
        return all(self._matches_filter(event, flt) for flt in step.filters)

    def _evaluate_rule_for_group(
        self, rule: CorrelationRule, group_key: str, events: List[Dict[str, Any]], current_time: datetime
    ) -> Optional[CorrelatedIncidentAlert]:
        """Evaluate a correlation rule over a window of events for a single partition group."""
        if not events:
            return None

        # Check cooldown
        cooldown_key = (rule.id, group_key)
        last_alert = self._cooldown_tracker.get(cooldown_key)
        if last_alert and (current_time - last_alert).total_seconds() < self._cooldown_seconds:
            return None

        # Case 1: Sequence matching (e.g. Step 1 followed by Step 2)
        if len(rule.sequence_steps) > 1:
            matched_events = []
            events_sorted = sorted(events, key=lambda x: x.get("timestamp", datetime.min))

            # Validate each sequence step chronologically
            step_idx = 0
            curr_step = rule.sequence_steps[0]
            step_matched_count = 0
            step_events: List[Dict[str, Any]] = []

            for evt in events_sorted:
                if self._matches_step(evt, curr_step):
                    step_matched_count += 1
                    step_events.append(evt)
                    if step_matched_count >= curr_step.min_count:
                        # Advance to next step
                        matched_events.extend(step_events)
                        step_idx += 1
                        if step_idx >= len(rule.sequence_steps):
                            # Entire sequence fulfilled!
                            break
                        curr_step = rule.sequence_steps[step_idx]
                        step_matched_count = 0
                        step_events = []

            if step_idx >= len(rule.sequence_steps):
                alert = CorrelatedIncidentAlert(
                    id=f"CALERT-{uuid.uuid4().hex[:8].upper()}",
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    triggered_at=current_time,
                    group_key=group_key,
                    matched_events_count=len(matched_events),
                    matched_event_ids=[str(e.get("id", i)) for i, e in enumerate(matched_events)],
                    sample_events=matched_events[:5],
                    risk_score=90.0 if rule.severity == "CRITICAL" else 75.0,
                    mitre_technique_id=rule.mitre_technique_id,
                    summary=f"Sequence rule '{rule.name}' triggered for {group_key} across {len(matched_events)} correlated events.",
                )
                self._cooldown_tracker[cooldown_key] = current_time
                return alert

        # Case 2: Aggregation matching (e.g. COUNT or DISTINCT_COUNT of target field)
        else:
            step = rule.sequence_steps[0] if rule.sequence_steps else None
            matching_events = [e for e in events if step is None or self._matches_step(e, step)]

            if not matching_events:
                return None

            agg_value = 0.0
            if rule.aggregation == AggregationFunction.COUNT:
                agg_value = float(len(matching_events))
            elif rule.aggregation == AggregationFunction.DISTINCT_COUNT and rule.aggregation_target_field:
                distinct_vals = {
                    e.get(rule.aggregation_target_field)
                    for e in matching_events
                    if e.get(rule.aggregation_target_field) is not None
                }
                agg_value = float(len(distinct_vals))

            if agg_value >= rule.threshold:
                alert = CorrelatedIncidentAlert(
                    id=f"CALERT-{uuid.uuid4().hex[:8].upper()}",
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    triggered_at=current_time,
                    group_key=group_key,
                    matched_events_count=len(matching_events),
                    matched_event_ids=[str(e.get("id", i)) for i, e in enumerate(matching_events)],
                    sample_events=matching_events[:5],
                    risk_score=95.0 if rule.severity == "CRITICAL" else 70.0,
                    mitre_technique_id=rule.mitre_technique_id,
                    summary=f"Threshold exceeded for '{rule.name}': {agg_value} >= {rule.threshold} on {group_key}.",
                )
                self._cooldown_tracker[cooldown_key] = current_time
                return alert

        return None

    def process_event(self, event: Dict[str, Any]) -> List[CorrelatedIncidentAlert]:
        """Ingest event into buffer and evaluate all active rules."""
        self._buffer.add_event(event)
        evt_time = event.get("timestamp")
        if isinstance(evt_time, str):
            try:
                evt_time = datetime.fromisoformat(evt_time.replace("Z", "+00:00")).replace(tzinfo=None)
            except Exception:
                evt_time = datetime.utcnow()
        elif not isinstance(evt_time, datetime):
            evt_time = datetime.utcnow()

        now = evt_time
        new_alerts = []

        for rule in self._rules.values():
            if not rule.enabled:
                continue

            # Identify grouping keys
            if rule.group_by_fields:
                for grp_field in rule.group_by_fields:
                    val = event.get(grp_field)
                    if val is not None:
                        window_events = self._buffer.get_window(
                            window_seconds=rule.window_seconds,
                            group_by_field=grp_field,
                            group_by_value=str(val),
                            as_of_time=now,
                        )
                        alert = self._evaluate_rule_for_group(rule, f"{grp_field}:{val}", window_events, now)
                        if alert:
                            new_alerts.append(alert)
                            self._emitted_alerts.append(alert)
            else:
                # Global window without partition
                window_events = self._buffer.get_window(window_seconds=rule.window_seconds, as_of_time=now)
                alert = self._evaluate_rule_for_group(rule, "GLOBAL", window_events, now)
                if alert:
                    new_alerts.append(alert)
                    self._emitted_alerts.append(alert)

        return new_alerts

    def process_batch(self, events: List[Dict[str, Any]]) -> List[CorrelatedIncidentAlert]:
        """Ingest batch and evaluate."""
        alerts = []
        for evt in events:
            alerts.extend(self.process_event(evt))
        return alerts

    def get_emitted_alerts(self, limit: int = 100) -> List[CorrelatedIncidentAlert]:
        return list(reversed(self._emitted_alerts))[:limit]

    def get_stats(self) -> Dict[str, Any]:
        """CEP runtime statistics."""
        return {
            "total_rules": len(self._rules),
            "enabled_rules": sum(1 for r in self._rules.values() if r.enabled),
            "buffer_total_events": self._buffer.total_events(),
            "total_correlated_alerts": len(self._emitted_alerts),
            "critical_alerts": sum(1 for a in self._emitted_alerts if a.severity == "CRITICAL"),
        }
