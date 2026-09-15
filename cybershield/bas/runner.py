"""
Breach and Attack Simulation (BAS) Execution Runner.
Executes atomic tests in sandbox synthetic mode, cross-checks detection engines,
and produces comprehensive coverage reports.
"""

import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from cybershield.bas.atomic_tests import ATOMIC_TEST_CATALOG, get_atomic_test
from cybershield.bas.schemas import (
    AtomicTest,
    AtomicTestResult,
    SimulationExecutionMode,
    SimulationReport,
    SimulationRunRequest,
)
from cybershield.correlation.engine import TemporalCorrelationEngine
from cybershield.edr.behavior_engine import EDRBehaviorEngine
from cybershield.edr.schemas import ProcessTelemetryEvent
from cybershield.hunting.engine import ThreatHuntingEngine
from cybershield.hunting.schemas import HuntExecutionRequest


class AttackSimulationRunner:
    """Orchestrates breach and attack simulation runs and detection validation."""

    def __init__(self):
        self._edr_engine = EDRBehaviorEngine()
        self._cep_engine = TemporalCorrelationEngine(buffer_retention_seconds=600)
        self._hunting_engine = ThreatHuntingEngine()
        self._reports_history: Dict[str, SimulationReport] = {}

    def list_available_tests(self) -> List[AtomicTest]:
        return ATOMIC_TEST_CATALOG

    def _evaluate_with_edr(self, events: List[Dict[str, Any]]) -> List[str]:
        """Test process events against EDR behavior rules."""
        matched_rules = []
        proc_events: List[ProcessTelemetryEvent] = []
        for evt in events:
            if evt.get("event_type") == "PROCESS_CREATE":
                try:
                    telemetry = ProcessTelemetryEvent(
                        pid=1234,
                        ppid=1000,
                        process_name=evt.get("process_name", "unknown.exe"),
                        image_path=f"C:\\Windows\\System32\\{evt.get('process_name', 'unknown.exe')}",
                        command_line=evt.get("command_line", ""),
                        parent_process_name=evt.get("parent_process", "explorer.exe"),
                        user=evt.get("user_name", "sim_user"),
                    )
                    proc_events.append(telemetry)
                except Exception:
                    pass

        if proc_events:
            alerts = self._edr_engine.analyze_processes("SIM-AGENT", "SIM-HOST", proc_events)
            for a in alerts:
                matched_rules.append(f"EDR:{a.title} ({a.mitre_technique})")
        return matched_rules

    def _evaluate_with_cep(self, events: List[Dict[str, Any]]) -> List[str]:
        """Test events against CEP sliding window temporal correlation."""
        matched = []
        alerts = self._cep_engine.process_batch(events)
        for a in alerts:
            matched.append(f"CEP:{a.rule_id} - {a.rule_name}")
        return matched

    def _evaluate_with_hunting(self, test: AtomicTest, events: List[Dict[str, Any]]) -> List[str]:
        """Check if any hunting hypothesis matches test events."""
        matched = []
        hypos = self._hunting_engine.list_hypotheses()
        # Find matching hypothesis by technique
        target_hypos = [h for h in hypos if test.mitre_technique_id in h.mitre_technique_ids]
        if not target_hypos:
            target_hypos = hypos[:3]  # Fallback evaluate

        for hypo in target_hypos:
            try:
                res = self._hunting_engine.execute_hunt(
                    HuntExecutionRequest(hypothesis_id=hypo.id), events
                )
                if res.matched_events_count > 0:
                    matched.append(f"HUNT:{hypo.id} - {hypo.title}")
            except Exception:
                pass
        return matched

    def run_atomic_test(self, test: AtomicTest, mode: SimulationExecutionMode) -> AtomicTestResult:
        """Run single atomic test and check detection coverage."""
        t0 = time.perf_counter()
        events = test.simulated_events
        matched_rules = []
        detecting_engine = None

        if mode == SimulationExecutionMode.SYNTHETIC_INJECTION:
            # 1. Test EDR behavior engine
            edr_matches = self._evaluate_with_edr(events)
            if edr_matches:
                matched_rules.extend(edr_matches)
                detecting_engine = detecting_engine or "EDR Behavior Engine"

            # 2. Test CEP correlation engine
            cep_matches = self._evaluate_with_cep(events)
            if cep_matches:
                matched_rules.extend(cep_matches)
                detecting_engine = detecting_engine or "CEP Correlation Engine"

            # 3. Test Threat Hunting engine
            hunt_matches = self._evaluate_with_hunting(test, events)
            if hunt_matches:
                matched_rules.extend(hunt_matches)
                detecting_engine = detecting_engine or "Threat Hunting Workspace"

        duration_ms = (time.perf_counter() - t0) * 1000
        detected = len(matched_rules) > 0

        gap_notes = None
        if not detected:
            gap_notes = f"Technique {test.mitre_technique_id} ({test.name}) was not flagged by active detection rules."

        return AtomicTestResult(
            test_id=test.test_id,
            name=test.name,
            mitre_technique_id=test.mitre_technique_id,
            tactic=test.tactic,
            executed_at=datetime.utcnow(),
            duration_ms=round(duration_ms, 2),
            detected=detected,
            detecting_engine=detecting_engine,
            matched_rules=matched_rules,
            alerts_generated=len(matched_rules),
            gap_notes=gap_notes,
        )

    def execute_simulation_suite(self, request: SimulationRunRequest) -> SimulationReport:
        """Execute full or filtered suite of atomic breach simulations."""
        started_at = datetime.utcnow()
        selected_tests: List[AtomicTest] = []

        if request.test_ids:
            for tid in request.test_ids:
                t = get_atomic_test(tid)
                if t:
                    selected_tests.append(t)
        else:
            selected_tests = list(ATOMIC_TEST_CATALOG)

        results: List[AtomicTestResult] = []
        defense_gaps: List[Dict[str, str]] = []
        recommendations: List[str] = []

        for test in selected_tests:
            res = self.run_atomic_test(test, request.execution_mode)
            results.append(res)
            if not res.detected:
                defense_gaps.append({
                    "test_id": test.test_id,
                    "technique_id": test.mitre_technique_id,
                    "tactic": test.tactic,
                    "description": test.description,
                })
                recommendations.append(
                    f"Deploy Sigma/EDR detection rule targeting {test.mitre_technique_id} ({test.name})"
                )

        detected_count = sum(1 for r in results if r.detected)
        missed_count = len(results) - detected_count
        coverage_pct = (detected_count / len(results) * 100.0) if results else 0.0

        report = SimulationReport(
            run_id=f"BAS-{uuid.uuid4().hex[:8].upper()}",
            started_at=started_at,
            completed_at=datetime.utcnow(),
            execution_mode=request.execution_mode,
            total_tests_run=len(results),
            detected_count=detected_count,
            missed_count=missed_count,
            detection_coverage_pct=round(coverage_pct, 1),
            test_results=results,
            defense_gaps=defense_gaps,
            hardening_recommendations=recommendations,
        )

        self._reports_history[report.run_id] = report
        return report

    def get_report(self, run_id: str) -> Optional[SimulationReport]:
        return self._reports_history.get(run_id)

    def list_reports(self) -> List[SimulationReport]:
        return list(self._reports_history.values())
