"""
Breach and Attack Simulation (BAS) Schemas and Models.
Defines atomic security tests, execution requests, detection validation results, and defense gap metrics.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SimulationExecutionMode(str, Enum):
    SYNTHETIC_INJECTION = "SYNTHETIC_INJECTION"  # Injects synthetic telemetry through detection pipeline
    DRY_RUN = "DRY_RUN"                          # Validates rule coverage statically


class AtomicTest(BaseModel):
    """An individual atomic attack simulation test mapped to MITRE ATT&CK."""
    test_id: str
    name: str
    tactic: str
    mitre_technique_id: str
    description: str
    category: str
    simulated_events: List[Dict[str, Any]] = Field(default_factory=list)
    expected_detection_engines: List[str] = Field(default_factory=list)  # ["EDR", "CEP", "SIGMA"]
    severity: str = "HIGH"


class AtomicTestResult(BaseModel):
    """Result of an individual simulated attack technique execution."""
    test_id: str
    name: str
    mitre_technique_id: str
    tactic: str
    executed_at: datetime = Field(default_factory=datetime.utcnow)
    duration_ms: float
    detected: bool
    detecting_engine: Optional[str] = None
    matched_rules: List[str] = Field(default_factory=list)
    alerts_generated: int = 0
    gap_notes: Optional[str] = None


class SimulationRunRequest(BaseModel):
    """Request to launch a Breach and Attack Simulation suite."""
    test_ids: Optional[List[str]] = None  # None executes all available tests
    execution_mode: SimulationExecutionMode = SimulationExecutionMode.SYNTHETIC_INJECTION
    target_host: str = "SIM-WORKSTATION-01"


class SimulationReport(BaseModel):
    """Comprehensive BAS validation report showing coverage and defense posture."""
    run_id: str
    started_at: datetime
    completed_at: datetime
    execution_mode: SimulationExecutionMode
    total_tests_run: int
    detected_count: int
    missed_count: int
    detection_coverage_pct: float
    test_results: List[AtomicTestResult] = Field(default_factory=list)
    defense_gaps: List[Dict[str, str]] = Field(default_factory=list)
    hardening_recommendations: List[str] = Field(default_factory=list)
