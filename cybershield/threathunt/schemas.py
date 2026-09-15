"""
CyberShield Enterprise - Threat Hunting Hypothesis Matrix & Multi-Engine Transpiler Schemas
Provides data models for MITRE ATT&CK hunting hypotheses, universal query conditions,
multi-engine query transpilation (CS-QL, Sigma, SPL, KQL, EQL), and hunt findings.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class TargetQueryEngine(str, Enum):
    CS_QL = "cs_ql"
    SIGMA = "sigma"
    SPLUNK_SPL = "splunk_spl"
    MICROSOFT_KQL = "microsoft_kql"
    ELASTIC_EQL = "elastic_eql"


class HuntConfidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"


class HuntLifecycleState(str, Enum):
    HYPOTHESIS_FORMULATED = "HYPOTHESIS_FORMULATED"
    QUERY_GENERATED = "QUERY_GENERATED"
    EXECUTING = "EXECUTING"
    FINDINGS_IDENTIFIED = "FINDINGS_IDENTIFIED"
    HARDENED_TO_RULE = "HARDENED_TO_RULE"
    CLOSED = "CLOSED"


class HuntCondition(BaseModel):
    field: str = Field(..., description="Target telemetry field (e.g. process_name, command_line, parent_process)")
    operator: str = Field("contains", description="'equals', 'contains', 'in', 'regex', 'not_equals'")
    values: List[str] = Field(..., description="Target match values")


class HuntingHypothesis(BaseModel):
    hypothesis_id: str = Field(..., description="Unique hypothesis identifier (e.g. HUNT-01)")
    title: str = Field(..., description="Descriptive hypothesis title")
    mitre_technique_id: str = Field(..., description="MITRE ATT&CK technique code (e.g. T1059.001)")
    mitre_tactic: str = Field(..., description="MITRE tactic (e.g. Execution, Persistence, Lateral Movement)")
    description: str = Field(..., description="Core hunting hypothesis premise and expected adversary behavior")
    data_sources: List[str] = Field(..., description="Required telemetry sources (e.g. Process Creation, Network Flow)")
    conditions: List[HuntCondition] = Field(default_factory=list, description="Structured query predicates")
    state: HuntLifecycleState = Field(HuntLifecycleState.HYPOTHESIS_FORMULATED, description="Hunt campaign status")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")


class TranspiledQuery(BaseModel):
    engine: TargetQueryEngine = Field(..., description="Target query dialect")
    query_text: str = Field(..., description="Synthesized query syntax")
    syntax_valid: bool = Field(True, description="Whether generated query conforms to engine grammars")
    estimated_efficiency: str = Field("HIGH", description="Query execution plan rating")


class MultiQueryBundle(BaseModel):
    hypothesis_id: str = Field(..., description="Linked hypothesis ID")
    transpiled_queries: Dict[TargetQueryEngine, str] = Field(..., description="Dialect -> Query string mapping")


class HuntFinding(BaseModel):
    finding_id: str = Field(..., description="Unique hunt finding UUID")
    hypothesis_id: str = Field(..., description="Originating hypothesis ID")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Detection timestamp")
    entity_name: str = Field(..., description="Affected host, user, or IP")
    telemetry_match: Dict[str, Any] = Field(default_factory=dict, description="Matched event attributes")
    rarity_score: float = Field(..., description="Statistical anomaly score (0.0 = common, 1.0 = rare)")
    confidence: HuntConfidence = Field(HuntConfidence.MEDIUM, description="Analyst confidence")
    mitre_technique_id: str = Field(..., description="ATT&CK technique ID")
    recommended_action: str = Field(..., description="Prescribed containment action")


class HuntCampaignReport(BaseModel):
    campaign_id: str = Field(..., description="Unique hunt campaign run ID")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Report timestamp")
    hypotheses_evaluated: int = Field(0, description="Count of hypotheses tested")
    queries_transpiled: int = Field(0, description="Count of multi-engine queries generated")
    total_findings: int = Field(0, description="Number of anomalous items uncovered")
    findings: List[HuntFinding] = Field(default_factory=list, description="Identified threat findings")
    coverage_score: float = Field(..., description="ATT&CK hunting coverage metric (0 - 100)")
    hardened_rules_generated: int = Field(0, description="Count of converted production Sigma rules")
