"""CyberShield Enterprise - SOAR Hot-Reload Schemas.
Data contracts for dynamic Python playbooks, AST validation security policies,
sandbox runtime execution results, and hot-reload registry metrics.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class PlaybookTriggerType(str, Enum):
    ALERT_SEVERITY = "ALERT_SEVERITY"
    MITRE_TECHNIQUE = "MITRE_TECHNIQUE"
    ENDPOINT_QUARANTINE_REQUEST = "ENDPOINT_QUARANTINE_REQUEST"
    SCHEDULED_CRON = "SCHEDULED_CRON"
    MANUAL_WEBHOOK = "MANUAL_WEBHOOK"


class PlaybookExitStatus(str, Enum):
    SUCCESS = "SUCCESS"
    TIMED_OUT = "TIMED_OUT"
    SANDBOX_VIOLATION = "SANDBOX_VIOLATION"
    RUNTIME_ERROR = "RUNTIME_ERROR"


class SafetySandboxPolicy(BaseModel):
    """Execution sandbox constraints preventing malicious or runaway playbook code."""
    max_memory_mb: int = Field(default=64, ge=16, le=512)
    timeout_seconds: float = Field(default=5.0, ge=0.5, le=30.0)
    allowed_modules: List[str] = Field(
        default_factory=lambda: ["json", "math", "datetime", "re", "collections", "urllib.parse"]
    )
    disallowed_calls: List[str] = Field(
        default_factory=lambda: ["eval", "exec", "compile", "open", "globals", "locals", "__import__", "getattr", "setattr"]
    )


class DynamicPlaybookSpec(BaseModel):
    """Definition of a dynamic, hot-reloadable SOAR response playbook."""
    playbook_id: str = Field(..., description="Unique playbook identifier")
    name: str = Field(..., description="Human-readable playbook name")
    version: int = Field(default=1, ge=1)
    trigger_type: PlaybookTriggerType = PlaybookTriggerType.ALERT_SEVERITY
    natural_language_intent: Optional[str] = Field(default=None, description="Original prompt / intent")
    python_source_code: str = Field(..., description="Python source implementing run_playbook(context, actions)")
    safety_policy: SafetySandboxPolicy = Field(default_factory=SafetySandboxPolicy)
    is_active: bool = True
    author: str = Field(default="SOC_Automation_Agent")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ASTValidationResult(BaseModel):
    """Results of static Python AST security inspection prior to compilation."""
    is_safe: bool
    ast_nodes_inspected: int
    detected_violations: List[str] = Field(default_factory=list)
    compiled_bytecode_hash: Optional[str] = None


class PlaybookExecutionResult(BaseModel):
    """Audit record of a dynamic sandboxed playbook execution run."""
    execution_id: str
    playbook_id: str
    playbook_version: int
    trigger_event: Dict[str, Any]
    exit_status: PlaybookExitStatus
    output_log: List[str] = Field(default_factory=list)
    execution_duration_ms: float
    actions_invoked: List[str] = Field(default_factory=list)
    error_message: Optional[str] = None
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class HotReloadRegistryMetrics(BaseModel):
    """Throughput and health metrics of the SOAR hot-reload subsystem."""
    active_hotloaded_playbooks: int
    total_compilations: int
    sandbox_rejections: int
    total_executions: int
    rollbacks_executed: int
