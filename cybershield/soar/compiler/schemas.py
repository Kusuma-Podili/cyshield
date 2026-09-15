"""
Visual SOAR Workflow DAG Schemas and Execution Models.
Defines visual workflow graph nodes, edges, validation states, and execution traces.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class WorkflowNodeType(str, Enum):
    TRIGGER = "TRIGGER"
    CONDITION = "CONDITION"
    ACTION = "ACTION"
    DELAY = "DELAY"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"
    JOIN = "JOIN"


class WorkflowNode(BaseModel):
    """A node within a visual SOAR playbook DAG."""
    id: str
    type: WorkflowNodeType
    name: str
    action_type: Optional[str] = None  # e.g., "BLOCK_IP_ON_FIREWALL", "ISOLATE_HOST"
    parameters: Dict[str, Any] = Field(default_factory=dict)
    condition_expression: Optional[str] = None  # e.g., "context.severity == 'CRITICAL'"
    timeout_seconds: int = 300


class WorkflowEdge(BaseModel):
    """A directed edge connecting two playbook nodes."""
    source_node_id: str
    target_node_id: str
    branch_label: Optional[str] = None  # "true", "false", or None for unconditional


class VisualWorkflowDefinition(BaseModel):
    """Complete visual DAG specification submitted by UI workflow builder."""
    workflow_id: str
    name: str
    description: str = ""
    enabled: bool = True
    nodes: List[WorkflowNode] = Field(default_factory=list)
    edges: List[WorkflowEdge] = Field(default_factory=list)


class NodeExecutionTrace(BaseModel):
    """Audit trace of a single node's execution."""
    node_id: str
    node_name: str
    node_type: WorkflowNodeType
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    status: str = "PENDING"  # PENDING, RUNNING, COMPLETED, FAILED, WAITING_APPROVAL
    input_state: Dict[str, Any] = Field(default_factory=dict)
    output_state: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None


class WorkflowExecutionState(BaseModel):
    """Overall state of a running or completed SOAR workflow execution."""
    execution_id: str
    workflow_id: str
    status: str = "RUNNING"  # RUNNING, COMPLETED, SUSPENDED_WAITING_APPROVAL, FAILED
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    initial_context: Dict[str, Any] = Field(default_factory=dict)
    current_context: Dict[str, Any] = Field(default_factory=dict)
    node_traces: List[NodeExecutionTrace] = Field(default_factory=list)
    pending_approval_node_id: Optional[str] = None
