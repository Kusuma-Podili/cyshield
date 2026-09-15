"""
Visual SOAR Workflow Compiler REST API Routes.
Exposes endpoints for compiling visual DAG workflows, executing playbooks, and approving gates.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from cybershield.soar.compiler.dag_compiler import SOARWorkflowCompiler
from cybershield.soar.compiler.runtime import SOARWorkflowRuntime
from cybershield.soar.compiler.schemas import (
    VisualWorkflowDefinition,
    WorkflowExecutionState,
)

soar_compiler_router = APIRouter(prefix="/api/soar/workflows", tags=["Visual SOAR Playbook Compiler"])
soar_runtime = SOARWorkflowRuntime()


class WorkflowRunPayload(BaseModel):
    workflow: VisualWorkflowDefinition
    context: Dict[str, Any] = Field(default_factory=dict)


class ApprovalPayload(BaseModel):
    approved: bool = True
    approver_notes: Optional[str] = None


@soar_compiler_router.post("/compile")
async def compile_workflow(workflow: VisualWorkflowDefinition):
    """Validate and compile a visual DAG workflow definition."""
    try:
        graph = SOARWorkflowCompiler.compile(workflow)
        soar_runtime.register_compiled_graph(graph)
        return {
            "status": "compiled",
            "workflow_id": graph.workflow_id,
            "total_nodes": len(graph.nodes),
            "triggers_count": len(graph.trigger_nodes),
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@soar_compiler_router.post("/execute", response_model=WorkflowExecutionState, status_code=status.HTTP_201_CREATED)
async def execute_workflow(payload: WorkflowRunPayload):
    """Compile and immediately execute a visual SOAR workflow with initial context."""
    try:
        graph = SOARWorkflowCompiler.compile(payload.workflow)
        return soar_runtime.execute_workflow(graph, payload.context)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@soar_compiler_router.get("/executions", response_model=List[WorkflowExecutionState])
async def list_executions():
    """List historical and active workflow executions."""
    return soar_runtime.list_executions()


@soar_compiler_router.get("/executions/{execution_id}", response_model=WorkflowExecutionState)
async def get_execution(execution_id: str):
    """Retrieve full node execution timeline and context state."""
    exec_state = soar_runtime.get_execution(execution_id)
    if not exec_state:
        raise HTTPException(status_code=404, detail=f"Execution '{execution_id}' not found")
    return exec_state


@soar_compiler_router.post("/executions/{execution_id}/approve", response_model=WorkflowExecutionState)
async def approve_step(execution_id: str, payload: ApprovalPayload):
    """Approve or reject a workflow suspended at a human-in-the-loop approval gate."""
    try:
        return soar_runtime.resume_approval(execution_id, payload.approved)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
