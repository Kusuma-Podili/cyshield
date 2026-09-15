"""
Visual SOAR Workflow Execution Runtime.
Executes compiled DAG graphs with state tracking, variable interpolation, and human approval gates.
"""

import copy
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from cybershield.soar.compiler.dag_compiler import CompiledWorkflowGraph
from cybershield.soar.compiler.schemas import (
    NodeExecutionTrace,
    WorkflowExecutionState,
    WorkflowNode,
    WorkflowNodeType,
)


class SOARWorkflowRuntime:
    """Execution engine for compiled visual SOAR workflows."""

    def __init__(self):
        self._executions: Dict[str, WorkflowExecutionState] = {}
        self._compiled_graphs: Dict[str, CompiledWorkflowGraph] = {}

    def register_compiled_graph(self, graph: CompiledWorkflowGraph) -> None:
        self._compiled_graphs[graph.workflow_id] = graph

    def get_execution(self, execution_id: str) -> Optional[WorkflowExecutionState]:
        return self._executions.get(execution_id)

    def list_executions(self) -> List[WorkflowExecutionState]:
        return list(self._executions.values())

    @staticmethod
    def _evaluate_condition(expression: Optional[str], context: Dict[str, Any]) -> bool:
        """Safely evaluate simple comparison expression against context dictionary."""
        if not expression:
            return True

        # Example expressions: "severity == 'CRITICAL'" or "score >= 80"
        try:
            # Safe evaluation environment
            safe_ctx = {"context": context, **context}
            # Replace common syntax
            expr = expression.strip()
            # Basic comparisons
            if "==" in expr:
                left, right = [p.strip() for p in expr.split("==", 1)]
                lval = safe_ctx.get(left.replace("context.", ""), left.strip("'\""))
                rval = right.strip("'\"")
                return str(lval).lower() == str(rval).lower()
            elif "!=" in expr:
                left, right = [p.strip() for p in expr.split("!=", 1)]
                lval = safe_ctx.get(left.replace("context.", ""), left.strip("'\""))
                rval = right.strip("'\"")
                return str(lval).lower() != str(rval).lower()
            elif ">=" in expr:
                left, right = [p.strip() for p in expr.split(">=", 1)]
                lval = float(safe_ctx.get(left.replace("context.", ""), 0))
                rval = float(right)
                return lval >= rval
            elif ">" in expr:
                left, right = [p.strip() for p in expr.split(">", 1)]
                lval = float(safe_ctx.get(left.replace("context.", ""), 0))
                rval = float(right)
                return lval > rval
        except Exception:
            return False

        return True

    @staticmethod
    def _interpolate_parameters(params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Interpolate {{context.var}} variables in action parameters."""
        resolved = {}
        for k, v in params.items():
            if isinstance(v, str) and "{{" in v and "}}" in v:
                match = re.search(r"\{\{\s*(?:context\.)?([a-zA-Z0-9_]+)\s*\}\}", v)
                if match:
                    var_name = match.group(1)
                    val = context.get(var_name, "")
                    resolved[k] = v.replace(match.group(0), str(val))
                else:
                    resolved[k] = v
            else:
                resolved[k] = v
        return resolved

    def execute_workflow(
        self, graph: CompiledWorkflowGraph, initial_context: Dict[str, Any]
    ) -> WorkflowExecutionState:
        """Execute a compiled workflow DAG from its trigger nodes."""
        exec_id = f"EXEC-SOAR-{uuid.uuid4().hex[:8].upper()}"
        state = WorkflowExecutionState(
            execution_id=exec_id,
            workflow_id=graph.workflow_id,
            status="RUNNING",
            started_at=datetime.utcnow(),
            initial_context=copy.deepcopy(initial_context),
            current_context=copy.deepcopy(initial_context),
        )
        self._executions[exec_id] = state
        self._compiled_graphs[graph.workflow_id] = graph

        # Start execution from triggers
        queue = list(graph.trigger_nodes)
        visited = set()

        while queue:
            node_id = queue.pop(0)
            if node_id in visited:
                continue
            visited.add(node_id)

            node = graph.nodes[node_id]
            trace = NodeExecutionTrace(
                node_id=node.id,
                node_name=node.name,
                node_type=node.type,
                started_at=datetime.utcnow(),
                input_state=copy.deepcopy(state.current_context),
            )

            # Node Execution Logic
            if node.type == WorkflowNodeType.TRIGGER:
                trace.status = "COMPLETED"
                trace.output_state = {"triggered": True}

            elif node.type == WorkflowNodeType.CONDITION:
                cond_result = self._evaluate_condition(node.condition_expression, state.current_context)
                trace.status = "COMPLETED"
                trace.output_state = {"condition_result": cond_result}

            elif node.type == WorkflowNodeType.ACTION:
                # Resolve parameters and simulate action invocation
                resolved_params = self._interpolate_parameters(node.parameters, state.current_context)
                trace.status = "COMPLETED"
                output = {
                    "action": node.action_type,
                    "parameters_executed": resolved_params,
                    "action_status": "SUCCESS",
                }
                trace.output_state = output
                state.current_context[f"{node.id}_result"] = output

            elif node.type == WorkflowNodeType.HUMAN_APPROVAL:
                trace.status = "WAITING_APPROVAL"
                trace.completed_at = datetime.utcnow()
                state.node_traces.append(trace)
                state.status = "SUSPENDED_WAITING_APPROVAL"
                state.pending_approval_node_id = node.id
                return state

            trace.completed_at = datetime.utcnow()
            state.node_traces.append(trace)

            # Determine next nodes from outgoing edges
            outgoing_edges = graph.outgoing.get(node_id, [])
            for target_id, branch_label in outgoing_edges:
                if node.type == WorkflowNodeType.CONDITION:
                    cond_bool = trace.output_state.get("condition_result", True)
                    expected_label = "true" if cond_bool else "false"
                    if branch_label and branch_label.lower() == expected_label:
                        queue.append(target_id)
                else:
                    # Unconditional edge
                    queue.append(target_id)

        state.status = "COMPLETED"
        state.completed_at = datetime.utcnow()
        return state

    def resume_approval(self, execution_id: str, approved: bool) -> WorkflowExecutionState:
        """Resume a suspended workflow after human approval decision."""
        state = self._executions.get(execution_id)
        if not state:
            raise ValueError(f"Execution '{execution_id}' not found")
        if state.status != "SUSPENDED_WAITING_APPROVAL" or not state.pending_approval_node_id:
            raise ValueError(f"Execution '{execution_id}' is not waiting for approval")

        graph = self._compiled_graphs.get(state.workflow_id)
        if not graph:
            raise ValueError(f"Graph for workflow '{state.workflow_id}' not found")

        curr_node_id = state.pending_approval_node_id
        # Update last trace
        if state.node_traces and state.node_traces[-1].node_id == curr_node_id:
            state.node_traces[-1].status = "APPROVED" if approved else "REJECTED"
            state.node_traces[-1].output_state = {"approved": approved}

        state.pending_approval_node_id = None

        if not approved:
            state.status = "COMPLETED"
            state.completed_at = datetime.utcnow()
            return state

        # Continue execution along outgoing edges
        queue = [target_id for (target_id, _) in graph.outgoing.get(curr_node_id, [])]
        state.status = "RUNNING"

        while queue:
            node_id = queue.pop(0)
            node = graph.nodes[node_id]
            trace = NodeExecutionTrace(
                node_id=node.id,
                node_name=node.name,
                node_type=node.type,
                started_at=datetime.utcnow(),
                input_state=copy.deepcopy(state.current_context),
            )

            if node.type == WorkflowNodeType.ACTION:
                resolved_params = self._interpolate_parameters(node.parameters, state.current_context)
                trace.status = "COMPLETED"
                output = {"action": node.action_type, "parameters": resolved_params, "action_status": "SUCCESS"}
                trace.output_state = output
                state.current_context[f"{node.id}_result"] = output

            trace.completed_at = datetime.utcnow()
            state.node_traces.append(trace)

            for target_id, _ in graph.outgoing.get(node_id, []):
                queue.append(target_id)

        state.status = "COMPLETED"
        state.completed_at = datetime.utcnow()
        return state
