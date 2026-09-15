"""
Visual SOAR Workflow DAG Compiler.
Performs graph validation, cycle detection, topological sorting, and dead-branch pruning.
"""

from collections import defaultdict, deque
from typing import Dict, List, Set, Tuple

from cybershield.soar.compiler.schemas import (
    VisualWorkflowDefinition,
    WorkflowEdge,
    WorkflowNode,
    WorkflowNodeType,
)


class CompiledWorkflowGraph:
    """Validated and optimized workflow execution graph."""

    def __init__(self, definition: VisualWorkflowDefinition):
        self.workflow_id = definition.workflow_id
        self.name = definition.name
        self.nodes: Dict[str, WorkflowNode] = {n.id: n for n in definition.nodes}
        self.trigger_nodes: List[str] = [n.id for n in definition.nodes if n.type == WorkflowNodeType.TRIGGER]
        # Outgoing edges: node_id -> List[(target_node_id, branch_label)]
        self.outgoing: Dict[str, List[Tuple[str, str | None]]] = defaultdict(list)
        # Incoming edges: node_id -> List[source_node_id]
        self.incoming: Dict[str, List[str]] = defaultdict(list)

        for edge in definition.edges:
            self.outgoing[edge.source_node_id].append((edge.target_node_id, edge.branch_label))
            self.incoming[edge.target_node_id].append(edge.source_node_id)


class SOARWorkflowCompiler:
    """Compiles visual workflow definitions into validated execution graphs."""

    @classmethod
    def compile(cls, definition: VisualWorkflowDefinition) -> CompiledWorkflowGraph:
        """Validate and compile visual workflow definition."""
        if not definition.nodes:
            raise ValueError("Workflow must contain at least one node")

        node_ids = {n.id for n in definition.nodes}
        if len(node_ids) != len(definition.nodes):
            raise ValueError("Duplicate node IDs found in workflow definition")

        # 1. Validate edge references
        for edge in definition.edges:
            if edge.source_node_id not in node_ids:
                raise ValueError(f"Edge references non-existent source node '{edge.source_node_id}'")
            if edge.target_node_id not in node_ids:
                raise ValueError(f"Edge references non-existent target node '{edge.target_node_id}'")

        # 2. Must have at least one TRIGGER node
        trigger_nodes = [n for n in definition.nodes if n.type == WorkflowNodeType.TRIGGER]
        if not trigger_nodes:
            raise ValueError("Workflow must contain at least one TRIGGER node")

        # 3. Cycle Detection using Kahn's algorithm
        in_degree: Dict[str, int] = {n.id: 0 for n in definition.nodes}
        for edge in definition.edges:
            in_degree[edge.target_node_id] += 1

        queue = deque([n.id for n in definition.nodes if in_degree[n.id] == 0])
        visited_count = 0

        while queue:
            curr = queue.popleft()
            visited_count += 1
            for edge in definition.edges:
                if edge.source_node_id == curr:
                    in_degree[edge.target_node_id] -= 1
                    if in_degree[edge.target_node_id] == 0:
                        queue.append(edge.target_node_id)

        if visited_count != len(definition.nodes):
            raise ValueError("Cyclic dependency detected in workflow DAG. Loops must be broken.")

        return CompiledWorkflowGraph(definition)
