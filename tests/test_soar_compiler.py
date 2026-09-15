"""
Unit and Integration Tests for Visual SOAR Workflow Compiler and Runtime.
Verifies graph compilation, cycle detection, conditional branching, parameter interpolation, and human gates.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.soar.compiler.dag_compiler import SOARWorkflowCompiler
from cybershield.soar.compiler.runtime import SOARWorkflowRuntime
from cybershield.soar.compiler.schemas import (
    VisualWorkflowDefinition,
    WorkflowEdge,
    WorkflowNode,
    WorkflowNodeType,
)


@pytest.fixture
def runtime():
    return SOARWorkflowRuntime()


@pytest.fixture
def client():
    return TestClient(app)


def test_valid_workflow_compilation():
    wf = VisualWorkflowDefinition(
        workflow_id="wf-test-01",
        name="Auto Containment Playbook",
        nodes=[
            WorkflowNode(id="n1", type=WorkflowNodeType.TRIGGER, name="Ransomware Alert Trigger"),
            WorkflowNode(id="n2", type=WorkflowNodeType.ACTION, name="Isolate Host", action_type="QUARANTINE_HOST"),
        ],
        edges=[
            WorkflowEdge(source_node_id="n1", target_node_id="n2"),
        ],
    )
    graph = SOARWorkflowCompiler.compile(wf)
    assert graph.workflow_id == "wf-test-01"
    assert len(graph.nodes) == 2
    assert "n1" in graph.trigger_nodes


def test_cycle_detection():
    # Construct cyclic graph: n1 -> n2 -> n3 -> n2 (loop!)
    wf_cycle = VisualWorkflowDefinition(
        workflow_id="wf-cycle-01",
        name="Invalid Cyclic Playbook",
        nodes=[
            WorkflowNode(id="n1", type=WorkflowNodeType.TRIGGER, name="Trigger"),
            WorkflowNode(id="n2", type=WorkflowNodeType.ACTION, name="Step 1"),
            WorkflowNode(id="n3", type=WorkflowNodeType.ACTION, name="Step 2"),
        ],
        edges=[
            WorkflowEdge(source_node_id="n1", target_node_id="n2"),
            WorkflowEdge(source_node_id="n2", target_node_id="n3"),
            WorkflowEdge(source_node_id="n3", target_node_id="n2"),  # Loop!
        ],
    )
    with pytest.raises(ValueError, match="Cyclic dependency detected"):
        SOARWorkflowCompiler.compile(wf_cycle)


def test_linear_execution_with_interpolation(runtime):
    wf = VisualWorkflowDefinition(
        workflow_id="wf-linear-01",
        name="Firewall Block Playbook",
        nodes=[
            WorkflowNode(id="t1", type=WorkflowNodeType.TRIGGER, name="C2 Alert"),
            WorkflowNode(
                id="a1",
                type=WorkflowNodeType.ACTION,
                name="Block IP",
                action_type="BLOCK_IP_ON_FIREWALL",
                parameters={"target_ip": "{{source_ip}}", "firewall_group": "Edge-DMZ"},
            ),
        ],
        edges=[WorkflowEdge(source_node_id="t1", target_node_id="a1")],
    )
    graph = SOARWorkflowCompiler.compile(wf)
    context = {"source_ip": "198.51.100.99", "severity": "HIGH"}

    state = runtime.execute_workflow(graph, context)
    assert state.status == "COMPLETED"
    assert len(state.node_traces) == 2

    # Check parameter interpolation result
    action_trace = state.node_traces[1]
    assert action_trace.node_id == "a1"
    assert action_trace.output_state["parameters_executed"]["target_ip"] == "198.51.100.99"


def test_conditional_branching_execution(runtime):
    wf = VisualWorkflowDefinition(
        workflow_id="wf-cond-01",
        name="Triage Escalation Playbook",
        nodes=[
            WorkflowNode(id="t1", type=WorkflowNodeType.TRIGGER, name="Alert"),
            WorkflowNode(
                id="c1",
                type=WorkflowNodeType.CONDITION,
                name="Is Critical?",
                condition_expression="severity == 'CRITICAL'",
            ),
            WorkflowNode(id="a_crit", type=WorkflowNodeType.ACTION, name="Automated Isolate", action_type="ISOLATE_HOST"),
            WorkflowNode(id="a_norm", type=WorkflowNodeType.ACTION, name="Slack Notify", action_type="SEND_NOTIFICATION"),
        ],
        edges=[
            WorkflowEdge(source_node_id="t1", target_node_id="c1"),
            WorkflowEdge(source_node_id="c1", target_node_id="a_crit", branch_label="true"),
            WorkflowEdge(source_node_id="c1", target_node_id="a_norm", branch_label="false"),
        ],
    )
    graph = SOARWorkflowCompiler.compile(wf)

    # Case 1: Critical severity -> follows true branch
    state_crit = runtime.execute_workflow(graph, {"severity": "CRITICAL"})
    visited_ids = [t.node_id for t in state_crit.node_traces]
    assert "a_crit" in visited_ids
    assert "a_norm" not in visited_ids

    # Case 2: Low severity -> follows false branch
    state_low = runtime.execute_workflow(graph, {"severity": "LOW"})
    visited_low = [t.node_id for t in state_low.node_traces]
    assert "a_norm" in visited_low
    assert "a_crit" not in visited_low


def test_human_approval_suspension_and_resume(runtime):
    wf = VisualWorkflowDefinition(
        workflow_id="wf-approval-01",
        name="Dangerous Containment with Gate",
        nodes=[
            WorkflowNode(id="t1", type=WorkflowNodeType.TRIGGER, name="Trigger"),
            WorkflowNode(id="g1", type=WorkflowNodeType.HUMAN_APPROVAL, name="SOC Lead Gate"),
            WorkflowNode(id="a1", type=WorkflowNodeType.ACTION, name="Kill Domain Controller Service"),
        ],
        edges=[
            WorkflowEdge(source_node_id="t1", target_node_id="g1"),
            WorkflowEdge(source_node_id="g1", target_node_id="a1"),
        ],
    )
    graph = SOARWorkflowCompiler.compile(wf)

    state = runtime.execute_workflow(graph, {"asset": "DC01"})
    assert state.status == "SUSPENDED_WAITING_APPROVAL"
    assert state.pending_approval_node_id == "g1"

    # Resume with approval
    resumed = runtime.resume_approval(state.execution_id, approved=True)
    assert resumed.status == "COMPLETED"
    trace_ids = [t.node_id for t in resumed.node_traces]
    assert "a1" in trace_ids


def test_soar_compiler_api_endpoints(client):
    wf_payload = {
        "workflow": {
            "workflow_id": "wf-api-test",
            "name": "API Test Playbook",
            "nodes": [
                {"id": "node-1", "type": "TRIGGER", "name": "API Trigger"},
                {
                    "id": "node-2",
                    "type": "ACTION",
                    "name": "Block Attacker",
                    "action_type": "BLOCK_IP",
                    "parameters": {"ip": "{{src_ip}}"},
                },
            ],
            "edges": [{"source_node_id": "node-1", "target_node_id": "node-2"}],
        },
        "context": {"src_ip": "185.220.101.55"},
    }

    # 1. Compile endpoint
    resp = client.post("/api/soar/workflows/compile", json=wf_payload["workflow"])
    assert resp.status_code == 200
    assert resp.json()["status"] == "compiled"

    # 2. Execute endpoint
    resp = client.post("/api/soar/workflows/execute", json=wf_payload)
    assert resp.status_code == 201
    exec_data = resp.json()
    assert exec_data["status"] == "COMPLETED"
    exec_id = exec_data["execution_id"]

    # 3. Retrieve execution
    resp = client.get(f"/api/soar/workflows/executions/{exec_id}")
    assert resp.status_code == 200
    assert resp.json()["execution_id"] == exec_id

    # 4. List executions
    resp = client.get("/api/soar/workflows/executions")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1
