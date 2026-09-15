"""CyberShield Enterprise - Continuous Automated Red Teaming (CART) API Routes.
Exposes endpoints for attack graph management, multi-hop exploit path planning,
choke-point analysis, and autonomous adversary simulation runs.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    AttackGraphNode,
    AttackGraphEdge,
    ExploitPathPlan,
    ChokePointReport,
    AdversaryProfile,
    SimulationRun,
)
from .planner import AttackGraphModel, ExploitPathPlanner

router = APIRouter(prefix="/api/v1/cart", tags=["Continuous Automated Red Teaming (CART)"])

# Active singleton CART model and planner
_GRAPH = AttackGraphModel()
_PLANNER = ExploitPathPlanner(graph=_GRAPH)


@router.post("/nodes", response_model=AttackGraphNode, status_code=status.HTTP_201_CREATED)
def add_asset_node(node: AttackGraphNode):
    """Register or update an asset in the continuous attack graph."""
    return _GRAPH.add_node(node)


@router.get("/nodes", response_model=List[AttackGraphNode])
def list_asset_nodes():
    """Retrieve all assets currently mapped in the attack graph."""
    return list(_GRAPH.nodes.values())


@router.post("/edges", response_model=AttackGraphEdge, status_code=status.HTTP_201_CREATED)
def add_exploit_edge(edge: AttackGraphEdge):
    """Define a feasible lateral movement or exploitation link between two assets."""
    if edge.source_id not in _GRAPH.nodes:
        raise HTTPException(status_code=404, detail=f"Source node '{edge.source_id}' does not exist.")
    if edge.target_id not in _GRAPH.nodes:
        raise HTTPException(status_code=404, detail=f"Target node '{edge.target_id}' does not exist.")
    return _GRAPH.add_edge(edge)


@router.get("/edges", response_model=List[AttackGraphEdge])
def list_exploit_edges():
    """Retrieve all mapped exploit transitions and lateral movement links."""
    return _GRAPH.edges


@router.post("/plan", response_model=ExploitPathPlan)
def plan_attack_path(
    start_node_id: str = Query(..., description="Starting compromised entry asset"),
    target_node_id: str = Query(..., description="Target Crown Jewel asset"),
    stealth_weight: float = Query(0.5, ge=0.0, le=1.0, description="Adversary stealth preference"),
):
    """Calculate the lowest-cost optimal adversary exploit path to Crown Jewel."""
    plan = _PLANNER.plan_exploit_path(
        start_node_id=start_node_id,
        target_node_id=target_node_id,
        stealth_weight=stealth_weight,
    )
    if not plan:
        raise HTTPException(status_code=404, detail="No viable attack path found between specified assets.")
    return plan


@router.get("/chokepoints", response_model=List[ChokePointReport])
def get_defensive_chokepoints():
    """Identify strategic enterprise choke-points for maximum ROI defensive hardening."""
    return _PLANNER.identify_choke_points()


@router.post("/simulate", response_model=SimulationRun, status_code=status.HTTP_201_CREATED)
def run_adversary_simulation(
    start_node_id: str = Query(...),
    target_crown_jewel_id: str = Query(...),
    skill_level: int = Query(8, ge=1, le=10),
    stealth_weight: float = Query(0.7, ge=0.0, le=1.0),
    profile_name: str = Query("APT29_CozyBear"),
):
    """Execute an autonomous step-by-step red team adversary campaign simulation."""
    profile = AdversaryProfile(
        profile_id=f"prof-{profile_name.lower()}",
        name=profile_name,
        skill_level=skill_level,
        stealth_weight=stealth_weight,
    )
    return _PLANNER.simulate_campaign(
        profile=profile,
        start_node_id=start_node_id,
        target_crown_jewel_id=target_crown_jewel_id,
    )


@router.get("/simulations", response_model=List[SimulationRun])
def list_simulation_runs():
    """Retrieve execution history of past autonomous red team simulation campaigns."""
    return _PLANNER.simulation_history
