"""CyberShield Enterprise - Continuous Automated Red Teaming (CART) Planner.
Implements multi-objective Dijkstra/A* exploit path chaining, Crown Jewel exposure mapping,
defensive choke-point identification, and autonomous adversary campaign simulation.
"""

import math
import heapq
import random
import uuid
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict

from .schemas import (
    AssetTier,
    AttackGraphNode,
    AttackGraphEdge,
    ExploitPathStep,
    ExploitPathPlan,
    ChokePointReport,
    AdversaryProfile,
    SimulationRun,
)


class AttackGraphModel:
    """Topology graph representing enterprise assets, vulnerabilities, and lateral exploit links."""

    def __init__(self):
        self.nodes: Dict[str, AttackGraphNode] = {}
        self.edges: List[AttackGraphEdge] = []
        self.adj_out: Dict[str, List[AttackGraphEdge]] = defaultdict(list)
        self.adj_in: Dict[str, List[AttackGraphEdge]] = defaultdict(list)

    def add_node(self, node: AttackGraphNode) -> AttackGraphNode:
        """Register or update an asset node in the attack graph."""
        self.nodes[node.node_id] = node
        return node

    def add_edge(self, edge: AttackGraphEdge) -> AttackGraphEdge:
        """Add a directed exploit or lateral movement link."""
        self.edges.append(edge)
        self.adj_out[edge.source_id].append(edge)
        self.adj_in[edge.target_id].append(edge)
        return edge

    def get_crown_jewels(self) -> List[AttackGraphNode]:
        """Return all Tier 0 mission-critical Crown Jewel assets."""
        return [n for n in self.nodes.values() if n.asset_tier == AssetTier.TIER_0_CROWN_JEWEL]

    def get_entry_points(self) -> List[AttackGraphNode]:
        """Return all Tier 3 exposed perimeter assets."""
        return [n for n in self.nodes.values() if n.asset_tier == AssetTier.TIER_3_PERIMETER_EXPOSED]


class ExploitPathPlanner:
    """Calculates optimal adversary trajectories, choke points, and emulates attacks."""

    def __init__(self, graph: Optional[AttackGraphModel] = None):
        self.graph = graph or AttackGraphModel()
        self.simulation_history: List[SimulationRun] = []

    def plan_exploit_path(
        self,
        start_node_id: str,
        target_node_id: str,
        stealth_weight: float = 0.5,
    ) -> Optional[ExploitPathPlan]:
        """Calculates the lowest-cost adversary trajectory using multi-objective Dijkstra."""
        if start_node_id not in self.graph.nodes or target_node_id not in self.graph.nodes:
            return None

        # Priority queue stores: (cumulative_cost, current_node_id, path_edges)
        pq: List[Tuple[float, str, List[AttackGraphEdge]]] = [(0.0, start_node_id, [])]
        visited_costs: Dict[str, float] = {start_node_id: 0.0}

        best_plan_edges: Optional[List[AttackGraphEdge]] = None
        best_cost = float("inf")

        while pq:
            curr_cost, curr_node, edge_path = heapq.heappop(pq)

            if curr_node == target_node_id:
                best_plan_edges = edge_path
                best_cost = curr_cost
                break

            if curr_cost > visited_costs.get(curr_node, float("inf")):
                continue

            for edge in self.graph.adj_out.get(curr_node, []):
                # Edge weight formula:
                # balances intrinsic cost, success probability penalty, and stealth detection risk
                prob_penalty = -math.log(max(0.001, edge.success_probability))
                stealth_penalty = edge.detection_risk * (1.0 + stealth_weight * 2.0)
                step_weight = edge.transition_cost + (prob_penalty * 2.0) + (stealth_penalty * 3.0)

                new_cost = curr_cost + step_weight
                neighbor = edge.target_id

                if new_cost < visited_costs.get(neighbor, float("inf")):
                    visited_costs[neighbor] = new_cost
                    heapq.heappush(pq, (new_cost, neighbor, edge_path + [edge]))

        if not best_plan_edges:
            return None

        # Assemble plan
        target_node = self.graph.nodes[target_node_id]
        steps: List[ExploitPathStep] = []
        path_nodes: List[str] = [start_node_id]
        overall_success = 1.0
        cum_no_detect = 1.0
        recommended_defenses: List[str] = []

        for idx, edge in enumerate(best_plan_edges, start=1):
            steps.append(
                ExploitPathStep(
                    step_order=idx,
                    from_node_id=edge.source_id,
                    to_node_id=edge.target_id,
                    technique_id=edge.technique_id,
                    technique_name=edge.technique_name,
                    vuln_exploited=edge.required_vuln_id,
                    step_success_prob=edge.success_probability,
                    step_detection_risk=edge.detection_risk,
                )
            )
            path_nodes.append(edge.target_id)
            overall_success *= edge.success_probability
            cum_no_detect *= (1.0 - edge.detection_risk)

            # Defensive recommendations
            target_asset = self.graph.nodes.get(edge.target_id)
            if edge.required_vuln_id and target_asset:
                matching_vulns = [v for v in target_asset.vulnerabilities if v.vuln_id == edge.required_vuln_id]
                cve_label = matching_vulns[0].cve_id if matching_vulns else edge.required_vuln_id
                recommended_defenses.append(f"Deploy emergency virtual patch for {cve_label} on {target_asset.name}")
            else:
                recommended_defenses.append(f"Enforce microsegmentation blocking {edge.technique_name} from {edge.source_id} to {edge.target_id}")

        cum_detection_risk = round(1.0 - cum_no_detect, 3)

        return ExploitPathPlan(
            plan_id=f"plan-{uuid.uuid4().hex[:8]}",
            target_crown_jewel_id=target_node_id,
            target_name=target_node.name,
            path_nodes=path_nodes,
            steps=steps,
            overall_success_prob=round(overall_success, 4),
            cumulative_detection_risk=cum_detection_risk,
            path_cost=round(best_cost, 2),
            recommended_defenses=list(dict.fromkeys(recommended_defenses)),  # Deduplicated
        )

    def identify_choke_points(self) -> List[ChokePointReport]:
        """Calculates strategic choke-points where single defensive remediations sever multiple attack paths."""
        entry_points = self.graph.get_entry_points()
        crown_jewels = self.graph.get_crown_jewels()

        if not entry_points or not crown_jewels:
            return []

        # Find all paths from any entry point to any crown jewel
        path_counts = defaultdict(int)
        node_vulnerabilities = defaultdict(set)

        for ep in entry_points:
            for cj in crown_jewels:
                plan = self.plan_exploit_path(ep.node_id, cj.node_id)
                if plan and len(plan.path_nodes) > 2:
                    # Exclude start and terminal nodes; count intermediate bridge nodes
                    intermediate = plan.path_nodes[1:-1]
                    for nid in intermediate:
                        path_counts[nid] += 1
                        node = self.graph.nodes.get(nid)
                        if node:
                            for v in node.vulnerabilities:
                                node_vulnerabilities[nid].add(v.cve_id)

        reports: List[ChokePointReport] = []
        for nid, count in path_counts.items():
            node = self.graph.nodes[nid]
            impact = min(100.0, count * 25.0 + (len(node_vulnerabilities[nid]) * 10.0))
            reports.append(
                ChokePointReport(
                    choke_node_id=nid,
                    node_name=node.name,
                    asset_tier=node.asset_tier,
                    severed_paths_count=count,
                    critical_vulnerabilities=sorted(list(node_vulnerabilities[nid])),
                    defensive_impact_score=round(impact, 2),
                )
            )

        reports.sort(key=lambda x: x.defensive_impact_score, reverse=True)
        return reports

    def simulate_campaign(
        self,
        profile: AdversaryProfile,
        start_node_id: str,
        target_crown_jewel_id: str,
        rng_seed: Optional[int] = None,
    ) -> SimulationRun:
        """Executes a simulated adversary campaign step-by-step along the planned exploit trajectory."""
        rng = random.Random(rng_seed) if rng_seed is not None else random.Random()
        plan = self.plan_exploit_path(start_node_id, target_crown_jewel_id, stealth_weight=profile.stealth_weight)

        run_id = f"sim-{uuid.uuid4().hex[:8]}"
        timeline: List[Dict[str, Any]] = []

        if not plan:
            return SimulationRun(
                run_id=run_id,
                adversary_profile_id=profile.profile_id,
                start_node_id=start_node_id,
                target_crown_jewel_id=target_crown_jewel_id,
                reached_target=False,
                total_steps_executed=0,
                alert_triggered=False,
                timeline=[{"message": "No viable exploit path found from start to Crown Jewel."}],
            )

        reached = True
        alert_triggered = False
        steps_executed = 0

        for step in plan.steps:
            steps_executed += 1
            # Skill modifier: higher skill boosts success probability
            skill_boost = (profile.skill_level - 5) * 0.03
            effective_success = min(0.99, max(0.05, step.step_success_prob + skill_boost))

            roll_success = rng.random()
            step_passed = roll_success <= effective_success

            # Detection roll
            roll_detect = rng.random()
            detected = roll_detect <= step.step_detection_risk
            if detected:
                alert_triggered = True

            timeline.append({
                "step": step.step_order,
                "from": step.from_node_id,
                "to": step.to_node_id,
                "technique": step.technique_name,
                "success": step_passed,
                "detected": detected,
            })

            if not step_passed:
                reached = False
                break

        run = SimulationRun(
            run_id=run_id,
            adversary_profile_id=profile.profile_id,
            start_node_id=start_node_id,
            target_crown_jewel_id=target_crown_jewel_id,
            reached_target=reached,
            total_steps_executed=steps_executed,
            alert_triggered=alert_triggered,
            timeline=timeline,
        )
        self.simulation_history.append(run)
        return run
