"""Graph Attack Path & Lateral Movement Analysis Engine.

Constructs identity and host relationship graphs from authentication telemetry
(Kerberos, NTLM, RDP, SMB, SSH) and computes lateral movement hops, pivot hubs,
and attack paths toward crown-jewel assets without external graph databases.
"""

from __future__ import annotations

import heapq
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("cybershield.ml.advanced.graph")


@dataclass
class GraphNode:
    node_id: str
    node_type: str  # HOST, USER, DOMAIN_CONTROLLER, DATABASE, CROWN_JEWEL
    label: str
    is_compromised: bool = False
    is_crown_jewel: bool = False
    attributes: Dict[str, str] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    relation: str  # ADMINS, LOGGED_INTO, ACCESSED_SHARE, RDP_SESSION, SSH_SESSION
    weight: float = 1.0  # Resistance to movement (lower = easier path)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AttackPathResult:
    source_id: str
    target_id: str
    path_found: bool
    hop_count: int
    path_nodes: List[str]
    total_resistance: float
    risk_score: float  # 0.0 to 100.0 (higher = easier/more dangerous attack path)
    choke_points: List[str]


class IdentityHostGraph:
    """In-memory topological attack graph engine for lateral movement modeling."""

    def __init__(self) -> None:
        self.nodes: Dict[str, GraphNode] = {}
        # Adjacency list: node_id -> List[(neighbor_id, weight, relation)]
        self.adj: Dict[str, List[Tuple[str, float, str]]] = defaultdict(list)
        self.reverse_adj: Dict[str, List[Tuple[str, float, str]]] = defaultdict(list)

    def add_node(
        self,
        node_id: str,
        node_type: str,
        label: Optional[str] = None,
        is_compromised: bool = False,
        is_crown_jewel: bool = False,
        attributes: Optional[Dict[str, str]] = None,
    ) -> GraphNode:
        """Add or update an identity/host graph vertex."""
        clean_id = node_id.strip()
        node = GraphNode(
            node_id=clean_id,
            node_type=node_type.upper(),
            label=label or clean_id,
            is_compromised=is_compromised,
            is_crown_jewel=is_crown_jewel,
            attributes=attributes or {},
        )
        self.nodes[clean_id] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        weight: float = 1.0,
    ) -> None:
        """Add a directed authentication / access edge."""
        src = source_id.strip()
        tgt = target_id.strip()
        if src not in self.nodes:
            self.add_node(src, "UNKNOWN")
        if tgt not in self.nodes:
            self.add_node(tgt, "UNKNOWN")

        self.adj[src].append((tgt, weight, relation))
        self.reverse_adj[tgt].append((src, weight, relation))

    def find_shortest_attack_path(
        self,
        start_node_id: str,
        target_node_id: str,
    ) -> AttackPathResult:
        """Compute Dijkstra shortest path / least resistance path between two nodes."""
        start = start_node_id.strip()
        target = target_node_id.strip()

        if start not in self.nodes or target not in self.nodes:
            return AttackPathResult(
                source_id=start,
                target_id=target,
                path_found=False,
                hop_count=0,
                path_nodes=[],
                total_resistance=float("inf"),
                risk_score=0.0,
                choke_points=[],
            )

        # Priority queue: (accumulated_weight, current_node, path_nodes)
        pq: List[Tuple[float, str, List[str]]] = [(0.0, start, [start])]
        visited: Dict[str, float] = {start: 0.0}

        while pq:
            cost, u, path = heapq.heappop(pq)

            if u == target:
                hop_count = len(path) - 1
                # Risk score inversely proportional to resistance and hop count
                # Short, low-resistance path = 95+ risk
                risk = max(10.0, min(99.0, round(100.0 / (1.0 + cost * 0.5 + hop_count * 0.3), 1)))
                
                # Choke points are intermediate nodes excluding endpoints
                choke_points = path[1:-1]

                return AttackPathResult(
                    source_id=start,
                    target_id=target,
                    path_found=True,
                    hop_count=hop_count,
                    path_nodes=path,
                    total_resistance=round(cost, 2),
                    risk_score=risk,
                    choke_points=choke_points,
                )

            if cost > visited.get(u, float("inf")):
                continue

            for v, weight, _ in self.adj[u]:
                new_cost = cost + weight
                if new_cost < visited.get(v, float("inf")):
                    visited[v] = new_cost
                    heapq.heappush(pq, (new_cost, v, path + [v]))

        return AttackPathResult(
            source_id=start,
            target_id=target,
            path_found=False,
            hop_count=0,
            path_nodes=[],
            total_resistance=float("inf"),
            risk_score=0.0,
            choke_points=[],
        )

    def detect_pivot_hubs(self, min_degree: int = 3) -> List[Dict[str, Any]]:
        """Identify critical pivot hubs (nodes with high in-degree and out-degree)."""
        hubs = []
        for node_id, node in self.nodes.items():
            in_deg = len(self.reverse_adj[node_id])
            out_deg = len(self.adj[node_id])
            total_degree = in_deg + out_deg
            if total_degree >= min_degree:
                hubs.append({
                    "node_id": node_id,
                    "label": node.label,
                    "node_type": node.node_type,
                    "in_degree": in_deg,
                    "out_degree": out_deg,
                    "total_connections": total_degree,
                    "is_compromised": node.is_compromised,
                })
        hubs.sort(key=lambda x: x["total_connections"], reverse=True)
        return hubs

    def seed_enterprise_topology(self) -> None:
        """Seed representative enterprise active directory / subnet topology."""
        # Nodes
        self.add_node("ws-hr-01", "HOST", "HR Laptop 1", is_compromised=True)
        self.add_node("ws-eng-04", "HOST", "Engineering Workstation 4")
        self.add_node("srv-jumpbox-01", "HOST", "DMZ Bastion Jumpbox")
        self.add_node("admin_alice", "USER", "Alice (Domain Admin)")
        self.add_node("dc-primary.corp", "DOMAIN_CONTROLLER", "Primary Domain Controller", is_crown_jewel=True)
        self.add_node("db-financial-sql", "DATABASE", "SWIFT Wire Database", is_crown_jewel=True)

        # Lateral movement edges
        self.add_edge("ws-hr-01", "srv-jumpbox-01", "RDP_SESSION", weight=1.5)
        self.add_edge("srv-jumpbox-01", "admin_alice", "CACHED_CREDENTIALS", weight=0.8)
        self.add_edge("admin_alice", "dc-primary.corp", "DOMAIN_ADMIN", weight=0.5)
        self.add_edge("dc-primary.corp", "db-financial-sql", "ENTERPRISE_ADMIN", weight=0.2)
        self.add_edge("ws-hr-01", "ws-eng-04", "SMB_SHARE", weight=2.0)
        self.add_edge("ws-eng-04", "db-financial-sql", "APP_SERVICE", weight=3.5)
