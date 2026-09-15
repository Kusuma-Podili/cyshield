"""CyberShield Enterprise - Security Graph Builder & Feature Extractor.
Constructs multi-relational enterprise attack graphs and computes high-dimensional
entity feature vectors for inductive Graph Neural Network processing.
"""

import math
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict

from .schemas import (
    GraphNodeType,
    GraphEdgeType,
    SecurityNode,
    SecurityEdge,
    HeterogeneousGraph,
    NodeFeatureVector,
)

FEATURE_DIM = 24


class SecurityGraphBuilder:
    """Manages graph topology, adjacency lists, and feature extraction for enterprise security entities."""

    def __init__(self, graph_id: str = "graph-default", tenant_id: str = "TENANT-DEFAULT"):
        self.graph_id = graph_id
        self.tenant_id = tenant_id
        self.nodes: Dict[str, SecurityNode] = {}
        self.edges: List[SecurityEdge] = []
        # Adjacency maps: node_id -> list of (neighbor_id, edge_type, weight, direction)
        self.adj_out: Dict[str, List[SecurityEdge]] = defaultdict(list)
        self.adj_in: Dict[str, List[SecurityEdge]] = defaultdict(list)
        self.neighbors: Dict[str, Set[str]] = defaultdict(set)

    def add_node(
        self,
        node_id: str,
        node_type: GraphNodeType,
        label: str,
        properties: Optional[Dict[str, Any]] = None,
        base_risk_score: float = 0.0,
        is_compromised_seed: bool = False,
    ) -> SecurityNode:
        """Add or update an entity node in the graph."""
        node = SecurityNode(
            node_id=node_id,
            node_type=node_type,
            label=label,
            properties=properties or {},
            base_risk_score=float(base_risk_score),
            is_compromised_seed=is_compromised_seed,
        )
        self.nodes[node_id] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: GraphEdgeType,
        weight: float = 1.0,
        properties: Optional[Dict[str, Any]] = None,
    ) -> SecurityEdge:
        """Add a directed edge between two security entity nodes."""
        edge = SecurityEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            weight=float(weight),
            properties=properties or {},
        )
        self.edges.append(edge)
        self.adj_out[source_id].append(edge)
        self.adj_in[target_id].append(edge)
        self.neighbors[source_id].add(target_id)
        self.neighbors[target_id].add(source_id)
        return edge

    def get_neighbors(self, node_id: str) -> List[str]:
        """Return all 1-hop adjacent node IDs (incoming and outgoing)."""
        return list(self.neighbors.get(node_id, set()))

    def get_k_hop_neighborhood(self, root_id: str, k: int = 2) -> Set[str]:
        """Extract all node IDs within k hops of the root entity node."""
        visited: Set[str] = {root_id}
        current_layer = {root_id}

        for _ in range(k):
            next_layer = set()
            for nid in current_layer:
                for nbr in self.neighbors.get(nid, set()):
                    if nbr not in visited:
                        visited.add(nbr)
                        next_layer.add(nbr)
            current_layer = next_layer
            if not current_layer:
                break

        return visited

    def extract_features(self, node_id: str) -> NodeFeatureVector:
        """Extract a normalized 24-dimensional continuous feature vector for a graph entity."""
        node = self.nodes.get(node_id)
        if not node:
            # Fallback zero vector for unseen node
            return NodeFeatureVector(
                node_id=node_id,
                node_type=GraphNodeType.HOST,
                features=[0.0] * FEATURE_DIM,
                feature_dimension=FEATURE_DIM,
                feature_names=[f"f_{i}" for i in range(FEATURE_DIM)],
            )

        features = [0.0] * FEATURE_DIM
        feature_names = [
            "is_host", "is_process", "is_user", "is_socket",
            "is_file", "is_registry", "is_dns", "is_alert",
            "norm_base_risk", "in_degree_norm", "out_degree_norm", "degree_ratio",
            "is_privileged", "is_external_conn", "is_suspicious_ext", "is_unsigned",
            "high_entropy_flag", "neighbor_type_entropy", "edge_weight_sum", "temporal_burst",
            "is_compromised_seed", "cmdline_length_norm", "port_risk_score", "alert_count_norm"
        ]

        # 1. One-hot encoding of node type (indices 0..7)
        type_mapping = {
            GraphNodeType.HOST: 0,
            GraphNodeType.PROCESS: 1,
            GraphNodeType.USER: 2,
            GraphNodeType.SOCKET: 3,
            GraphNodeType.FILE: 4,
            GraphNodeType.REGISTRY: 5,
            GraphNodeType.DNS_QUERY: 6,
            GraphNodeType.ALERT: 7,
        }
        type_idx = type_mapping.get(node.node_type, 0)
        features[type_idx] = 1.0

        # 2. Base risk score normalized (0..1) (index 8)
        features[8] = max(0.0, min(1.0, node.base_risk_score / 100.0))

        # 3. Graph degree metrics (indices 9..11)
        in_deg = len(self.adj_in.get(node_id, []))
        out_deg = len(self.adj_out.get(node_id, []))
        features[9] = math.tanh(in_deg / 10.0)
        features[10] = math.tanh(out_deg / 10.0)
        total_deg = in_deg + out_deg
        features[11] = (out_deg / (total_deg + 1e-6))

        # 4. Domain & security property indicators (indices 12..16)
        props = node.properties
        # Privilege / admin
        is_priv = bool(props.get("is_admin") or props.get("is_root") or props.get("privileged", False))
        features[12] = 1.0 if is_priv else 0.0

        # External IP / socket
        remote_ip = str(props.get("remote_ip", props.get("ip", "")))
        is_ext = False
        if remote_ip and not (remote_ip.startswith("10.") or remote_ip.startswith("192.168.") or remote_ip.startswith("172.16.") or remote_ip.startswith("127.")):
            is_ext = True
        features[13] = 1.0 if is_ext else 0.0

        # Suspicious extensions / scripts
        path_str = str(props.get("path", props.get("image", ""))).lower()
        suspicious_exts = [".ps1", ".bat", ".vbs", ".exe", ".sh", ".py", ".dll", ".so"]
        features[14] = 1.0 if any(path_str.endswith(ext) for ext in suspicious_exts) else 0.0

        # Unsigned binary
        is_unsigned = props.get("signed") is False or props.get("is_signed") is False
        features[15] = 1.0 if is_unsigned else 0.0

        # High entropy flag
        entropy = float(props.get("entropy", 0.0))
        features[16] = 1.0 if entropy > 7.0 else (entropy / 8.0)

        # 5. Neighbor type diversity / entropy (index 17)
        nbrs = self.get_neighbors(node_id)
        if nbrs:
            nbr_types = defaultdict(int)
            for nbr in nbrs:
                if nbr in self.nodes:
                    nbr_types[self.nodes[nbr].node_type] += 1
            total_nbr = len(nbrs)
            h = 0.0
            for cnt in nbr_types.values():
                p = cnt / total_nbr
                if p > 0:
                    h -= p * math.log2(p)
            features[17] = min(1.0, h / 3.0)
        else:
            features[17] = 0.0

        # 6. Edge weight accumulation (index 18)
        w_sum = sum(e.weight for e in self.adj_out.get(node_id, [])) + sum(e.weight for e in self.adj_in.get(node_id, []))
        features[18] = math.tanh(w_sum / 20.0)

        # 7. Temporal burst (index 19)
        burst = float(props.get("connection_rate", props.get("event_count", len(nbrs))))
        features[19] = math.tanh(burst / 50.0)

        # 8. Seed compromised indicator (index 20)
        features[20] = 1.0 if node.is_compromised_seed else 0.0

        # 9. Command line length normalized (index 21)
        cmdline = str(props.get("cmdline", props.get("command", "")))
        features[21] = min(1.0, len(cmdline) / 500.0)

        # 10. Port risk score (index 22)
        port = int(props.get("port", props.get("remote_port", 0)))
        high_risk_ports = {22, 23, 445, 135, 3389, 4444, 5985, 5986, 8080, 8443, 6667}
        features[22] = 1.0 if port in high_risk_ports else (0.5 if port > 1024 else 0.2 if port > 0 else 0.0)

        # 11. Alert count normalized (index 23)
        alert_cnt = sum(1 for e in self.adj_in.get(node_id, []) if e.edge_type == GraphEdgeType.TRIGGERED_ALERT)
        features[23] = min(1.0, alert_cnt / 5.0)

        return NodeFeatureVector(
            node_id=node_id,
            node_type=node.node_type,
            features=features,
            feature_dimension=FEATURE_DIM,
            feature_names=feature_names,
        )

    def to_heterogeneous_graph(self) -> HeterogeneousGraph:
        """Export internal graph state to Pydantic HeterogeneousGraph schema."""
        return HeterogeneousGraph(
            graph_id=self.graph_id,
            tenant_id=self.tenant_id,
            nodes=self.nodes,
            edges=self.edges,
            metadata={
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
            },
        )

    @classmethod
    def from_heterogeneous_graph(cls, hg: HeterogeneousGraph) -> "SecurityGraphBuilder":
        """Instantiate builder from a HeterogeneousGraph schema object."""
        builder = cls(graph_id=hg.graph_id, tenant_id=hg.tenant_id)
        builder.nodes = dict(hg.nodes)
        for edge in hg.edges:
            builder.add_edge(
                source_id=edge.source_id,
                target_id=edge.target_id,
                edge_type=edge.edge_type,
                weight=edge.weight,
                properties=edge.properties,
            )
        return builder
