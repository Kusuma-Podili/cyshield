"""CyberShield Enterprise - Inductive GraphSAGE Neural Layer.
Implements neighborhood aggregation (Mean, Max-Pooling, Attention) and multi-hop
representation learning for inductive node embedding on heterogeneous security graphs.
"""

import math
import random
from typing import Dict, List, Set, Optional, Tuple

from .schemas import AggregatorType, NodeEmbeddingResult, GraphNodeType
from .graph import SecurityGraphBuilder, FEATURE_DIM


def relu(x: float) -> float:
    return max(0.0, x)


def leaky_relu(x: float, alpha: float = 0.01) -> float:
    return x if x > 0 else alpha * x


def l2_normalize(vec: List[float]) -> Tuple[List[float], float]:
    norm = math.sqrt(sum(v * v for v in vec))
    if norm < 1e-12:
        return [0.0] * len(vec), 0.0
    return [v / norm for v in vec], norm


def matmul_vec(matrix: List[List[float]], vec: List[float]) -> List[float]:
    """Matrix-vector multiplication: M (rows x cols) * v (cols) -> res (rows)."""
    rows = len(matrix)
    cols = len(matrix[0]) if rows > 0 else 0
    res = [0.0] * rows
    for i in range(rows):
        s = 0.0
        row_i = matrix[i]
        for j in range(cols):
            s += row_i[j] * vec[j]
        res[i] = s
    return res


class GraphSAGELayer:
    """A single GraphSAGE aggregation and transformation layer."""

    def __init__(
        self,
        in_dim: int,
        out_dim: int,
        aggregator: AggregatorType = AggregatorType.MEAN,
        seed: int = 42,
    ):
        self.in_dim = in_dim
        self.out_dim = out_dim
        self.aggregator = aggregator
        self.rng = random.Random(seed)

        # Initialize weights using Xavier/Glorot uniform initialization
        scale_self = math.sqrt(6.0 / (in_dim + out_dim))
        self.W_self: List[List[float]] = [
            [self.rng.uniform(-scale_self, scale_self) for _ in range(in_dim)]
            for _ in range(out_dim)
        ]

        scale_neigh = math.sqrt(6.0 / (in_dim + out_dim))
        self.W_neigh: List[List[float]] = [
            [self.rng.uniform(-scale_neigh, scale_neigh) for _ in range(in_dim)]
            for _ in range(out_dim)
        ]

        self.bias: List[float] = [0.0] * out_dim

        # Pooling projection weights if POOLING aggregator is chosen
        if self.aggregator == AggregatorType.POOLING:
            scale_pool = math.sqrt(6.0 / (in_dim + in_dim))
            self.W_pool: List[List[float]] = [
                [self.rng.uniform(-scale_pool, scale_pool) for _ in range(in_dim)]
                for _ in range(in_dim)
            ]
            self.b_pool: List[float] = [0.0] * in_dim

    def aggregate_neighbors(
        self,
        target_id: str,
        neighbor_vectors: List[List[float]],
        edge_weights: Optional[List[float]] = None,
    ) -> List[float]:
        """Aggregate neighbor feature representations."""
        if not neighbor_vectors:
            return [0.0] * self.in_dim

        num_nbrs = len(neighbor_vectors)

        if self.aggregator == AggregatorType.MEAN:
            # Weighted or unweighted mean
            weights = edge_weights if edge_weights and len(edge_weights) == num_nbrs else [1.0] * num_nbrs
            total_weight = sum(weights) + 1e-9
            agg = [0.0] * self.in_dim
            for vec, w in zip(neighbor_vectors, weights):
                for d in range(self.in_dim):
                    agg[d] += vec[d] * w
            return [val / total_weight for val in agg]

        elif self.aggregator == AggregatorType.POOLING:
            # Element-wise max pooling over transformed neighbor vectors: max_i(relu(W_pool * h_i + b_pool))
            transformed_pool: List[List[float]] = []
            for vec in neighbor_vectors:
                proj = matmul_vec(self.W_pool, vec)
                activated = [relu(proj[d] + self.b_pool[d]) for d in range(self.in_dim)]
                transformed_pool.append(activated)

            agg = [-float("inf")] * self.in_dim
            for vec in transformed_pool:
                for d in range(self.in_dim):
                    if vec[d] > agg[d]:
                        agg[d] = vec[d]
            return [0.0 if x == -float("inf") else x for x in agg]

        elif self.aggregator == AggregatorType.ATTENTION:
            # Simplified cosine/dot-product attention
            weights = edge_weights if edge_weights and len(edge_weights) == num_nbrs else [1.0] * num_nbrs
            exp_scores = [math.exp(min(5.0, max(-5.0, w))) for w in weights]
            total_exp = sum(exp_scores) + 1e-9
            softmax_weights = [s / total_exp for s in exp_scores]

            agg = [0.0] * self.in_dim
            for vec, alpha in zip(neighbor_vectors, softmax_weights):
                for d in range(self.in_dim):
                    agg[d] += vec[d] * alpha
            return agg

        return [0.0] * self.in_dim

    def forward_node(
        self,
        self_vector: List[float],
        neighbor_vectors: List[List[float]],
        edge_weights: Optional[List[float]] = None,
    ) -> List[float]:
        """Computes: h_v' = LeakyReLU(W_self * h_v + W_neigh * AGG({h_u}) + bias)."""
        neigh_agg = self.aggregate_neighbors("target", neighbor_vectors, edge_weights)

        h_self_proj = matmul_vec(self.W_self, self_vector)
        h_neigh_proj = matmul_vec(self.W_neigh, neigh_agg)

        out = [0.0] * self.out_dim
        for d in range(self.out_dim):
            val = h_self_proj[d] + h_neigh_proj[d] + self.bias[d]
            out[d] = leaky_relu(val)

        normalized, _ = l2_normalize(out)
        return normalized


class InductiveGraphEmbeddingModel:
    """Hierarchical GraphSAGE model supporting 2-hop inductive feature embedding on enterprise graphs."""

    def __init__(
        self,
        in_dim: int = FEATURE_DIM,
        hidden_dim: int = 32,
        out_dim: int = 16,
        aggregator: AggregatorType = AggregatorType.MEAN,
        seed: int = 1337,
    ):
        self.in_dim = in_dim
        self.hidden_dim = hidden_dim
        self.out_dim = out_dim
        self.aggregator = aggregator

        self.layer1 = GraphSAGELayer(in_dim, hidden_dim, aggregator=aggregator, seed=seed)
        self.layer2 = GraphSAGELayer(hidden_dim, out_dim, aggregator=aggregator, seed=seed + 1)

    def embed_node(self, node_id: str, graph: SecurityGraphBuilder) -> NodeEmbeddingResult:
        """Inductively compute the 2-hop GraphSAGE embedding for any target entity node."""
        node = graph.nodes.get(node_id)
        node_type = node.node_type if node else GraphNodeType.HOST

        # 1. Collect 1-hop neighbors and 2-hop neighbors
        hop1_ids = graph.get_neighbors(node_id)
        all_nodes_needed: Set[str] = {node_id} | set(hop1_ids)
        for h1 in hop1_ids:
            for h2 in graph.get_neighbors(h1):
                all_nodes_needed.add(h2)

        # 2. Extract raw features for all required nodes (Hop 0)
        h0_vectors: Dict[str, List[float]] = {}
        for nid in all_nodes_needed:
            h0_vectors[nid] = graph.extract_features(nid).features

        # 3. Layer 1 forward pass: Compute h1 for target node and all its 1-hop neighbors
        h1_vectors: Dict[str, List[float]] = {}
        nodes_for_l1 = {node_id} | set(hop1_ids)

        for nid in nodes_for_l1:
            nbrs_of_nid = graph.get_neighbors(nid)
            nbr_vecs = [h0_vectors[nbr] for nbr in nbrs_of_nid if nbr in h0_vectors]
            # Edge weights
            weights = []
            for nbr in nbrs_of_nid:
                edge_match = [e.weight for e in graph.adj_out.get(nid, []) if e.target_id == nbr]
                if not edge_match:
                    edge_match = [e.weight for e in graph.adj_in.get(nid, []) if e.source_id == nbr]
                weights.append(edge_match[0] if edge_match else 1.0)

            h1_vectors[nid] = self.layer1.forward_node(h0_vectors[nid], nbr_vecs, weights)

        # 4. Layer 2 forward pass: Compute final h2 embedding for the target node
        hop1_nbr_vecs = [h1_vectors[nbr] for nbr in hop1_ids if nbr in h1_vectors]
        target_weights = []
        for nbr in hop1_ids:
            edge_match = [e.weight for e in graph.adj_out.get(node_id, []) if e.target_id == nbr]
            if not edge_match:
                edge_match = [e.weight for e in graph.adj_in.get(node_id, []) if e.source_id == nbr]
            target_weights.append(edge_match[0] if edge_match else 1.0)

        final_vec = self.layer2.forward_node(h1_vectors[node_id], hop1_nbr_vecs, target_weights)
        norm_vec, l2 = l2_normalize(final_vec)

        return NodeEmbeddingResult(
            node_id=node_id,
            node_type=node_type,
            embedding=norm_vec,
            embedding_dimension=len(norm_vec),
            l2_norm=round(l2, 4),
            neighborhood_size=len(hop1_ids),
            k_hops=2,
        )

    def compute_similarity(self, emb1: List[float], emb2: List[float]) -> float:
        """Compute cosine similarity between two node embedding vectors."""
        if len(emb1) != len(emb2) or not emb1:
            return 0.0
        dot = sum(a * b for a, b in zip(emb1, emb2))
        norm1 = math.sqrt(sum(a * a for a in emb1))
        norm2 = math.sqrt(sum(b * b for b in emb2))
        if norm1 < 1e-9 or norm2 < 1e-9:
            return 0.0
        return max(-1.0, min(1.0, dot / (norm1 * norm2)))
