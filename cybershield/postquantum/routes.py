"""
Post-Quantum Cryptography & Quantum Readiness REST API routes.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.postquantum.engine import PostQuantumEngine
from cybershield.postquantum.schemas import (
    CryptoAsset,
    HybridKEMExchange,
    MoscaTheoremEvaluation,
    MoscaTheoremRequest,
    PQAlgorithmType,
)

postquantum_router = APIRouter(prefix="/api/postquantum", tags=["Post-Quantum Cryptography & Quantum Readiness"])
_pq_engine = PostQuantumEngine()


@postquantum_router.get("/assets", response_model=List[CryptoAsset])
async def list_cryptographic_assets():
    """List monitored cryptographic keys, TLS ciphers, and certificates with Shor/Grover risk tiers."""
    return _pq_engine.list_assets()


@postquantum_router.post("/assets", response_model=CryptoAsset, status_code=status.HTTP_201_CREATED)
async def register_cryptographic_asset(asset: CryptoAsset):
    """Register a new enterprise cryptographic asset into the PQC audit inventory."""
    return _pq_engine.add_asset(asset)


@postquantum_router.post("/evaluate-algorithm")
async def evaluate_algorithm(algorithm: PQAlgorithmType = Query(...)):
    """Evaluate an algorithm against Shor's and Grover's quantum threat exposure."""
    risk, replacement = _pq_engine.evaluate_algorithm(algorithm)
    return {
        "algorithm": algorithm.value,
        "quantum_risk": risk.value,
        "recommended_replacement": replacement,
    }


@postquantum_router.post("/hybrid-kem", response_model=HybridKEMExchange)
async def perform_hybrid_kem_exchange():
    """Execute a simulated dual-layer Hybrid Key Encapsulation (X25519 + ML-KEM-768) handshake."""
    return _pq_engine.perform_hybrid_kem_exchange()


@postquantum_router.post("/mosca-theorem", response_model=MoscaTheoremEvaluation)
async def evaluate_mosca_theorem(req: MoscaTheoremRequest):
    """
    Evaluate Mosca's Theorem (X + Y > Z) for Harvest-Now-Decrypt-Later (HNDL) exposure
    and compute enterprise Quantum Readiness Score.
    """
    return _pq_engine.evaluate_mosca_theorem(req)


@postquantum_router.get("/overview")
async def get_postquantum_overview():
    """High-level metrics on quantum-safe assets, Shor-critical exposures, and migration progress."""
    return _pq_engine.get_overview_metrics()
