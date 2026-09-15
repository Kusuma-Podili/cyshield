"""
Quantum-Resistant Cryptography & Post-Quantum TLS 1.3 Readiness Schemas.
Models NIST PQC standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA),
hybrid key exchange, and Mosca's Theorem evaluation.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PQAlgorithmType(str, Enum):
    # NIST Standardized Post-Quantum Algorithms
    ML_KEM_512 = "ML_KEM_512"  # Kyber-512 (NIST Level 1)
    ML_KEM_768 = "ML_KEM_768"  # Kyber-768 (NIST Level 3)
    ML_KEM_1024 = "ML_KEM_1024"  # Kyber-1024 (NIST Level 5)
    ML_DSA_44 = "ML_DSA_44"  # Dilithium2
    ML_DSA_65 = "ML_DSA_65"  # Dilithium3
    ML_DSA_87 = "ML_DSA_87"  # Dilithium5
    SLH_DSA_128 = "SLH_DSA_128"  # SPHINCS+
    HYBRID_X25519_ML_KEM_768 = "HYBRID_X25519_ML_KEM_768"

    # Classical Algorithms (Vulnerable to Shor / Grover)
    RSA_2048 = "RSA_2048"
    RSA_4096 = "RSA_4096"
    ECDSA_P256 = "ECDSA_P256"
    ECDSA_P384 = "ECDSA_P384"
    X25519 = "X25519"
    AES_128_GCM = "AES_128_GCM"
    AES_256_GCM = "AES_256_GCM"


class QuantumRiskTier(str, Enum):
    QUANTUM_SAFE = "QUANTUM_SAFE"  # Immune to Shor and Grover attacks
    GROVER_VULNERABLE = "GROVER_VULNERABLE"  # Symmetric key effectively halved (e.g. 128 -> 64 bits)
    SHOR_CRITICAL = "SHOR_CRITICAL"  # Completely broken in polynomial time by Shor's algorithm
    MIGRATING_HYBRID = "MIGRATING_HYBRID"  # Protected by dual classical + post-quantum layer


class CryptoAsset(BaseModel):
    """Monitored cryptographic deployment within the enterprise perimeter."""
    asset_id: str
    name: str
    target_service: str  # e.g., "HTTPS Reverse Proxy", "WireGuard VPN", "SSH Gateway"
    current_algorithm: PQAlgorithmType
    key_size_bits: int
    quantum_risk: QuantumRiskTier
    recommended_pqc_replacement: str
    last_audited: datetime = Field(default_factory=datetime.utcnow)


class HybridKEMExchange(BaseModel):
    """Simulated X25519 + ML-KEM-768 Hybrid Key Encapsulation Mechanism session."""
    session_id: str
    classical_public_key_hex: str
    pqc_public_key_hex: str
    combined_shared_secret_sha256: str
    quantum_safety_confirmed: bool = True
    established_at: datetime = Field(default_factory=datetime.utcnow)


class MoscaTheoremRequest(BaseModel):
    """Parameters to evaluate Mosca's Theorem for Harvest Now Decrypt Later (HNDL) exposure."""
    data_shelf_life_years: float = 15.0  # X: how long data must remain confidential
    migration_time_years: float = 4.0   # Y: time required to migrate infrastructure
    estimated_qday_years: float = 10.0   # Z: estimated years until Cryptanalytically Relevant Quantum Computer


class MoscaTheoremEvaluation(BaseModel):
    """Outcome of Mosca's Theorem (X + Y > Z) risk evaluation."""
    data_shelf_life_years: float
    migration_time_years: float
    estimated_qday_years: float
    total_exposure_window_years: float  # X + Y
    is_vulnerable_to_hndl: bool  # True if X + Y > Z
    quantum_readiness_score: float  # 0 to 100
    risk_summary: str
    recommended_action: str
