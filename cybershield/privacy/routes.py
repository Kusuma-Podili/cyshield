"""CyberShield Enterprise - Privacy-Preserving Differential Privacy & Federated Telemetry Routes.
Exposes endpoints for mathematical noise injection, k-anonymity/l-diversity sanitization,
secure federated weight aggregation, and privacy budget accounting.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    DifferentialPrivacyRequest,
    DifferentialPrivacyResponse,
    KAnonymityBatchRequest,
    KAnonymityBatchResponse,
    FederatedAggregationRequest,
    FederatedAggregationResponse,
    PrivacyBudgetStatus,
)
from .engine import PrivacyPreservingEngine

router = APIRouter(prefix="/api/v1/privacy", tags=["Privacy-Preserving Threat Telemetry"])

# Singleton engine instance
_PRIVACY_ENGINE = PrivacyPreservingEngine()


@router.post("/differential", response_model=DifferentialPrivacyResponse, status_code=status.HTTP_200_OK)
def inject_differential_privacy_noise(request: DifferentialPrivacyRequest):
    """Perturb aggregate threat counter with calibrated Laplace or Gaussian noise."""
    return _PRIVACY_ENGINE.apply_differential_privacy(request)


@router.post("/anonymize", response_model=KAnonymityBatchResponse, status_code=status.HTTP_200_OK)
def anonymize_incident_telemetry(batch: KAnonymityBatchRequest):
    """Enforce k-anonymity and l-diversity on raw incident telemetry before cross-org sharing."""
    return _PRIVACY_ENGINE.apply_k_anonymity(batch)


@router.post("/federated/aggregate", response_model=FederatedAggregationResponse, status_code=status.HTTP_200_OK)
def federated_model_aggregation(request: FederatedAggregationRequest):
    """Perform secure multi-party aggregation of local anomaly model weights."""
    return _PRIVACY_ENGINE.secure_federated_aggregation(request)


@router.get("/budget", response_model=PrivacyBudgetStatus)
def get_privacy_budget_status():
    """Query remaining global differential privacy budget (epsilon)."""
    return _PRIVACY_ENGINE.get_budget_status()
