"""
CyberShield Enterprise - Machine Learning & UEBA REST API Routes
Exposes high-performance endpoints for model registry, automated training,
Isolation Forest anomaly detection, payload classification, and UEBA profiling.
"""

from __future__ import annotations

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.session import get_db
from cybershield.database.models.user import User
from cybershield.database.models.role import Permission
from cybershield.auth import require_permission
from cybershield.audit.service import AuditService
from cybershield.ml.schemas import (
    MLModelResponse,
    ModelTrainRequest,
    ModelTrainResponse,
    AnomalyPredictRequest,
    AnomalyPredictResponse,
    PayloadClassifyRequest,
    PayloadClassifyResponse,
    UEBAEvaluateRequest,
    UEBAEvaluateResponse,
    DatasetGenerateRequest,
    DatasetInfoResponse,
    MLKPIMetricsResponse,
)
from cybershield.ml.registry.service import ml_service
from cybershield.ml.datasets.manager import dataset_manager
from cybershield.ml.engines.risk_predictor import RiskPredictorEngine

router = APIRouter(prefix="/api/ml", tags=["Machine Learning & UEBA"])


@router.get("/models", response_model=List[MLModelResponse], summary="List Registered ML Models")
async def list_models(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ML_VIEW)),
):
    """Retrieve all active and candidate machine learning models with accuracy metrics."""
    return await ml_service.list_models(session=db)


@router.post("/train", response_model=ModelTrainResponse, summary="Trigger Model Training Workflow")
async def train_model(
    req: ModelTrainRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ML_TRAIN)),
):
    """Execute model training or retraining on specified dataset and promote artifact."""
    try:
        result = await ml_service.train_model(
            session=db,
            task_type=req.task_type,
            algorithm=req.algorithm,
            dataset_name=req.dataset_name,
            hyperparameters=req.hyperparameters,
        )

        await AuditService.log_event(
            db=db,
            action="ML_MODEL_TRAINED",
            resource=f"model:{result['model_id']}",
            username=current_user.username,
            user_id=current_user.id,
            details={"task_type": req.task_type, "version": result["version"], "duration": result["training_duration_sec"]},
            status="SUCCESS",
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/predict/anomaly", response_model=AnomalyPredictResponse, summary="Isolation Forest Anomaly Scoring")
async def predict_anomaly(
    req: AnomalyPredictRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ML_VIEW)),
):
    """Evaluate network flow features and return unsupervised anomaly score and classification."""
    features = req.model_dump()
    return await ml_service.predict_anomaly(session=db, features=features)


@router.post("/predict/payload", response_model=PayloadClassifyResponse, summary="Web Attack Payload Classification")
async def classify_payload(
    req: PayloadClassifyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ML_VIEW)),
):
    """Classify input payload into SQLi, XSS, Cmd Injection, Path Traversal, or Benign."""
    return await ml_service.classify_payload(session=db, payload=req.payload)


@router.post("/predict/ueba", response_model=UEBAEvaluateResponse, summary="Evaluate User Behavioral Baseline")
async def evaluate_ueba(
    req: UEBAEvaluateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ML_VIEW)),
):
    """Assess user event against statistical baseline, evaluating Z-score volume and travel velocity."""
    return await ml_service.evaluate_ueba(
        session=db,
        username=req.username,
        bytes_transferred=req.bytes_transferred,
        event_hour=req.event_hour,
        login_lat=req.login_latitude,
        login_lon=req.login_longitude,
        city=req.city,
        country=req.country,
        accessed_resource=req.accessed_resource,
    )


@router.get("/ueba/profiles", summary="List User Behavioral Baselines")
async def list_ueba_profiles(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ML_VIEW)),
):
    """Retrieve all profiled user behavioral baselines and active risk ratings."""
    return await ml_service.list_ueba_profiles(session=db)


@router.get("/datasets", response_model=List[DatasetInfoResponse], summary="List ML Training Datasets")
async def list_datasets(
    current_user: User = Depends(require_permission(Permission.ML_VIEW)),
):
    """List available local training datasets, sample counts, and class distributions."""
    return dataset_manager.list_datasets()


@router.post("/datasets/generate", response_model=DatasetInfoResponse, summary="Generate Synthetic Dataset")
async def generate_dataset(
    req: DatasetGenerateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ML_TRAIN)),
):
    """Generate a reproducible synthetic cybersecurity dataset."""
    try:
        ds_name = f"{req.dataset_type.lower()}_synth_{int(time.time()) % 10000}"
        result = dataset_manager.create_dataset(
            name=ds_name,
            dataset_type=req.dataset_type,
            n_samples=req.sample_count,
        )

        await AuditService.log_event(
            db=db,
            action="DATASET_GENERATED",
            resource=f"dataset:{ds_name}",
            username=current_user.username,
            user_id=current_user.id,
            details={"type": req.dataset_type, "samples": req.sample_count},
            status="SUCCESS",
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/risk/predict", summary="Bayesian Entity Risk Prediction")
async def predict_risk(
    req: Dict[str, Any],
    current_user: User = Depends(require_permission(Permission.ML_VIEW)),
):
    """Compute continuous Bayesian composite risk score for an asset or entity."""
    return RiskPredictorEngine.calculate_entity_risk(
        max_cvss_score=float(req.get("max_cvss_score", 0.0)),
        active_alert_count=int(req.get("active_alert_count", 0)),
        open_ports=req.get("open_ports", []),
        is_critical_asset=bool(req.get("is_critical_asset", False)),
        active_exploit_observed=bool(req.get("active_exploit_observed", False)),
        ueba_anomaly_score=float(req.get("ueba_anomaly_score", 0.0)),
    )


@router.get("/kpis", response_model=MLKPIMetricsResponse, summary="ML Operations KPIs")
async def get_ml_kpis(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ML_VIEW)),
):
    """Retrieve telemetry metrics on active models, inferences served, latency, and drift."""
    return await ml_service.get_kpi_metrics(session=db)
