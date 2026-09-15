"""
CyberShield Enterprise - Machine Learning & UEBA Pydantic Schemas
Defines request and response schemas for model serving, anomaly detection,
payload classification, UEBA evaluations, and dataset operations.
"""

from __future__ import annotations

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class MLModelResponse(BaseModel):
    id: str
    name: str
    version: str
    algorithm: str
    task_type: str
    status: str
    metrics: Dict[str, Any] = Field(default_factory=dict)
    hyperparameters: Dict[str, Any] = Field(default_factory=dict)
    artifact_path: Optional[str] = None
    dataset_name: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    trained_at: Optional[str] = None


class ModelTrainRequest(BaseModel):
    task_type: str = Field(..., description="ANOMALY_DETECTION, PAYLOAD_CLASSIFICATION, RISK_PREDICTION")
    algorithm: Optional[str] = Field(None, description="ISOLATION_FOREST, TFIDF_NAIVE_BAYES, RANDOM_FOREST")
    dataset_name: Optional[str] = Field(None, description="Source dataset to train on")
    hyperparameters: Optional[Dict[str, Any]] = Field(default_factory=dict)


class ModelTrainResponse(BaseModel):
    model_id: str
    name: str
    version: str
    task_type: str
    algorithm: str
    status: str
    metrics: Dict[str, Any]
    training_duration_sec: float
    message: str


class AnomalyPredictRequest(BaseModel):
    packet_count: float = Field(..., ge=0.0, description="Observed network flow packet count")
    byte_count: float = Field(..., ge=0.0, description="Total flow bytes transferred")
    duration_sec: float = Field(1.0, ge=0.0, description="Flow duration in seconds")
    dst_port: int = Field(80, ge=1, le=65535, description="Target destination port")
    protocol: str = Field("TCP", description="TCP, UDP, ICMP")
    bytes_out_ratio: float = Field(0.5, ge=0.0, le=1.0, description="Ratio of outbound bytes to total bytes")
    is_off_hours: bool = Field(False, description="Whether event occurred outside standard business hours")


class AnomalyPredictResponse(BaseModel):
    is_anomaly: bool
    anomaly_score: float = Field(..., description="Raw decision score (-1.0 to 1.0, negative indicates outlier)")
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Normalized risk rating (0 - 100)")
    confidence: float = Field(..., ge=0.0, le=1.0)
    classification: str = Field("NORMAL", description="NORMAL, SUSPICIOUS, HIGH_ANOMALY")
    explanation: str
    latency_ms: float


class PayloadClassifyRequest(BaseModel):
    payload: str = Field(..., min_length=1, description="Raw HTTP parameter, URI, header, or command string")


class PayloadClassifyResponse(BaseModel):
    payload: str
    predicted_class: str = Field(
        ...,
        description="BENIGN, SQL_INJECTION, CROSS_SITE_SCRIPTING, COMMAND_INJECTION, PATH_TRAVERSAL"
    )
    confidence: float = Field(..., ge=0.0, le=1.0)
    probabilities: Dict[str, float]
    matched_indicators: List[str] = Field(default_factory=list)
    risk_level: str
    latency_ms: float


class UEBAEvaluateRequest(BaseModel):
    username: str = Field(..., description="User account identifier")
    bytes_transferred: Optional[float] = Field(None, ge=0.0)
    event_hour: Optional[int] = Field(None, ge=0, le=23)
    login_latitude: Optional[float] = Field(None, ge=-90.0, le=90.0)
    login_longitude: Optional[float] = Field(None, ge=-180.0, le=180.0)
    country: Optional[str] = Field(None)
    city: Optional[str] = Field(None)
    accessed_resource: Optional[str] = Field(None)


class UEBAEvaluateResponse(BaseModel):
    username: str
    risk_score: float = Field(..., ge=0.0, le=100.0)
    is_anomalous: bool
    impossible_travel_detected: bool
    distance_km: Optional[float] = None
    velocity_kmh: Optional[float] = None
    off_hours_login: bool = False
    z_score_bytes: float = 0.0
    anomalous_factors: List[str] = Field(default_factory=list)
    peer_group: str = "STANDARD_EMPLOYEE"
    latency_ms: float


class DatasetGenerateRequest(BaseModel):
    dataset_type: str = Field("NETFLOW", description="NETFLOW, PAYLOADS, UEBA")
    sample_count: int = Field(1000, ge=50, le=50000)


class DatasetInfoResponse(BaseModel):
    name: str
    dataset_type: str
    samples_count: int
    features_count: int
    labels_distribution: Dict[str, int]
    created_at: str


class MLKPIMetricsResponse(BaseModel):
    total_registered_models: int
    active_models: int
    inferences_served: int
    avg_inference_latency_ms: float
    anomalies_detected: int
    anomaly_rate_percent: float
    drift_alerts_count: int
