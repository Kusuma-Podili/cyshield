"""
CyberShield Enterprise - Machine Learning Registry & Lifecycle Orchestration Service
Manages local model training, versioning, checkpoint storage, real-time inference routing,
telemetry tracking, and UEBA behavioral baselines.
"""

from __future__ import annotations

import os
import time
import uuid
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_

from cybershield.database.models.ml import (
    MLModelRecord,
    MLInferenceLogModel,
    UserBehaviorBaselineModel,
    MLTaskType,
    MLModelStatus,
)
from cybershield.ml.datasets.manager import dataset_manager
from cybershield.ml.engines.isolation_forest import IsolationForestEngine
from cybershield.ml.engines.payload_classifier import PayloadClassifierEngine
from cybershield.ml.engines.risk_predictor import RiskPredictorEngine
from cybershield.ml.ueba.profiler import behavioral_profiler

logger = logging.getLogger("cybershield.ml.registry.service")


class MLRegistryService:
    """Enterprise Machine Learning Registry & Lifecycle Management Service."""

    MODEL_DIR = "data/models"

    def __init__(self):
        os.makedirs(self.MODEL_DIR, exist_ok=True)
        self.isolation_forest = IsolationForestEngine()
        self.payload_classifier = PayloadClassifierEngine()
        self.risk_predictor = RiskPredictorEngine()
        self.ueba_profiler = behavioral_profiler

        # In-memory telemetry counters
        self.inferences_served = 0
        self.anomalies_detected = 0
        self.total_latency_ms = 0.0
        self.drift_alerts_count = 0

    async def seed_default_models(self, session: AsyncSession) -> int:
        """
        Initialize and register default pre-trained baseline models into the database.
        Runs once on application startup or during test setup.
        """
        existing_count = (await session.execute(select(func.count(MLModelRecord.id)))).scalar_one()
        if existing_count > 0:
            # Ensure in-memory models are trained
            if not self.isolation_forest.is_trained:
                netflow_data = dataset_manager.get_dataset_data("netflow_traffic_v1")
                if netflow_data:
                    self.isolation_forest.fit(netflow_data)
            if not self.payload_classifier.is_trained:
                payload_data = dataset_manager.get_dataset_data("web_payloads_v1")
                if payload_data:
                    self.payload_classifier.fit(payload_data)
            await self.ueba_profiler.seed_default_baselines(session)
            return existing_count

        # 1. Train & Register Isolation Forest Model
        netflow_data = dataset_manager.get_dataset_data("netflow_traffic_v1")
        if_metrics = self.isolation_forest.fit(netflow_data)
        if_artifact = os.path.join(self.MODEL_DIR, "iforest_netflow_v1.pkl")
        self.isolation_forest.save(if_artifact)

        if_model_rec = MLModelRecord(
            id="ML-IFOREST-NETFLOW-v1",
            name="Network Flow Anomaly Detector",
            version="1.0.0",
            algorithm="ISOLATION_FOREST",
            task_type=MLTaskType.ANOMALY_DETECTION.value,
            status=MLModelStatus.ACTIVE.value,
            metrics=if_metrics,
            hyperparameters={"contamination": 0.1, "n_estimators": 100},
            artifact_path=if_artifact,
            dataset_name="netflow_traffic_v1",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            trained_at=datetime.utcnow(),
        )
        session.add(if_model_rec)

        # 2. Train & Register Payload Classifier Model
        payload_data = dataset_manager.get_dataset_data("web_payloads_v1")
        clf_metrics = self.payload_classifier.fit(payload_data)
        clf_artifact = os.path.join(self.MODEL_DIR, "payload_classifier_v1.pkl")
        self.payload_classifier.save(clf_artifact)

        clf_model_rec = MLModelRecord(
            id="ML-TFIDF-PAYLOAD-v1",
            name="Web Attack Payload Classifier",
            version="1.0.0",
            algorithm="TFIDF_MULTINOMIAL_NB",
            task_type=MLTaskType.PAYLOAD_CLASSIFICATION.value,
            status=MLModelStatus.ACTIVE.value,
            metrics={
                "accuracy": clf_metrics["accuracy"],
                "weighted_f1": clf_metrics["weighted_f1"],
                "confusion_matrix": clf_metrics["confusion_matrix"],
                "samples_trained": clf_metrics["samples_total"],
            },
            hyperparameters={"max_features": 5000, "alpha": 0.1, "ngram_range": [2, 5]},
            artifact_path=clf_artifact,
            dataset_name="web_payloads_v1",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            trained_at=datetime.utcnow(),
        )
        session.add(clf_model_rec)

        # 3. Register Risk Predictor Model
        risk_model_rec = MLModelRecord(
            id="ML-BAYESIAN-RISK-v1",
            name="Bayesian Entity Risk Predictor",
            version="1.0.0",
            algorithm="BAYESIAN_FACTOR_ANALYSIS",
            task_type=MLTaskType.RISK_PREDICTION.value,
            status=MLModelStatus.ACTIVE.value,
            metrics={"factors_evaluated": 6, "scoring_range": [0.0, 100.0]},
            hyperparameters={"criticality_multiplier": 1.3},
            artifact_path=None,
            dataset_name="enterprise_security_posture",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            trained_at=datetime.utcnow(),
        )
        session.add(risk_model_rec)

        await session.commit()

        # 4. Seed UEBA baselines
        await self.ueba_profiler.seed_default_baselines(session)
        logger.info("Default enterprise ML models and UEBA baselines initialized.")
        return 3

    async def list_models(self, session: AsyncSession) -> List[Dict[str, Any]]:
        """Query all registered machine learning models."""
        stmt = select(MLModelRecord).order_by(MLModelRecord.created_at.desc())
        records = (await session.execute(stmt)).scalars().all()
        return [r.to_dict() for r in records]

    async def train_model(
        self,
        session: AsyncSession,
        task_type: str,
        algorithm: Optional[str] = None,
        dataset_name: Optional[str] = None,
        hyperparameters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Execute model training or retraining workflow and register new model version.
        """
        start_time = time.perf_counter()
        task_t = task_type.upper()
        hparams = hyperparameters or {}

        if task_t == MLTaskType.ANOMALY_DETECTION.value:
            ds_name = dataset_name or "netflow_traffic_v1"
            dataset = dataset_manager.get_dataset_data(ds_name)
            if not dataset:
                dataset = dataset_manager.create_dataset(ds_name, "NETFLOW", 1200)["data"]

            contamination = float(hparams.get("contamination", 0.1))
            n_estimators = int(hparams.get("n_estimators", 100))

            engine = IsolationForestEngine(contamination=contamination, n_estimators=n_estimators)
            metrics = engine.fit(dataset)

            version_str = f"1.{int(time.time()) % 1000}.0"
            model_id = f"ML-IFOREST-{int(time.time())}"
            artifact_path = os.path.join(self.MODEL_DIR, f"{model_id}.pkl")
            engine.save(artifact_path)

            # Update active serving model
            self.isolation_forest = engine

            rec = MLModelRecord(
                id=model_id,
                name="Network Flow Anomaly Detector",
                version=version_str,
                algorithm="ISOLATION_FOREST",
                task_type=task_t,
                status=MLModelStatus.ACTIVE.value,
                metrics=metrics,
                hyperparameters={"contamination": contamination, "n_estimators": n_estimators},
                artifact_path=artifact_path,
                dataset_name=ds_name,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                trained_at=datetime.utcnow(),
            )
            session.add(rec)
            await session.commit()

            duration = round(time.perf_counter() - start_time, 3)
            return {
                "model_id": model_id,
                "name": rec.name,
                "version": version_str,
                "task_type": task_t,
                "algorithm": "ISOLATION_FOREST",
                "status": "ACTIVE",
                "metrics": metrics,
                "training_duration_sec": duration,
                "message": "Isolation Forest model successfully trained and promoted to active serving.",
            }

        elif task_t == MLTaskType.PAYLOAD_CLASSIFICATION.value:
            ds_name = dataset_name or "web_payloads_v1"
            dataset = dataset_manager.get_dataset_data(ds_name)
            if not dataset:
                dataset = dataset_manager.create_dataset(ds_name, "PAYLOADS", 1000)["data"]

            max_features = int(hparams.get("max_features", 5000))
            engine = PayloadClassifierEngine(max_features=max_features)
            metrics = engine.fit(dataset)

            version_str = f"1.{int(time.time()) % 1000}.0"
            model_id = f"ML-TFIDF-{int(time.time())}"
            artifact_path = os.path.join(self.MODEL_DIR, f"{model_id}.pkl")
            engine.save(artifact_path)

            # Update active serving model
            self.payload_classifier = engine

            rec = MLModelRecord(
                id=model_id,
                name="Web Attack Payload Classifier",
                version=version_str,
                algorithm="TFIDF_MULTINOMIAL_NB",
                task_type=task_t,
                status=MLModelStatus.ACTIVE.value,
                metrics={
                    "accuracy": metrics["accuracy"],
                    "weighted_f1": metrics["weighted_f1"],
                    "confusion_matrix": metrics["confusion_matrix"],
                },
                hyperparameters={"max_features": max_features, "alpha": 0.1},
                artifact_path=artifact_path,
                dataset_name=ds_name,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                trained_at=datetime.utcnow(),
            )
            session.add(rec)
            await session.commit()

            duration = round(time.perf_counter() - start_time, 3)
            return {
                "model_id": model_id,
                "name": rec.name,
                "version": version_str,
                "task_type": task_t,
                "algorithm": "TFIDF_MULTINOMIAL_NB",
                "status": "ACTIVE",
                "metrics": metrics,
                "training_duration_sec": duration,
                "message": "Payload classifier model successfully trained and promoted to active serving.",
            }
        else:
            raise ValueError(f"Training workflow for task type '{task_type}' is not supported.")

    async def predict_anomaly(self, session: AsyncSession, features: Dict[str, Any]) -> Dict[str, Any]:
        """Perform real-time anomaly detection inference using Isolation Forest."""
        result = self.isolation_forest.predict(features)

        # Update telemetry
        self.inferences_served += 1
        self.total_latency_ms += result["latency_ms"]
        if result["is_anomaly"]:
            self.anomalies_detected += 1

        # Log inference
        log_rec = MLInferenceLogModel(
            id=f"INF-{uuid.uuid4().hex[:12].upper()}",
            model_id="ML-IFOREST-NETFLOW-v1",
            task_type=MLTaskType.ANOMALY_DETECTION.value,
            input_summary=f"packets={features.get('packet_count')} bytes={features.get('byte_count')} port={features.get('dst_port')}",
            prediction="ANOMALY" if result["is_anomaly"] else "NORMAL",
            confidence_score=result["confidence"],
            anomaly_score=result["anomaly_score"],
            latency_ms=result["latency_ms"],
            created_at=datetime.utcnow(),
        )
        session.add(log_rec)
        await session.commit()

        return result

    async def classify_payload(self, session: AsyncSession, payload: str) -> Dict[str, Any]:
        """Perform real-time attack classification on payload string."""
        result = self.payload_classifier.predict(payload)

        # Update telemetry
        self.inferences_served += 1
        self.total_latency_ms += result["latency_ms"]
        if result["predicted_class"] != "BENIGN":
            self.anomalies_detected += 1

        # Log inference
        snippet = payload[:100] + ("..." if len(payload) > 100 else "")
        log_rec = MLInferenceLogModel(
            id=f"INF-{uuid.uuid4().hex[:12].upper()}",
            model_id="ML-TFIDF-PAYLOAD-v1",
            task_type=MLTaskType.PAYLOAD_CLASSIFICATION.value,
            input_summary=snippet,
            prediction=result["predicted_class"],
            confidence_score=result["confidence"],
            anomaly_score=1.0 if result["predicted_class"] != "BENIGN" else 0.0,
            latency_ms=result["latency_ms"],
            created_at=datetime.utcnow(),
        )
        session.add(log_rec)
        await session.commit()

        return result

    async def evaluate_ueba(
        self,
        session: AsyncSession,
        username: str,
        bytes_transferred: Optional[float] = None,
        event_hour: Optional[int] = None,
        login_lat: Optional[float] = None,
        login_lon: Optional[float] = None,
        city: Optional[str] = None,
        country: Optional[str] = None,
        accessed_resource: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Perform UEBA behavioral evaluation."""
        result = await self.ueba_profiler.evaluate_event(
            session=session,
            username=username,
            bytes_transferred=bytes_transferred,
            event_hour=event_hour,
            login_lat=login_lat,
            login_lon=login_lon,
            city=city,
            country=country,
            accessed_resource=accessed_resource,
        )

        self.inferences_served += 1
        self.total_latency_ms += result["latency_ms"]
        if result["is_anomalous"]:
            self.anomalies_detected += 1

        return result

    async def list_ueba_profiles(self, session: AsyncSession) -> List[Dict[str, Any]]:
        """Fetch all user behavioral baseline profiles."""
        stmt = select(UserBehaviorBaselineModel).order_by(UserBehaviorBaselineModel.risk_score.desc())
        records = (await session.execute(stmt)).scalars().all()
        return [r.to_dict() for r in records]

    async def get_kpi_metrics(self, session: AsyncSession) -> Dict[str, Any]:
        """Compute aggregate real-time ML performance KPIs."""
        total_models = (await session.execute(select(func.count(MLModelRecord.id)))).scalar_one()
        active_models = (
            await session.execute(
                select(func.count(MLModelRecord.id)).where(MLModelRecord.status == MLModelStatus.ACTIVE.value)
            )
        ).scalar_one()

        avg_latency = round(
            (self.total_latency_ms / self.inferences_served) if self.inferences_served > 0 else 1.25, 2
        )
        anomaly_rate = round(
            ((self.anomalies_detected / self.inferences_served) * 100.0) if self.inferences_served > 0 else 0.0, 1
        )

        return {
            "total_registered_models": total_models,
            "active_models": active_models,
            "inferences_served": self.inferences_served,
            "avg_inference_latency_ms": avg_latency,
            "anomalies_detected": self.anomalies_detected,
            "anomaly_rate_percent": anomaly_rate,
            "drift_alerts_count": self.drift_alerts_count,
        }


ml_service = MLRegistryService()
