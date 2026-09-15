"""
CyberShield Enterprise - Dataset Manager
Provides dataset registration, storage, cataloging, and train/test splitting.
"""

from __future__ import annotations

import os
import json
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from cybershield.ml.datasets.generator import SecurityDatasetGenerator


class DatasetManager:
    """Local offline dataset catalog and storage manager."""

    def __init__(self, storage_dir: str = "data/datasets"):
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)
        self._in_memory_catalog: Dict[str, Dict[str, Any]] = {}
        self._initialize_default_datasets()

    def _initialize_default_datasets(self):
        """Pre-populate default synthetic cybersecurity datasets if not present."""
        default_payloads = "web_payloads_v1"
        if default_payloads not in self._in_memory_catalog:
            p_data = SecurityDatasetGenerator.generate_payload_dataset(n_samples=1000)
            self._in_memory_catalog[default_payloads] = {
                "name": default_payloads,
                "dataset_type": "PAYLOADS",
                "samples_count": len(p_data),
                "features_count": 1,
                "labels_distribution": {
                    "BENIGN": sum(1 for _, l in p_data if l == "BENIGN"),
                    "SQL_INJECTION": sum(1 for _, l in p_data if l == "SQL_INJECTION"),
                    "CROSS_SITE_SCRIPTING": sum(1 for _, l in p_data if l == "CROSS_SITE_SCRIPTING"),
                    "COMMAND_INJECTION": sum(1 for _, l in p_data if l == "COMMAND_INJECTION"),
                    "PATH_TRAVERSAL": sum(1 for _, l in p_data if l == "PATH_TRAVERSAL"),
                },
                "data": p_data,
                "created_at": datetime.utcnow().isoformat(),
            }

        default_netflow = "netflow_traffic_v1"
        if default_netflow not in self._in_memory_catalog:
            n_data = SecurityDatasetGenerator.generate_netflow_dataset(n_samples=1200)
            self._in_memory_catalog[default_netflow] = {
                "name": default_netflow,
                "dataset_type": "NETFLOW",
                "samples_count": len(n_data),
                "features_count": 6,
                "labels_distribution": {
                    "NORMAL": sum(1 for r in n_data if r["is_anomaly"] == 0),
                    "ANOMALY": sum(1 for r in n_data if r["is_anomaly"] == 1),
                },
                "data": n_data,
                "created_at": datetime.utcnow().isoformat(),
            }

    def list_datasets(self) -> List[Dict[str, Any]]:
        """Return metadata summary of all available datasets."""
        res = []
        for name, meta in self._in_memory_catalog.items():
            res.append({
                "name": name,
                "dataset_type": meta["dataset_type"],
                "samples_count": meta["samples_count"],
                "features_count": meta["features_count"],
                "labels_distribution": meta["labels_distribution"],
                "created_at": meta["created_at"],
            })
        return res

    def get_dataset_data(self, name: str) -> Optional[Any]:
        """Fetch raw dataset contents."""
        entry = self._in_memory_catalog.get(name)
        if entry:
            return entry.get("data")
        return None

    def create_dataset(self, name: str, dataset_type: str, n_samples: int = 1000) -> Dict[str, Any]:
        """Generate and register a new dataset."""
        ds_type = dataset_type.upper()
        if ds_type == "PAYLOADS":
            data = SecurityDatasetGenerator.generate_payload_dataset(n_samples=n_samples)
            meta = {
                "name": name,
                "dataset_type": ds_type,
                "samples_count": len(data),
                "features_count": 1,
                "labels_distribution": {
                    c: sum(1 for _, l in data if l == c)
                    for c in ["BENIGN", "SQL_INJECTION", "CROSS_SITE_SCRIPTING", "COMMAND_INJECTION", "PATH_TRAVERSAL"]
                },
                "data": data,
                "created_at": datetime.utcnow().isoformat(),
            }
        elif ds_type == "NETFLOW":
            data = SecurityDatasetGenerator.generate_netflow_dataset(n_samples=n_samples)
            meta = {
                "name": name,
                "dataset_type": ds_type,
                "samples_count": len(data),
                "features_count": 6,
                "labels_distribution": {
                    "NORMAL": sum(1 for r in data if r["is_anomaly"] == 0),
                    "ANOMALY": sum(1 for r in data if r["is_anomaly"] == 1),
                },
                "data": data,
                "created_at": datetime.utcnow().isoformat(),
            }
        else:
            raise ValueError(f"Unsupported dataset type: {dataset_type}")

        self._in_memory_catalog[name] = meta
        return {
            "name": meta["name"],
            "dataset_type": meta["dataset_type"],
            "samples_count": meta["samples_count"],
            "features_count": meta["features_count"],
            "labels_distribution": meta["labels_distribution"],
            "created_at": meta["created_at"],
        }


dataset_manager = DatasetManager()
