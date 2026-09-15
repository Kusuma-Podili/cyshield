"""Enterprise Configuration Management for CyberShield Enterprise.

Centralizes runtime parameters, algorithmic thresholds, storage paths,
and engine configurations for on-premises deployment without external cloud calls.
"""

from __future__ import annotations

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any


BASE_DIR = Path(__file__).resolve().parent.parent


@dataclass
class AnomalyEngineConfig:
    """Hyperparameters and operational limits for ML anomaly detection."""
    contamination: float = 0.05
    n_estimators: int = 100
    random_state: int = 42
    flow_history_window: int = 5000
    z_score_threshold: float = 3.0
    entropy_threshold: float = 7.2
    enable_adaptive_learning: bool = True


@dataclass
class UEBAConfig:
    """User and Entity Behavior Analytics baselines and risk thresholds."""
    max_baseline_days: int = 30
    rare_process_percentile: float = 0.01
    impossible_travel_speed_kmh: float = 800.0
    privilege_spike_factor: float = 2.5
    high_risk_score_cutoff: float = 75.0
    critical_risk_score_cutoff: float = 90.0


@dataclass
class PayloadScannerConfig:
    """NLP and heuristic classifier configuration for malicious payload inspection."""
    ngram_range: tuple = (2, 5)
    max_features: int = 5000
    confidence_threshold: float = 0.75
    enable_regex_heuristics: bool = True
    max_payload_length_bytes: int = 65536


@dataclass
class IngestionConfig:
    """SIEM telemetry ingestion buffer and concurrency settings."""
    event_queue_max_size: int = 50000
    batch_flush_interval_seconds: float = 0.25
    batch_flush_max_events: int = 500
    max_worker_threads: int = 8
    retention_days: int = 90


@dataclass
class SOARConfig:
    """Security Orchestration, Automation, and Response thresholds."""
    auto_execute_critical: bool = True
    require_human_approval_for_destructive: bool = True
    playbook_timeout_seconds: int = 60
    max_active_containments: int = 50


@dataclass
class ThreatIntelConfig:
    """Local IoC database and threat intelligence cache configuration."""
    bloom_filter_capacity: int = 250000
    bloom_filter_error_rate: float = 0.001
    auto_reload_rules: bool = True


@dataclass
class SystemConfig:
    """Master CyberShield Enterprise Configuration."""
    app_name: str = "CyberShield Enterprise"
    environment: str = "production"
    debug: bool = False
    data_dir: Path = field(default_factory=lambda: BASE_DIR / "data")
    evidence_dir: Path = field(default_factory=lambda: BASE_DIR / "data" / "evidence")
    rules_sigma_dir: Path = field(default_factory=lambda: BASE_DIR / "rules" / "sigma")
    rules_yara_dir: Path = field(default_factory=lambda: BASE_DIR / "rules" / "yara")
    playbooks_dir: Path = field(default_factory=lambda: BASE_DIR / "cybershield" / "soar" / "playbooks")
    
    # HTTP and WebSocket Server
    host: str = "127.0.0.1"
    port: int = 8000
    
    # Engine sub-configurations
    anomaly: AnomalyEngineConfig = field(default_factory=AnomalyEngineConfig)
    ueba: UEBAConfig = field(default_factory=UEBAConfig)
    payload: PayloadScannerConfig = field(default_factory=PayloadScannerConfig)
    ingestion: IngestionConfig = field(default_factory=IngestionConfig)
    soar: SOARConfig = field(default_factory=SOARConfig)
    intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)

    def __post_init__(self):
        """Ensure runtime directories exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.rules_sigma_dir.mkdir(parents=True, exist_ok=True)
        self.rules_yara_dir.mkdir(parents=True, exist_ok=True)
        self.playbooks_dir.mkdir(parents=True, exist_ok=True)


# Global singleton settings instance
settings = SystemConfig()
