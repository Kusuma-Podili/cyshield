"""CyberShield Threat Detection & Correlation Engines Module."""

from cybershield.engines.anomaly import anomaly_engine, AnomalyDetectionEngine, FlowFeatureExtractor
from cybershield.engines.ueba import ueba_engine, UEBAEngine, UserProfile
from cybershield.engines.payload import payload_engine, PayloadInspectionEngine
from cybershield.engines.static_scanner import static_scanner, StaticFileScanner, StaticAnalysisReport
from cybershield.engines.sigma_engine import sigma_engine, SigmaEngine, SigmaRule
from cybershield.engines.yara_engine import yara_engine, YaraEngine, CompiledYaraRule
from cybershield.engines.correlation import correlation_engine, ThreatCorrelationEngine, AlertCluster

from cybershield.config import settings

# Automatically compile rules from configured directory
sigma_engine.load_rules_from_dir(settings.rules_sigma_dir)
yara_engine.load_rules_from_dir(settings.rules_yara_dir)

__all__ = [
    "anomaly_engine",
    "AnomalyDetectionEngine",
    "FlowFeatureExtractor",
    "ueba_engine",
    "UEBAEngine",
    "UserProfile",
    "payload_engine",
    "PayloadInspectionEngine",
    "static_scanner",
    "StaticFileScanner",
    "StaticAnalysisReport",
    "sigma_engine",
    "SigmaEngine",
    "SigmaRule",
    "yara_engine",
    "YaraEngine",
    "CompiledYaraRule",
    "correlation_engine",
    "ThreatCorrelationEngine",
    "AlertCluster",
]
