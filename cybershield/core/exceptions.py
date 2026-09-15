"""Domain-specific exception hierarchy for CyberShield Enterprise."""

from __future__ import annotations
from typing import Optional, Dict, Any


class CyberShieldBaseException(Exception):
    """Root exception for all CyberShield platform errors."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class IngestionError(CyberShieldBaseException):
    """Raised when telemetry ingestion fails."""
    pass


class LogParsingError(IngestionError):
    """Raised when parsing a raw log record fails."""
    pass


class SchemaValidationError(IngestionError):
    """Raised when normalized telemetry violates the OCSF/ECS contract."""
    pass


class DetectionEngineError(CyberShieldBaseException):
    """Base exception for detection and ML engine failures."""
    pass


class AnomalyDetectorError(DetectionEngineError):
    """Raised when anomaly inference or model scoring encounters an error."""
    pass


class FeatureExtractionError(DetectionEngineError):
    """Raised when extracting features from raw network/event flows fails."""
    pass


class RuleEvaluationError(DetectionEngineError):
    """Raised when evaluating a Sigma or YARA detection rule fails."""
    pass


class SigmaCompilationError(RuleEvaluationError):
    """Raised when a Sigma YAML detection rule cannot be compiled into an AST."""
    pass


class YaraExecutionError(RuleEvaluationError):
    """Raised when a YARA pattern scan encounters an execution error."""
    pass


class SOARError(CyberShieldBaseException):
    """Base exception for security orchestration and automation failures."""
    pass


class PlaybookExecutionError(SOARError):
    """Raised when a response playbook fails during step execution."""
    pass


class ActionExecutionError(SOARError):
    """Raised when an automated containment or remediation action fails."""
    pass


class ContainmentFailedError(ActionExecutionError):
    """Raised when host isolation or credential revocation fails."""
    pass


class DigitalEvidenceError(CyberShieldBaseException):
    """Base exception for digital forensics and evidence locker errors."""
    pass


class EvidenceIntegrityError(DigitalEvidenceError):
    """Raised when evidence cryptographic hash does not match recorded chain-of-custody."""
    pass


class QueryEngineError(CyberShieldBaseException):
    """Base exception for CS-QL query errors."""
    pass


class QuerySyntaxError(QueryEngineError):
    """Raised when CS-QL query syntax is invalid."""
    pass


class QueryExecutionError(QueryEngineError):
    """Raised when executing a parsed query plan against the event store fails."""
    pass
