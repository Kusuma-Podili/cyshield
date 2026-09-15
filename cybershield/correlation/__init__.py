"""
CyberShield Enterprise Complex Event Processing (CEP) and Temporal Correlation Subsystem.
Sliding/tumbling window event buffering, stateful sequence chains, and attack pattern aggregation.
"""

from cybershield.correlation.engine import TemporalCorrelationEngine
from cybershield.correlation.rules_catalog import DEFAULT_CORRELATION_RULES
from cybershield.correlation.routes import correlation_router
from cybershield.correlation.window_buffer import TemporalEventBuffer

__all__ = [
    "TemporalCorrelationEngine",
    "TemporalEventBuffer",
    "DEFAULT_CORRELATION_RULES",
    "correlation_router",
]
