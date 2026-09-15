"""
CyberShield Enterprise - UEBA Package
Provides user & entity behavior analytics, statistical baselining, and impossible travel detection.
"""

from cybershield.ml.ueba.impossible_travel import ImpossibleTravelDetector
from cybershield.ml.ueba.profiler import BehavioralProfiler

__all__ = [
    "ImpossibleTravelDetector",
    "BehavioralProfiler",
]
