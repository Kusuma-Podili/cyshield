"""
CyberShield Enterprise - ML Datasets Package
Provides dataset generation, train/test splitting, and feature storage.
"""

from cybershield.ml.datasets.generator import SecurityDatasetGenerator
from cybershield.ml.datasets.manager import dataset_manager

__all__ = [
    "SecurityDatasetGenerator",
    "dataset_manager",
]
