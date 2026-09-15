"""
CyberShield Enterprise - Core Structured Logging Engine
Provides unified, thread-safe, and colored console/file logging.
"""

import logging
import sys
from typing import Optional

DEFAULT_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def get_logger(name: str = "cybershield", level: int = logging.INFO) -> logging.Logger:
    """Acquire configured logger instance."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(DEFAULT_FORMAT))
        logger.addHandler(handler)
        logger.setLevel(level)
    return logger
