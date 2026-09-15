"""CyberShield Enterprise - Main Application Launcher.

Starts the on-premises AI Threat Detection Platform and SOC Glass Cockpit.
Usage:
    python run_cybershield.py [--host 127.0.0.1] [--port 8000] [--simulate]
"""

from __future__ import annotations

import sys
import argparse
import logging
import uvicorn

from cybershield.version import __version__, __build__
from cybershield.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("cybershield.launcher")


def main():
    parser = argparse.ArgumentParser(
        description=f"CyberShield Enterprise v{__version__} - AI Threat Detection & Response Platform"
    )
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reloading for development")

    args = parser.parse_args()

    banner = rf"""
  +=========================================================================+
  |                                                                         |
  |     CYBERSHIELD ENTERPRISE - AI THREAT DETECTION & SOAR PLATFORM        |
  |                                                                         |
  |                 Version: {__version__} | Build: {__build__}                  |
  |            100% Offline AI Engines | Sigma | YARA | SOAR Playbooks      |
  |                                                                         |
  +=========================================================================+
    """
    print(banner)
    print(f"[*] Initializing detection engines (Isolation Forest, UEBA, NLP Classifier)...")
    print(f"[*] Access Enterprise SOC Glass Cockpit at: http://{args.host}:{args.port}")
    print(f"[*] Real-time WebSocket feed endpoint: ws://{args.host}:{args.port}/ws/soc")
    print(f"[*] Press CTRL+C to terminate platform gracefully.\n")

    uvicorn.run(
        "cybershield.api.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
        access_log=True,
    )


if __name__ == "__main__":
    main()
