"""Attack Simulation REST API Endpoints for Live SOC Verification."""

from __future__ import annotations

from typing import Dict, Any, Optional
from fastapi import APIRouter
from pydantic import BaseModel

from cybershield.simulation.attack_simulator import attack_simulator

router = APIRouter(prefix="/api/v1/simulation", tags=["Simulation"])


class RansomwareSimRequest(BaseModel):
    host: str = "ws-finance-08.corp"
    user: str = "mscott"


class BruteForceSimRequest(BaseModel):
    target_user: str = "jdoe_dev"
    attacker_ip: str = "91.240.118.172"


@router.post("/ransomware")
async def trigger_ransomware(payload: Optional[RansomwareSimRequest] = None):
    """Trigger simulated ransomware detonation with shadow copy purge and SOAR containment."""
    host = payload.host if payload else "ws-finance-08.corp"
    user = payload.user if payload else "mscott"
    return await attack_simulator.simulate_ransomware_detonation(host=host, user=user)


@router.post("/bruteforce")
async def trigger_bruteforce(payload: Optional[BruteForceSimRequest] = None):
    """Trigger simulated credential stuffing and brute force lockout."""
    user = payload.target_user if payload else "jdoe_dev"
    ip = payload.attacker_ip if payload else "91.240.118.172"
    return await attack_simulator.simulate_credential_stuffing(target_user=user, attacker_ip=ip)


@router.post("/sqli")
async def trigger_sqli():
    """Trigger simulated SQL injection and web attack payload."""
    return await attack_simulator.simulate_web_exploit_sqli()


@router.post("/apt29")
async def trigger_apt29():
    """Trigger full APT29 lateral movement and Mimikatz credential dumping campaign."""
    return await attack_simulator.simulate_apt_lateral_movement()


@router.post("/exfil")
async def trigger_exfil():
    """Trigger high-entropy anomalous outbound data exfiltration flow."""
    return await attack_simulator.simulate_data_exfiltration()
