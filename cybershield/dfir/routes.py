"""REST API Endpoints for DFIR Forensic Artifact Analysis & Super-Timeline."""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status

from cybershield.auth.dependencies import get_current_user
from cybershield.database.models.user import User
from cybershield.dfir.schemas import (
    ArtifactType,
    ArtifactAnalyzeRequest,
    DFIRAnalysisResult,
    SuperTimelineRequest,
    SuperTimelineResponse,
    ForensicFinding,
)
from cybershield.dfir.timeline_engine import TimelineEngine

router = APIRouter(prefix="/api/dfir", tags=["Digital Forensics & Incident Response (DFIR)"])


@router.post("/analyze", response_model=DFIRAnalysisResult)
async def analyze_forensic_artifact(
    request: ArtifactAnalyzeRequest,
    current_user: User = Depends(get_current_user),
):
    """Analyze a host forensic artifact (EVTX, Prefetch, MFT, auditd) and extract evidence."""
    return TimelineEngine.analyze_artifact(request)


@router.post("/timeline", response_model=SuperTimelineResponse)
async def query_super_timeline(
    request: SuperTimelineRequest,
    current_user: User = Depends(get_current_user),
):
    """Retrieve chronologically ordered super-timeline across all ingested forensic artifacts."""
    return TimelineEngine.get_super_timeline(request)


@router.get("/findings", response_model=List[ForensicFinding])
async def list_forensic_findings(
    current_user: User = Depends(get_current_user),
):
    """List all identified forensic threats and adversary techniques across analyzed evidence."""
    return TimelineEngine.get_all_findings()


@router.get("/artifacts")
async def list_supported_artifacts(
    current_user: User = Depends(get_current_user),
):
    """List supported forensic artifact parsers and detection capabilities."""
    return {
        "supported_artifacts": [a.value for a in ArtifactType],
        "parsers": {
            "EVTX": "Windows Event Log binary chunk parser (Events 4624, 4625, 4688, 7045, 1102, 4720)",
            "PREFETCH": "Windows Prefetch (.pf) execution evidence parser (Windows 7/8/10/11)",
            "MFT": "NTFS $MFT 1024-byte record parser with anti-forensics timestomping detector",
            "AUDITD": "Linux kernel auditd journal log analyzer with sudo privilege escalation tracking",
        },
        "capabilities": [
            "Binary XML Template Decompression",
            "LOLBin & Encoded PowerShell Execution Detection",
            "Lateral Movement & Pass-the-Hash / Golden Ticket Timeline Correlator",
            "MACB Timestamp Discrepancy ($SI vs $FN) Timestomping Analysis",
            "Cross-Platform Unified Super-Timeline Synthesis",
        ],
    }
