"""CyberShield Enterprise - Forensics Timeline Reconstructor API Routes.
Exposes endpoints for forensic artifact ingestion, cross-host clock skew configuration,
NTFS timestomp detection, memory VAD shellcode dissection, and incident timeline reconstruction.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    ForensicArtifact,
    ClusteredIncidentEpisode,
    MemoryVADNode,
    TimestompDetection,
    ReconstructedIncidentTimeline,
)
from .reconstructor import ForensicsTimelineReconstructor

router = APIRouter(prefix="/api/v1/timeline", tags=["Forensics Timeline & Memory Dissector"])

# Active singleton reconstructor engine
_RECONSTRUCTOR = ForensicsTimelineReconstructor()


@router.post("/artifacts", response_model=ForensicArtifact, status_code=status.HTTP_201_CREATED)
def ingest_forensic_artifact(artifact: ForensicArtifact):
    """Ingest a normalized forensic artifact (MFT, Shimcache, Amcache, Memory, Evtx)."""
    return _RECONSTRUCTOR.ingest_artifact(artifact)


@router.get("/artifacts", response_model=List[ForensicArtifact])
def list_forensic_artifacts(limit: int = Query(50, ge=1, le=500)):
    """Retrieve ingested forensic artifacts ordered by normalized timestamp."""
    artifacts = list(_RECONSTRUCTOR.artifacts.values())
    artifacts.sort(key=lambda a: a.normalized_utc_timestamp)
    return artifacts[-limit:]


@router.post("/skew")
def configure_host_clock_skew(
    host_id: str = Query(..., description="Target machine hostname or IP"),
    offset_ms: int = Query(..., description="Calculated clock skew offset in milliseconds"),
):
    """Register clock skew calibration for a host machine."""
    _RECONSTRUCTOR.set_host_clock_skew(host_id, offset_ms)
    return {
        "status": "calibrated",
        "host_id": host_id,
        "offset_ms": offset_ms,
    }


@router.post("/timestomp/check", response_model=TimestompDetection)
def check_timestomp(
    file_path: str = Query(...),
    host_id: str = Query("host-workstation-01"),
    standard_info_time: datetime = Query(...),
    file_name_time: datetime = Query(...),
):
    """Detect anti-forensic timestomping divergence between NTFS $STANDARD_INFORMATION and $FILE_NAME."""
    return _RECONSTRUCTOR.detect_ntfs_timestomp(
        file_path=file_path,
        host_id=host_id,
        standard_info_time=standard_info_time,
        file_name_time=file_name_time,
    )


@router.post("/memory/dissect", response_model=MemoryVADNode)
def dissect_memory_vad(vad: MemoryVADNode):
    """Inspect Virtual Address Descriptor (VAD) region for reflective shellcode injection."""
    return _RECONSTRUCTOR.dissect_memory_vad(vad)


@router.post("/reconstruct", response_model=ReconstructedIncidentTimeline, status_code=status.HTTP_201_CREATED)
def reconstruct_incident_timeline(incident_id: str = Query(..., description="Incident ID to reconstruct")):
    """Build chronological incident trajectory, cluster into episodes, and synthesize narrative."""
    return _RECONSTRUCTOR.reconstruct_timeline(incident_id=incident_id)


@router.get("/{timeline_id}", response_model=ReconstructedIncidentTimeline)
def get_reconstructed_timeline(timeline_id: str):
    """Retrieve an existing reconstructed forensic incident timeline."""
    if timeline_id not in _RECONSTRUCTOR.timelines:
        raise HTTPException(status_code=404, detail=f"Timeline '{timeline_id}' not found.")
    return _RECONSTRUCTOR.timelines[timeline_id]
