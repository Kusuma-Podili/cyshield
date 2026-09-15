"""CyberShield Enterprise - Forensics Timeline Reconstructor Schemas.
Data contracts for heterogeneous forensic artifacts, timestomp anti-forensic indicators,
memory VAD tree dissections, and chronological incident episodes.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class ArtifactSourceType(str, Enum):
    MFT_RECORD = "MFT_RECORD"
    SHIMCACHE = "SHIMCACHE"
    AMCACHE = "AMCACHE"
    BASH_HISTORY = "BASH_HISTORY"
    MEMORY_VAD_DUMP = "MEMORY_VAD_DUMP"
    EVTX_SECURITY = "EVTX_SECURITY"
    PREFETCH_EXECUTION = "PREFETCH_EXECUTION"


class AttackPhase(str, Enum):
    INITIAL_ACCESS = "INITIAL_ACCESS"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    EXFILTRATION = "EXFILTRATION"


class ForensicArtifact(BaseModel):
    """Normalized forensic artifact ingested from endpoint forensics or memory."""
    artifact_id: str
    source_type: ArtifactSourceType
    host_id: str
    raw_timestamp: datetime
    normalized_utc_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    clock_skew_offset_ms: int = Field(default=0, description="Calculated NTP or local clock offset")
    confidence_score: float = Field(default=0.90, ge=0.0, le=1.0)
    entity_subject: str = Field(..., description="Subject initiating action (e.g. powershell.exe, user:alice)")
    action_verb: str = Field(..., description="Action performed (e.g. EXECUTE, WRITE_FILE, CONNECT_IP)")
    target_object: str = Field(..., description="Target object (e.g. mimikatz.exe, 198.51.100.22)")
    attack_phase: AttackPhase = AttackPhase.EXECUTION
    evidence: Dict[str, Any] = Field(default_factory=dict)


class ClusteredIncidentEpisode(BaseModel):
    """Coherent cluster of related forensic events within a temporal correlation window."""
    episode_id: str
    start_time: datetime
    end_time: datetime
    lead_process: str
    affected_hosts: List[str]
    attack_phase: AttackPhase
    artifact_count: int
    narrative: str


class MemoryVADNode(BaseModel):
    """Virtual Address Descriptor (VAD) memory region inspected for in-memory injection."""
    pid: int
    process_name: str
    start_address: str
    end_address: str
    protection: str = Field(default="PAGE_EXECUTE_READWRITE")
    is_executable: bool = True
    is_unbacked_memory: bool = Field(default=False, description="Executable memory not mapped to a disk file")
    entropy: float = Field(default=0.0, ge=0.0, le=8.0)
    shellcode_signature_matched: Optional[str] = None
    is_malicious_injection: bool = False


class TimestompDetection(BaseModel):
    """NTFS $STANDARD_INFORMATION vs $FILE_NAME timestamp divergence analysis."""
    file_path: str
    host_id: str
    standard_info_time: datetime
    file_name_time: datetime
    delta_seconds: float
    is_timestomped: bool
    details: str


class ReconstructedIncidentTimeline(BaseModel):
    """Comprehensive reconstructed chronological incident trajectory."""
    timeline_id: str
    incident_id: str
    total_artifacts: int
    episodes: List[ClusteredIncidentEpisode]
    anti_forensic_count: int
    patient_zero_host: str
    comprehensive_narrative: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
