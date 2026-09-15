"""CyberShield Enterprise - Forensics Timeline Reconstructor Engine.
Normalizes cross-host clock skews, detects NTFS timestomp anti-forensics,
dissects memory VAD shellcode injection, and builds chronological incident narratives.
"""

import uuid
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timezone, timedelta

from .schemas import (
    ArtifactSourceType,
    AttackPhase,
    ForensicArtifact,
    ClusteredIncidentEpisode,
    MemoryVADNode,
    TimestompDetection,
    ReconstructedIncidentTimeline,
)


class ForensicsTimelineReconstructor:
    """Reconstructs coherent multi-host forensic trajectories and detects anti-forensic tampering."""

    def __init__(self):
        self.artifacts: Dict[str, ForensicArtifact] = {}
        self.host_clock_skews: Dict[str, int] = {}  # host_id -> skew in milliseconds
        self.timelines: Dict[str, ReconstructedIncidentTimeline] = {}

    def set_host_clock_skew(self, host_id: str, offset_ms: int):
        """Register calculated NTP or triangulated clock offset for a host."""
        self.host_clock_skews[host_id] = offset_ms

    def ingest_artifact(self, artifact: ForensicArtifact) -> ForensicArtifact:
        """Normalize artifact timestamp with host clock skew and store in repository."""
        skew_ms = self.host_clock_skews.get(artifact.host_id, artifact.clock_skew_offset_ms)
        artifact.clock_skew_offset_ms = skew_ms

        # Correct raw timestamp with skew offset
        adjusted_time = artifact.raw_timestamp + timedelta(milliseconds=skew_ms)
        artifact.normalized_utc_timestamp = adjusted_time

        self.artifacts[artifact.artifact_id] = artifact
        return artifact

    def detect_ntfs_timestomp(
        self,
        file_path: str,
        host_id: str,
        standard_info_time: datetime,
        file_name_time: datetime,
    ) -> TimestompDetection:
        """Detects anti-forensic modification where $STANDARD_INFORMATION was rolled back."""
        delta = (file_name_time - standard_info_time).total_seconds()
        is_timestomped = False
        details = "Timestamps consistent with normal operating system file operations."

        # Case 1: SI timestamp is significantly older than FN timestamp (classic timestomp.exe)
        if delta > 300:  # > 5 minutes disparity
            is_timestomped = True
            details = (
                f"Anti-forensic timestomping detected: $STANDARD_INFORMATION timestamp was rolled back "
                f"by {abs(round(delta, 1))}s compared to immutable kernel $FILE_NAME timestamp."
            )
        # Case 2: Sub-second nanoseconds truncated to exact 0 (common artifact of sloppy timestomp utilities)
        elif standard_info_time.microsecond == 0 and file_name_time.microsecond != 0:
            is_timestomped = True
            details = (
                "Anti-forensic timestomping detected: $STANDARD_INFORMATION sub-second precision "
                "truncated to zero microsecond resolution."
            )

        return TimestompDetection(
            file_path=file_path,
            host_id=host_id,
            standard_info_time=standard_info_time,
            file_name_time=file_name_time,
            delta_seconds=round(delta, 2),
            is_timestomped=is_timestomped,
            details=details,
        )

    def dissect_memory_vad(self, vad: MemoryVADNode) -> MemoryVADNode:
        """Analyze virtual address descriptor memory page for reflective shellcode injection."""
        is_rwx = "EXECUTE" in vad.protection and "WRITE" in vad.protection

        # Unbacked executable memory (no mapped PE file on disk) with RWX protection
        if vad.is_unbacked_memory and is_rwx:
            vad.is_malicious_injection = True
            if vad.entropy > 6.5:
                vad.shellcode_signature_matched = "CobaltStrike_Beacon_Reflective_Loader"
            else:
                vad.shellcode_signature_matched = "Generic_Unbacked_RWX_Shellcode"
        elif vad.entropy > 7.2 and vad.is_executable:
            vad.is_malicious_injection = True
            vad.shellcode_signature_matched = "High_Entropy_Encrypted_Shellcode_Payload"

        return vad

    def reconstruct_timeline(
        self,
        incident_id: str,
        artifact_ids: Optional[List[str]] = None,
    ) -> ReconstructedIncidentTimeline:
        """Synthesize chronological incident episodes and an automated forensic narrative."""
        targets = [self.artifacts[aid] for aid in artifact_ids if aid in self.artifacts] if artifact_ids else list(self.artifacts.values())

        if not targets:
            empty_id = f"timeline-{uuid.uuid4().hex[:8]}"
            t = ReconstructedIncidentTimeline(
                timeline_id=empty_id,
                incident_id=incident_id,
                total_artifacts=0,
                episodes=[],
                anti_forensic_count=0,
                patient_zero_host="UNKNOWN",
                comprehensive_narrative="No forensic artifacts provided for timeline reconstruction.",
            )
            self.timelines[empty_id] = t
            return t

        # Sort chronologically by normalized UTC timestamp
        sorted_artifacts = sorted(targets, key=lambda a: a.normalized_utc_timestamp)

        episodes: List[ClusteredIncidentEpisode] = []
        anti_forensics_count = 0

        # Cluster artifacts into episodes based on 10-minute sliding window or attack phase shift
        current_cluster: List[ForensicArtifact] = [sorted_artifacts[0]]

        for i in range(1, len(sorted_artifacts)):
            prev = sorted_artifacts[i - 1]
            curr = sorted_artifacts[i]

            time_diff = (curr.normalized_utc_timestamp - prev.normalized_utc_timestamp).total_seconds()
            same_phase = (curr.attack_phase == prev.attack_phase)

            if time_diff <= 600 or same_phase:
                current_cluster.append(curr)
            else:
                episodes.append(self._build_episode(current_cluster))
                current_cluster = [curr]

        if current_cluster:
            episodes.append(self._build_episode(current_cluster))

        # Check anti-forensics count across artifacts
        for a in sorted_artifacts:
            if a.source_type in {ArtifactSourceType.MFT_RECORD, ArtifactSourceType.SHIMCACHE} and a.evidence.get("timestomped"):
                anti_forensics_count += 1

        patient_zero = sorted_artifacts[0].host_id

        # Build end-to-end forensic narrative
        narrative_lines = [
            f"Forensic Incident Reconstruction for {incident_id}:",
            f"Earliest activity (Patient Zero) detected on host '{patient_zero}' at {sorted_artifacts[0].normalized_utc_timestamp.isoformat()}.",
            f"Total of {len(sorted_artifacts)} forensic artifacts correlated across {len(episodes)} distinct attack episodes.",
        ]
        for ep in episodes:
            narrative_lines.append(f"  - Episode [{ep.attack_phase.value}]: {ep.narrative}")

        timeline_id = f"timeline-{uuid.uuid4().hex[:8]}"
        timeline = ReconstructedIncidentTimeline(
            timeline_id=timeline_id,
            incident_id=incident_id,
            total_artifacts=len(sorted_artifacts),
            episodes=episodes,
            anti_forensic_count=anti_forensics_count,
            patient_zero_host=patient_zero,
            comprehensive_narrative="\n".join(narrative_lines),
        )
        self.timelines[timeline_id] = timeline
        return timeline

    def _build_episode(self, cluster: List[ForensicArtifact]) -> ClusteredIncidentEpisode:
        """Create an episode summary from a cluster of artifacts."""
        start_t = cluster[0].normalized_utc_timestamp
        end_t = cluster[-1].normalized_utc_timestamp
        lead = cluster[0].entity_subject
        phase = cluster[0].attack_phase
        hosts = list({a.host_id for a in cluster})

        verbs = list({a.action_verb for a in cluster})
        targets = list({a.target_object for a in cluster})

        narrative = (
            f"Process '{lead}' executed actions ({', '.join(verbs[:3])}) targeting "
            f"({', '.join(targets[:3])}) across host(s) {', '.join(hosts)}."
        )

        return ClusteredIncidentEpisode(
            episode_id=f"ep-{uuid.uuid4().hex[:8]}",
            start_time=start_t,
            end_time=end_t,
            lead_process=lead,
            affected_hosts=hosts,
            attack_phase=phase,
            artifact_count=len(cluster),
            narrative=narrative,
        )
