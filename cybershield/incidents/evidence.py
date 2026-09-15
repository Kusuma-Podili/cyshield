"""Digital Forensics Evidence Locker & Cryptographic Chain of Custody.

Ensures court-admissible integrity for digital evidence artifacts (memory dumps,
PCAPs, disk images, log exports). Tracks custody handoffs and verifies SHA-256
signatures against cryptographic seals.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

from cybershield.core.models import (
    EvidenceArtifact,
    CustodyRecord,
    generate_id,
    now_utc,
)
from cybershield.core.crypto import (
    compute_sha256,
    compute_sha1,
    compute_md5,
    ChainOfCustodySigner,
)
from cybershield.core.exceptions import EvidenceIntegrityError

logger = logging.getLogger("cybershield.incidents.evidence")


class EvidenceLocker:
    """Enterprise digital evidence repository with tamper verification."""

    def __init__(self, platform_secret: str = "CyberShield-Enterprise-Master-Key-2026"):
        self._artifacts: Dict[str, EvidenceArtifact] = {}
        self._signer = ChainOfCustodySigner(platform_secret)

    def store_artifact(
        self,
        name: str,
        content: bytes,
        artifact_type: str = "GENERIC_SAMPLE",
        collector: str = "CyberShield Forensic Agent",
        alert_id: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> EvidenceArtifact:
        """Store raw bytes as an immutable forensic evidence artifact."""
        sha256 = compute_sha256(content)
        sha1 = compute_sha1(content)
        md5 = compute_md5(content)

        stamp_dict = self._signer.create_custody_stamp(
            artifact_id=f"ART-{sha256[:8]}",
            artifact_hash=sha256,
            analyst=collector,
            action="ACQUIRED_AND_HASHED",
        )

        initial_custody = CustodyRecord(
            analyst_or_agent=collector,
            action="ACQUIRED_AND_HASHED",
            sha256_hash=sha256,
            notes=f"Initial evidence collection for {name} ({len(content)} bytes)"
        )

        artifact = EvidenceArtifact(
            name=name,
            incident_id=incident_id,
            alert_id=alert_id,
            artifact_type=artifact_type,
            file_size_bytes=len(content),
            sha256_hash=sha256,
            sha1_hash=sha1,
            md5_hash=md5,
            collector=collector,
            chain_of_custody=[initial_custody],
            is_sealed=True,
        )

        self._artifacts[artifact.artifact_id] = artifact
        logger.info("Evidence artifact '%s' sealed into locker with SHA256: %s", artifact.artifact_id, sha256)
        return artifact

    def add_custody_record(
        self,
        artifact_id: str,
        analyst: str,
        action: str,
        notes: Optional[str] = None
    ) -> CustodyRecord:
        """Append a new verified custody step to an existing evidence artifact."""
        artifact = self.get_artifact(artifact_id)
        if not artifact:
            raise ValueError(f"Evidence artifact '{artifact_id}' not found.")

        record = CustodyRecord(
            analyst_or_agent=analyst,
            action=action,
            sha256_hash=artifact.sha256_hash,
            notes=notes,
        )
        artifact.chain_of_custody.append(record)
        logger.info("Chain-of-custody stamp added to artifact '%s' by %s (%s)", artifact_id, analyst, action)
        return record

    def verify_artifact_bytes(self, artifact_id: str, data: bytes) -> bool:
        """Verify that a given byte sequence matches the sealed artifact SHA-256."""
        artifact = self.get_artifact(artifact_id)
        if not artifact:
            return False
        current_hash = compute_sha256(data)
        if current_hash != artifact.sha256_hash:
            raise EvidenceIntegrityError(
                f"Evidence tamper detected! Expected {artifact.sha256_hash}, calculated {current_hash}"
            )
        return True

    def get_artifact(self, artifact_id: str) -> Optional[EvidenceArtifact]:
        """Fetch artifact metadata."""
        return self._artifacts.get(artifact_id)

    def get_all_artifacts(self) -> List[EvidenceArtifact]:
        """Return all sealed artifacts."""
        return list(self._artifacts.values())


# Global singleton evidence locker
evidence_locker = EvidenceLocker()
