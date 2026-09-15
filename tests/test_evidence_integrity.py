"""Unit tests for Cryptographic Evidence Locker & Chain of Custody."""

import pytest
from cybershield.incidents.evidence import evidence_locker
from cybershield.core.crypto import compute_sha256, ChainOfCustodySigner
from cybershield.core.exceptions import EvidenceIntegrityError


def test_evidence_sealing_and_verification():
    """Verify evidence is hashed with SHA-256 and integrity is maintained."""
    raw_memory_dump = b"WIN32_CRASH_DUMP_HEADER_AND_VOLATILE_PROCESSES_DATA_SAMPLE"
    expected_sha256 = compute_sha256(raw_memory_dump)

    artifact = evidence_locker.store_artifact(
        name="crashdump_target_01.dmp",
        content=raw_memory_dump,
        artifact_type="MEMORY_DUMP",
        collector="Senior Forensic Examiner",
    )

    assert artifact.sha256_hash == expected_sha256
    assert artifact.is_sealed is True
    assert len(artifact.chain_of_custody) == 1

    # Verify matching bytes passes
    assert evidence_locker.verify_artifact_bytes(artifact.artifact_id, raw_memory_dump) is True

    # Tampered bytes must raise EvidenceIntegrityError
    tampered_bytes = raw_memory_dump + b"_TAMPERED"
    with pytest.raises(EvidenceIntegrityError):
        evidence_locker.verify_artifact_bytes(artifact.artifact_id, tampered_bytes)


def test_chain_of_custody_signature_verification():
    """Verify cryptographic chain-of-custody signatures link securely."""
    signer = ChainOfCustodySigner("Test-Secret-Key")
    stamp1 = signer.create_custody_stamp("ART-001", "hash1", "Analyst-A", "COLLECTED")
    stamp2 = signer.create_custody_stamp("ART-001", "hash1", "Analyst-B", "TRANSFERRED", previous_stamp_hash=stamp1["signature"])

    chain = [stamp1, stamp2]
    assert signer.verify_chain(chain) is True

    # Tampering with intermediate signature breaks chain
    tampered_chain = [stamp1.copy(), stamp2.copy()]
    tampered_chain[0]["action"] = "MALICIOUS_MODIFICATION"
    with pytest.raises(EvidenceIntegrityError):
        signer.verify_chain(tampered_chain)
