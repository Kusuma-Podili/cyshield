"""
TAXII 2.1 Threat Intelligence Server Implementation.
Implements in-memory OASIS TAXII 2.1 collections, STIX 2.1 object storage, and indicator feeds.
"""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from cybershield.taxii.schemas import (
    StixBundle,
    TaxiiApiRoot,
    TaxiiCollection,
    TaxiiCollectionsList,
    TaxiiEnvelope,
    TaxiiServerDiscovery,
    TaxiiStatusResponse,
)


DEFAULT_TAXII_COLLECTIONS: List[TaxiiCollection] = [
    TaxiiCollection(
        id="col-cisa-kev",
        title="CISA Known Exploited Vulnerabilities (KEV)",
        description="Catalog of vulnerabilities known to be actively exploited in the wild.",
        can_read=True,
        can_write=True,
        total_objects=0,
    ),
    TaxiiCollection(
        id="col-ransomware-iocs",
        title="Ransomware Campaign Indicators of Compromise",
        description="High-fidelity indicators associated with LockBit, BlackCat, and Clop ransomware.",
        can_read=True,
        can_write=True,
        total_objects=0,
    ),
    TaxiiCollection(
        id="col-apt-threat-actors",
        title="Nation-State APT Threat Actors & TTPs",
        description="Threat actor infrastructure, C2 IP nodes, and weaponized tools.",
        can_read=True,
        can_write=True,
        total_objects=0,
    ),
]


class TaxiiServerEngine:
    """OASIS TAXII 2.1 Server for Threat Intelligence Distribution."""

    def __init__(self):
        self._discovery = TaxiiServerDiscovery()
        self._api_root = TaxiiApiRoot()
        self._collections: Dict[str, TaxiiCollection] = {c.id: c for c in DEFAULT_TAXII_COLLECTIONS}
        # Objects by collection: col_id -> Dict[object_id, object_dict]
        self._collection_objects: Dict[str, Dict[str, Dict[str, Any]]] = {
            c.id: {} for c in DEFAULT_TAXII_COLLECTIONS
        }
        self._status_jobs: Dict[str, TaxiiStatusResponse] = {}
        self._seed_default_stix_indicators()

    def _seed_default_stix_indicators(self):
        """Seed representative STIX 2.1 threat indicators."""
        # 1. LockBit 3.0 indicator in ransomware collection
        lockbit_indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": "LockBit 3.0 Ransomware Dropper Hash",
            "description": "SHA256 hash identifying LockBit 3.0 encryptor binary.",
            "indicator_types": ["malicious-activity"],
            "pattern": "[file:hashes.'SHA-256' = 'd9a8c7b6e5f41234567890abcdef1234567890abcdef1234567890abcdef1234']",
            "pattern_type": "stix",
            "valid_from": datetime.utcnow().isoformat() + "Z",
            "confidence": 95,
        }

        # 2. C2 IP address in ransomware collection
        c2_ip_indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": "Cobalt Strike Beacon C2 Server",
            "description": "Active C2 node directing beacon communications.",
            "indicator_types": ["anomalous-activity"],
            "pattern": "[ipv4-addr:value = '185.220.101.44']",
            "pattern_type": "stix",
            "valid_from": datetime.utcnow().isoformat() + "Z",
            "confidence": 90,
        }

        self.add_objects_to_collection("col-ransomware-iocs", [lockbit_indicator, c2_ip_indicator])

        # 3. CISA KEV indicator
        cve_indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": "CVE-2023-34362 MOVEit Transfer SQLi Exploitation",
            "description": "Web exploitation targeting MOVEit Transfer endpoints.",
            "indicator_types": ["malicious-activity"],
            "pattern": "[vulnerability:cve = 'CVE-2023-34362']",
            "pattern_type": "stix",
            "valid_from": datetime.utcnow().isoformat() + "Z",
            "confidence": 100,
        }
        self.add_objects_to_collection("col-cisa-kev", [cve_indicator])

    def get_discovery(self) -> TaxiiServerDiscovery:
        return self._discovery

    def get_api_root(self) -> TaxiiApiRoot:
        return self._api_root

    def list_collections(self) -> TaxiiCollectionsList:
        return TaxiiCollectionsList(collections=list(self._collections.values()))

    def get_collection(self, collection_id: str) -> Optional[TaxiiCollection]:
        return self._collections.get(collection_id)

    def add_objects_to_collection(
        self, collection_id: str, objects: List[Dict[str, Any]]
    ) -> TaxiiStatusResponse:
        """Ingest STIX 2.1 objects into collection."""
        col = self._collections.get(collection_id)
        if not col:
            raise ValueError(f"Collection '{collection_id}' not found")

        objects_dict = self._collection_objects.setdefault(collection_id, {})
        success_count = 0
        failures = []

        for obj in objects:
            obj_id = obj.get("id")
            if not obj_id:
                obj_id = f"{obj.get('type', 'stix-object')}--{uuid.uuid4()}"
                obj["id"] = obj_id

            objects_dict[obj_id] = obj
            success_count += 1

        col.total_objects = len(objects_dict)

        status_resp = TaxiiStatusResponse(
            id=f"STATUS-{uuid.uuid4().hex[:8].upper()}",
            status="complete",
            request_timestamp=datetime.utcnow(),
            total_count=len(objects),
            success_count=success_count,
            failure_count=len(failures),
            pending_count=0,
            failures=failures,
        )
        self._status_jobs[status_resp.id] = status_resp
        return status_resp

    def get_objects(
        self,
        collection_id: str,
        match_type: Optional[str] = None,
        match_id: Optional[str] = None,
        limit: int = 100,
    ) -> TaxiiEnvelope:
        """Query STIX 2.1 objects from a TAXII collection."""
        if collection_id not in self._collections:
            raise ValueError(f"Collection '{collection_id}' not found")

        objects_dict = self._collection_objects.get(collection_id, {})
        matched: List[Dict[str, Any]] = []

        for obj in objects_dict.values():
            if match_type and obj.get("type") != match_type:
                continue
            if match_id and obj.get("id") != match_id:
                continue
            matched.append(obj)
            if len(matched) >= limit:
                break

        return TaxiiEnvelope(more=False, objects=matched)

    def get_status_job(self, status_id: str) -> Optional[TaxiiStatusResponse]:
        return self._status_jobs.get(status_id)
