"""
OASIS TAXII 2.1 and STIX 2.1 Threat Intelligence Exchange Schemas.
Implements standard discovery, collection management, object query parameters, and status tracking.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


TAXII_MEDIA_TYPE_21 = "application/taxii+json;version=2.1"
STIX_MEDIA_TYPE_21 = "application/stix+json;version=2.1"


class TaxiiServerDiscovery(BaseModel):
    """TAXII Server Discovery response (GET /taxii2/)."""
    title: str = "CyberShield Enterprise TAXII 2.1 Server"
    description: str = "On-premises, privacy-first Threat Intelligence exchange server."
    contact: str = "soc-intel@cybershield.corp"
    default: str = "/taxii2/api/"
    api_roots: List[str] = Field(default_factory=lambda: ["/taxii2/api/"])


class TaxiiApiRoot(BaseModel):
    """TAXII API Root description."""
    title: str = "Enterprise Cyber Defense Threat Intelligence"
    description: str = "Primary API root for STIX 2.1 observable and indicator collections."
    versions: List[str] = Field(default_factory=lambda: ["taxii-2.1"])
    max_content_length: int = 10485760  # 10MB


class TaxiiCollection(BaseModel):
    """A collection of STIX 2.1 threat intelligence objects."""
    id: str
    title: str
    description: str
    can_read: bool = True
    can_write: bool = True
    media_types: List[str] = Field(default_factory=lambda: [STIX_MEDIA_TYPE_21])
    total_objects: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)


class TaxiiCollectionsList(BaseModel):
    collections: List[TaxiiCollection] = Field(default_factory=list)


class StixBundle(BaseModel):
    """STIX 2.1 Envelope containing cyber threat intelligence objects."""
    type: str = "bundle"
    id: str
    objects: List[Dict[str, Any]] = Field(default_factory=list)


class TaxiiStatusResponse(BaseModel):
    """Status of an asynchronous STIX ingestion job."""
    id: str
    status: str = "complete"  # pending, complete, error
    request_timestamp: datetime = Field(default_factory=datetime.utcnow)
    total_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    pending_count: int = 0
    failures: List[Dict[str, Any]] = Field(default_factory=list)


class TaxiiEnvelope(BaseModel):
    """Envelope returned when querying objects from a TAXII collection."""
    more: bool = False
    objects: List[Dict[str, Any]] = Field(default_factory=list)
    next: Optional[str] = None
