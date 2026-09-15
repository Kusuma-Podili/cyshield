"""
CyberShield Enterprise - Threat Intelligence Pydantic Schemas
Defines request and response models for IoC ingestion, STIX/MISP feed parsing,
fast lookup queries, and threat actor profiling.
"""

from __future__ import annotations

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class IoCCreateRequest(BaseModel):
    indicator_value: str = Field(...)
    indicator_type: str = Field("IP", description="IP, DOMAIN, URL, MD5, SHA1, SHA256")
    threat_type: str = Field("C2_SERVER")
    severity: str = Field("HIGH")
    confidence_score: int = Field(85, ge=0, le=100)
    threat_actor: Optional[str] = Field(None)
    campaign: Optional[str] = Field(None)
    mitre_tactics: List[str] = Field(default_factory=list)
    source_feed: str = Field("MANUAL_ANALYST")
    expires_in_days: Optional[int] = Field(90)


class IoCLookupRequest(BaseModel):
    indicator: str = Field(..., description="IP address, domain, URL, or file hash to check")


class IoCLookupResponse(BaseModel):
    indicator: str
    matched: bool
    confidence_score: int
    threat_type: Optional[str] = None
    severity: Optional[str] = None
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    mitre_tactics: List[str] = Field(default_factory=list)
    source_feed: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    is_active: bool = False
    lookup_latency_ms: float = 0.0


class FeedIngestRequest(BaseModel):
    feed_format: str = Field("STIX", description="STIX, MISP, or CSV")
    feed_name: str = Field("US_CERT_ALERT", description="Feed provider identifier")
    payload: Dict[str, Any] = Field(..., description="Raw STIX 2.1 or MISP JSON bundle")


class ThreatIntelKPIResponse(BaseModel):
    total_iocs: int
    active_iocs: int
    ip_iocs: int
    domain_iocs: int
    hash_iocs: int
    total_threat_actors: int
    active_campaigns: int
    avg_confidence_score: float
