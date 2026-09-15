"""
CyberShield Enterprise - Phishing & Email Security Schemas
Defines request and response schemas for email inspection, typosquatting checks,
and phishing defense metrics.
"""

from __future__ import annotations

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class EmailAttachmentItem(BaseModel):
    filename: str = Field(...)
    content_sample: Optional[str] = Field(None, description="ASCII or base64 excerpt of attachment contents")
    sha256: Optional[str] = Field(None)


class EmailAnalyzeRequest(BaseModel):
    headers: Dict[str, str] = Field(
        ...,
        description="Raw or parsed RFC 5322 email headers"
    )
    body: str = Field(
        ...,
        description="Plain text or HTML email body"
    )
    attachments: Optional[List[EmailAttachmentItem]] = Field(default_factory=list)


class BrandCheckRequest(BaseModel):
    domain: str = Field(...)


class PhishingKPIResponse(BaseModel):
    total_emails_scanned: int
    phishing_blocked: int
    suspicious_tagged: int
    clean_delivered: int
    quishing_attacks_detected: int
    top_impersonated_brands: List[Dict[str, Any]]
