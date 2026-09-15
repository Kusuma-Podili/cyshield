"""
API Security & Shadow API Discovery Gateway Schemas.
Models API traffic inspection, OWASP API Top 10 threats, schema conformance, and shadow/zombie endpoints.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class APIType(str, Enum):
    REST = "REST"
    GRAPHQL = "GRAPHQL"
    GRPC = "GRPC"
    WEBSOCKET = "WEBSOCKET"


class APIRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class OWASPAPIType(str, Enum):
    BOLA_IDOR = "BOLA_IDOR"  # API1:2023 Broken Object Level Authorization
    BROKEN_AUTH = "BROKEN_AUTH"  # API2:2023 Broken Authentication
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"  # API3:2023 Broken Object Property Level Authorization
    RESOURCE_CONSUMPTION = "RESOURCE_CONSUMPTION"  # API4:2023 Unrestricted Resource Consumption
    BFLA = "BFLA"  # API5:2023 Broken Function Level Authorization
    SHADOW_API = "SHADOW_API"  # API9:2023 Improper Inventory Management
    ZOMBIE_API = "ZOMBIE_API"  # Deprecated active API version


class APISpecEndpoint(BaseModel):
    """Registered legitimate endpoint from OpenAPI/Swagger specification."""
    path: str
    method: str  # GET, POST, PUT, DELETE, PATCH
    api_type: APIType = APIType.REST
    is_deprecated: bool = False
    requires_auth: bool = True
    allowed_roles: List[str] = Field(default_factory=lambda: ["admin", "analyst", "user"])


class APITrafficLog(BaseModel):
    """Inbound HTTP transaction payload for deep inspection."""
    log_id: str
    client_ip: str
    method: str
    path: str
    query_params: Dict[str, str] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)
    request_body: Optional[Dict[str, Any]] = None
    user_role: Optional[str] = "user"
    user_id: Optional[str] = "usr_1001"
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class APISecurityFinding(BaseModel):
    """Security vulnerability or attack pattern discovered in API traffic."""
    finding_id: str
    threat_type: OWASPAPIType
    severity: APIRiskLevel
    endpoint_path: str
    method: str
    client_ip: str
    description: str
    evidence_snippet: str
    remediation: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class APISecurityAuditReport(BaseModel):
    """Consolidated inventory and threat audit across monitored web APIs."""
    report_id: str
    total_endpoints_observed: int
    registered_endpoints_count: int
    shadow_endpoints_count: int
    zombie_endpoints_count: int
    findings: List[APISecurityFinding] = Field(default_factory=list)
    overall_api_risk_score: float = 10.0
    generated_at: datetime = Field(default_factory=datetime.utcnow)
