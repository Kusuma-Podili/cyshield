"""
Web Application Firewall (WAF) & OWASP Top 10 Core Rule Set (CRS) Schemas.
Models Layer 7 HTTP request inspection, ModSecurity-style anomaly scoring, and attack signatures.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class WAFRuleCategory(str, Enum):
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SSRF = "SSRF"
    XXE = "XXE"
    PROTOCOL_VIOLATION = "PROTOCOL_VIOLATION"


class WAFAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    MONITOR = "MONITOR"


class WAFMatchedRule(BaseModel):
    """Specific rule signature triggered during HTTP inspection."""
    rule_id: str
    category: WAFRuleCategory
    severity_score: int  # 2 (Low), 3 (Medium), 4 (High), 5 (Critical)
    message: str
    matched_variable: str  # e.g., "QUERY_STRING", "BODY", "HEADERS:User-Agent"
    matched_value_sample: str


class WAFInspectionRequest(BaseModel):
    """Inbound HTTP request requiring Layer 7 deep packet inspection."""
    client_ip: str
    method: str = "GET"
    uri: str
    query_string: str = ""
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None


class WAFInspectionResult(BaseModel):
    """Enforcement decision produced by the WAF engine."""
    action: WAFAction
    http_status_code: int = 200  # 200 (OK) or 403 (Forbidden)
    total_anomaly_score: int = 0
    is_blocked: bool = False
    block_reason: Optional[str] = None
    matched_rules: List[WAFMatchedRule] = Field(default_factory=list)
    inspection_time_ms: float = 0.5


class WAFPolicyConfig(BaseModel):
    """Global WAF operational policy configuration."""
    blocking_threshold: int = 5  # Cumulative anomaly score required to block (default 5)
    paranoia_level: int = 1  # 1 to 4
    is_active: bool = True
    action_mode: WAFAction = WAFAction.BLOCK
