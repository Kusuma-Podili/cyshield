"""
Autonomous Web Application Firewall (WAF) & OWASP Core Rule Set Engine.
Implements ModSecurity-style collaborative anomaly scoring and Layer 7 attack pattern inspection.
"""

import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from cybershield.waf.schemas import (
    WAFAction,
    WAFInspectionRequest,
    WAFInspectionResult,
    WAFMatchedRule,
    WAFPolicyConfig,
    WAFRuleCategory,
)


class WAFEngine:
    """
    High-performance Layer 7 Web Application Firewall inspecting HTTP payloads.
    """

    RULES = [
        # SQL Injection (SQLi)
        (
            "CRS-942100",
            WAFRuleCategory.SQL_INJECTION,
            5,
            re.compile(r"(?i)(?:'\s*or\s*['\d\w]+\s*=\s*['\d\w]+|union\s+(?:all\s+)?select|select\s+.*?\s+from|insert\s+into\s+.*?|drop\s+table\s+.*?)"),
            "Classic SQL Injection statement pattern discovered (Tautology / UNION / DDL)"
        ),
        (
            "CRS-942110",
            WAFRuleCategory.SQL_INJECTION,
            3,
            re.compile(r"(?i)(?:--\s*|\/\*.*?\*\/|#\s*)"),
            "SQL inline comment delimiter detected"
        ),
        (
            "CRS-942120",
            WAFRuleCategory.SQL_INJECTION,
            5,
            re.compile(r"(?i)(?:sleep\(\s*\d+\s*\)|benchmark\(\s*\d+\s*,\s*|waitfor\s+delay\s+['\"][\d:]+['\"])"),
            "Blind Time-Based SQL Injection probe"
        ),

        # Cross-Site Scripting (XSS)
        (
            "CRS-941100",
            WAFRuleCategory.XSS,
            5,
            re.compile(r"(?i)(?:<script[\s>]|javascript:|onload\s*=|onerror\s*=|onclick\s*=|document\.cookie|<svg[\s/].*?onload|<img\s+.*?onerror=)"),
            "Cross-Site Scripting (XSS) tag injection or event-handler payload"
        ),

        # Remote Code Execution (RCE) / Command Injection
        (
            "CRS-932100",
            WAFRuleCategory.COMMAND_INJECTION,
            5,
            re.compile(r"(?:;\s*(?:cat|ls|whoami|id|uname|nc|curl|wget)\b|\|\s*(?:bash|sh)\b|`whoami`|\$\(whoami\)|&+\s*(?:dir|type|ipconfig|whoami)\b)"),
            "OS Shell Command Injection operator and utility invocation"
        ),

        # Path Traversal / Local File Inclusion (LFI)
        (
            "CRS-930100",
            WAFRuleCategory.PATH_TRAVERSAL,
            5,
            re.compile(r"(?i)(?:\.\./|\.\.\\|/etc/passwd|/etc/shadow|c:\\windows\\win\.ini|php://(?:filter|input))"),
            "Directory Path Traversal or sensitive system file reference"
        ),

        # Server-Side Request Forgery (SSRF)
        (
            "CRS-934100",
            WAFRuleCategory.SSRF,
            5,
            re.compile(r"(?i)(?:169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|localhost:\d+)"),
            "Cloud Metadata or Loopback interface SSRF probe"
        ),

        # XML External Entity (XXE)
        (
            "CRS-933100",
            WAFRuleCategory.XXE,
            5,
            re.compile(r"(?i)(?:<!ENTITY\s+.*?SYSTEM|<!DOCTYPE\s+.*?SYSTEM)"),
            "XML External Entity (XXE) definition attempting local resource disclosure"
        ),
    ]

    def __init__(self, config: Optional[WAFPolicyConfig] = None):
        self._config = config or WAFPolicyConfig()
        self._total_inspected = 0
        self._total_blocked = 0
        self._category_blocks: Dict[str, int] = {c.value: 0 for c in WAFRuleCategory}

    @property
    def config(self) -> WAFPolicyConfig:
        return self._config

    def update_config(self, new_config: WAFPolicyConfig) -> WAFPolicyConfig:
        self._config = new_config
        return self._config

    def _inspect_string(self, target_var: str, content: str) -> List[WAFMatchedRule]:
        """Runs rule patterns against a decoded HTTP element string."""
        matches: List[WAFMatchedRule] = []
        if not content:
            return matches

        # Decode URL-encoded characters
        decoded = urllib.parse.unquote(content)

        for rule_id, category, severity, pattern, desc in self.RULES:
            m = pattern.search(decoded)
            if m:
                sample = m.group(0)[:60]
                matches.append(WAFMatchedRule(
                    rule_id=rule_id,
                    category=category,
                    severity_score=severity,
                    message=desc,
                    matched_variable=target_var,
                    matched_value_sample=sample,
                ))
        return matches

    def inspect_request(self, request: WAFInspectionRequest) -> WAFInspectionResult:
        """Evaluates inbound HTTP request against OWASP CRS rules using anomaly scoring."""
        self._total_inspected += 1
        start_time = time.time()
        all_matched: List[WAFMatchedRule] = []

        # 1. Inspect URI
        all_matched.extend(self._inspect_string("REQUEST_URI", request.uri))

        # 2. Inspect Query String
        if request.query_string:
            all_matched.extend(self._inspect_string("QUERY_STRING", request.query_string))

        # 3. Inspect Headers
        for h_name, h_val in request.headers.items():
            h_lower = h_name.lower()
            if h_lower in ("user-agent", "referer", "cookie", "x-forwarded-for"):
                all_matched.extend(self._inspect_string(f"HEADERS:{h_name}", h_val))

        # 4. Inspect Request Body
        if request.body:
            all_matched.extend(self._inspect_string("REQUEST_BODY", request.body))

        # Calculate total anomaly score
        total_score = sum(m.severity_score for m in all_matched)

        is_blocked = False
        action = WAFAction.ALLOW
        status_code = 200
        reason = None

        if self._config.is_active:
            if total_score >= self._config.blocking_threshold:
                if self._config.action_mode == WAFAction.BLOCK:
                    is_blocked = True
                    action = WAFAction.BLOCK
                    status_code = 403
                    self._total_blocked += 1
                    # Record category blocks
                    for m in all_matched:
                        cat_str = m.category.value
                        self._category_blocks[cat_str] = self._category_blocks.get(cat_str, 0) + 1
                    reason = f"Request blocked: Anomaly score {total_score} exceeds threshold {self._config.blocking_threshold}."
                else:
                    action = WAFAction.MONITOR

        elapsed_ms = round((time.time() - start_time) * 1000.0, 2)

        return WAFInspectionResult(
            action=action,
            http_status_code=status_code,
            total_anomaly_score=total_score,
            is_blocked=is_blocked,
            block_reason=reason,
            matched_rules=all_matched,
            inspection_time_ms=max(0.1, elapsed_ms),
        )

    def list_rules(self) -> List[Dict[str, Any]]:
        """Returns catalog of active detection signatures."""
        return [
            {
                "rule_id": r[0],
                "category": r[1].value,
                "severity": r[2],
                "description": r[4],
            }
            for r in self.RULES
        ]

    def get_overview_metrics(self) -> Dict[str, Any]:
        return {
            "total_requests_inspected": self._total_inspected,
            "total_requests_blocked": self._total_blocked,
            "blocking_threshold": self._config.blocking_threshold,
            "active_rules_count": len(self.RULES),
            "attacks_blocked_by_category": self._category_blocks,
            "is_active": self._config.is_active,
        }
