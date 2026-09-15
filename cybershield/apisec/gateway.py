"""
Autonomous API Security & Shadow API Discovery Gateway Engine.
Enforces OWASP API Security Top 10 heuristics, OpenAPI inventory drift analysis,
mass assignment screening, and Broken Object Level Authorization (BOLA) detection.
"""

import re
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from cybershield.apisec.schemas import (
    APIRiskLevel,
    APISecurityAuditReport,
    APISecurityFinding,
    APISpecEndpoint,
    APITrafficLog,
    APIType,
    OWASPAPIType,
)


class APISecurityGateway:
    """
    Intelligent API security gateway analyzing real-time transactions for vulnerabilities.
    """

    RESTRICTED_BODY_FIELDS = {
        "is_admin", "is_superuser", "role", "roles", "permissions",
        "is_verified", "account_balance", "credits", "tenant_id", "bypass_mfa"
    }

    def __init__(self):
        self._registered_specs: Dict[Tuple[str, str], APISpecEndpoint] = {}
        self._observed_endpoints: Set[Tuple[str, str]] = set()
        self._findings: List[APISecurityFinding] = []
        self._traffic_history: List[APITrafficLog] = []
        self._client_path_history: Dict[str, List[str]] = defaultdict(list)
        self._seed_registered_spec()

    def _seed_registered_spec(self):
        """Seed baseline approved OpenAPI 3.0 endpoints."""
        approved = [
            APISpecEndpoint(path="/api/v1/auth/login", method="POST", requires_auth=False),
            APISpecEndpoint(path="/api/v1/auth/refresh", method="POST", requires_auth=True),
            APISpecEndpoint(path="/api/v1/users", method="GET", allowed_roles=["admin", "analyst"]),
            APISpecEndpoint(path="/api/v1/users/{user_id}", method="GET", allowed_roles=["admin", "user"]),
            APISpecEndpoint(path="/api/v1/devices", method="GET", allowed_roles=["admin", "analyst"]),
            APISpecEndpoint(path="/api/v1/devices", method="POST", allowed_roles=["admin"]),
            APISpecEndpoint(path="/api/v0/auth/legacy-token", method="POST", is_deprecated=True),
        ]
        for ep in approved:
            self._registered_specs[(ep.method.upper(), ep.path)] = ep

    def register_endpoint(self, endpoint: APISpecEndpoint):
        """Add an approved endpoint to the schema inventory."""
        self._registered_specs[(endpoint.method.upper(), endpoint.path)] = endpoint

    def _match_path_spec(self, method: str, raw_path: str) -> Optional[APISpecEndpoint]:
        """Matches path against registered specs supporting variable parameters ({id})."""
        m = method.upper()
        # Direct exact match
        if (m, raw_path) in self._registered_specs:
            return self._registered_specs[(m, raw_path)]

        # Parameterized regex match (e.g. /api/v1/users/123 -> /api/v1/users/{user_id})
        for (spec_m, spec_path), spec in self._registered_specs.items():
            if spec_m != m:
                continue
            if "{" in spec_path and "}" in spec_path:
                regex_pattern = "^" + re.sub(r"\{[a-zA-Z0-9_]+\}", r"[a-zA-Z0-9_\-]+", spec_path) + "$"
                if re.match(regex_pattern, raw_path):
                    return spec
        return None

    def inspect_transaction(self, log: APITrafficLog) -> List[APISecurityFinding]:
        """Performs deep inspection of an incoming API transaction."""
        findings: List[APISecurityFinding] = []
        method_upper = log.method.upper()
        self._traffic_history.append(log)
        self._observed_endpoints.add((method_upper, log.path))

        matched_spec = self._match_path_spec(method_upper, log.path)

        # 1. Shadow API Discovery (API9:2023)
        if not matched_spec:
            findings.append(APISecurityFinding(
                finding_id=f"FIND-SHADOW-{uuid.uuid4().hex[:6].upper()}",
                threat_type=OWASPAPIType.SHADOW_API,
                severity=APIRiskLevel.HIGH,
                endpoint_path=log.path,
                method=method_upper,
                client_ip=log.client_ip,
                description="Unregistered / Undocumented Shadow API endpoint observed in production traffic.",
                evidence_snippet=f"{method_upper} {log.path} not present in authorized OpenAPI catalog.",
                remediation="Catalog endpoint in central API inventory, decommission, or enforce gateway blocking."
            ))
        elif matched_spec.is_deprecated:
            # Zombie API Discovery
            findings.append(APISecurityFinding(
                finding_id=f"FIND-ZOMBIE-{uuid.uuid4().hex[:6].upper()}",
                threat_type=OWASPAPIType.ZOMBIE_API,
                severity=APIRiskLevel.MEDIUM,
                endpoint_path=log.path,
                method=method_upper,
                client_ip=log.client_ip,
                description="Active traffic hitting deprecated Zombie API endpoint.",
                evidence_snippet=f"{method_upper} {log.path} was formally deprecated.",
                remediation="Deprecate and permanently shutdown old API version to prevent bypass of modern security controls."
            ))

        # 2. Broken Authentication (API2:2023)
        if matched_spec and matched_spec.requires_auth:
            auth_header = log.headers.get("authorization", "") or log.headers.get("Authorization", "")
            if not auth_header or not auth_header.strip():
                findings.append(APISecurityFinding(
                    finding_id=f"FIND-AUTH-{uuid.uuid4().hex[:6].upper()}",
                    threat_type=OWASPAPIType.BROKEN_AUTH,
                    severity=APIRiskLevel.CRITICAL,
                    endpoint_path=log.path,
                    method=method_upper,
                    client_ip=log.client_ip,
                    description="Protected API endpoint invoked without valid Authorization header.",
                    evidence_snippet="Missing Bearer token or authorization credentials.",
                    remediation="Reject unauthenticated requests at gateway with 401 Unauthorized."
                ))

        # 3. Broken Function Level Authorization - BFLA (API5:2023)
        if "/admin" in log.path.lower() or "/system" in log.path.lower():
            if log.user_role not in ("admin", "superadmin", "sec-admin"):
                findings.append(APISecurityFinding(
                    finding_id=f"FIND-BFLA-{uuid.uuid4().hex[:6].upper()}",
                    threat_type=OWASPAPIType.BFLA,
                    severity=APIRiskLevel.CRITICAL,
                    endpoint_path=log.path,
                    method=method_upper,
                    client_ip=log.client_ip,
                    description="Administrative function invoked by standard non-privileged user account.",
                    evidence_snippet=f"User role '{log.user_role}' attempted access to administrative path '{log.path}'.",
                    remediation="Implement strict role-based access control (RBAC) at controller method level."
                ))

        # 4. Mass Assignment / Broken Object Property Level Authorization (API3:2023)
        if log.request_body and isinstance(log.request_body, dict):
            injected_fields = [k for k in log.request_body.keys() if k.lower() in self.RESTRICTED_BODY_FIELDS]
            if injected_fields:
                findings.append(APISecurityFinding(
                    finding_id=f"FIND-MASS-{uuid.uuid4().hex[:6].upper()}",
                    threat_type=OWASPAPIType.MASS_ASSIGNMENT,
                    severity=APIRiskLevel.HIGH,
                    endpoint_path=log.path,
                    method=method_upper,
                    client_ip=log.client_ip,
                    description=f"Mass Assignment vulnerability: Request payload attempted modifying restricted property: {injected_fields}",
                    evidence_snippet=f"Payload keys: {injected_fields}",
                    remediation="Enforce strict DTO / Pydantic schema allowlists with extra='forbid' to strip unknown properties."
                ))

        # 5. Unrestricted Resource Consumption (API4:2023)
        for param, val in log.query_params.items():
            if param.lower() in ("limit", "size", "pagesize", "count"):
                try:
                    num_val = int(val)
                    if num_val > 1000:
                        findings.append(APISecurityFinding(
                            finding_id=f"FIND-RES-{uuid.uuid4().hex[:6].upper()}",
                            threat_type=OWASPAPIType.RESOURCE_CONSUMPTION,
                            severity=APIRiskLevel.MEDIUM,
                            endpoint_path=log.path,
                            method=method_upper,
                            client_ip=log.client_ip,
                            description=f"Excessive pagination request parameter '{param}={val}' exceeds maximum safe limit.",
                            evidence_snippet=f"Parameter {param}={val}",
                            remediation="Clamp pagination parameters to hard ceiling (e.g. max limit=100) to prevent memory exhaustion."
                        ))
                except ValueError:
                    pass

        # 6. BOLA / IDOR Sequential Identifier Enumeration (API1:2023)
        id_match = re.search(r"/(?:users|accounts|orders|invoices)/([a-zA-Z0-9_\-]+)", log.path)
        if id_match:
            obj_id = id_match.group(1)
            history = self._client_path_history[log.client_ip]
            history.append(obj_id)
            # Check if last 4 requests from this IP accessed distinct IDs
            if len(history) >= 4 and len(set(history[-4:])) >= 4:
                findings.append(APISecurityFinding(
                    finding_id=f"FIND-BOLA-{uuid.uuid4().hex[:6].upper()}",
                    threat_type=OWASPAPIType.BOLA_IDOR,
                    severity=APIRiskLevel.CRITICAL,
                    endpoint_path=log.path,
                    method=method_upper,
                    client_ip=log.client_ip,
                    description="Sequential Object Identifier Enumeration detected (BOLA / IDOR attack).",
                    evidence_snippet=f"Recent sequential IDs probed: {history[-4:]}",
                    remediation="Validate that authenticated principal strictly owns the requested resource ID."
                ))

        self._findings.extend(findings)
        return findings

    def get_shadow_endpoints(self) -> List[Dict[str, str]]:
        """Identify endpoints in live traffic missing from OpenAPI spec."""
        shadows = []
        for method, path in self._observed_endpoints:
            if not self._match_path_spec(method, path):
                shadows.append({"method": method, "path": path, "status": "SHADOW"})
        return shadows

    def get_zombie_endpoints(self) -> List[Dict[str, str]]:
        """Identify deprecated endpoints still receiving active traffic."""
        zombies = []
        for method, path in self._observed_endpoints:
            spec = self._match_path_spec(method, path)
            if spec and spec.is_deprecated:
                zombies.append({"method": method, "path": path, "status": "ZOMBIE"})
        return zombies

    def list_findings(self) -> List[APISecurityFinding]:
        return list(reversed(self._findings))

    def list_endpoints(self) -> List[Dict[str, Any]]:
        results = []
        for (m, p), spec in self._registered_specs.items():
            results.append({
                "method": m,
                "path": p,
                "is_deprecated": spec.is_deprecated,
                "requires_auth": spec.requires_auth,
                "is_cataloged": True
            })
        for m, p in self._observed_endpoints:
            if (m, p) not in self._registered_specs:
                results.append({
                    "method": m,
                    "path": p,
                    "is_deprecated": False,
                    "requires_auth": True,
                    "is_cataloged": False
                })
        return results

    def get_overview_metrics(self) -> Dict[str, Any]:
        shadows = self.get_shadow_endpoints()
        zombies = self.get_zombie_endpoints()
        threat_breakdown: Dict[str, int] = {}
        for f in self._findings:
            t = f.threat_type.value
            threat_breakdown[t] = threat_breakdown.get(t, 0) + 1

        return {
            "total_traffic_requests_inspected": len(self._traffic_history),
            "total_unique_endpoints_observed": len(self._observed_endpoints),
            "registered_spec_endpoints": len(self._registered_specs),
            "shadow_endpoints_count": len(shadows),
            "zombie_endpoints_count": len(zombies),
            "total_security_findings": len(self._findings),
            "threats_by_owasp_type": threat_breakdown,
        }
