"""
Autonomous DNS Firewall & Protective C2 Sinkholing Engine.
Provides real-time Response Policy Zone (RPZ) enforcement,
algorithmic Domain Generation Algorithm (DGA) detection,
DNS tunneling exfiltration mitigation, and C2 sinkhole telemetry collection.
"""

import fnmatch
import math
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from cybershield.dnsfw.schemas import (
    DNSAction,
    DNSFirewallRule,
    DNSInspectionRequest,
    DNSInspectionResponse,
    DNSQueryType,
    DNSSinkholeHit,
)


class DNSFirewallEngine:
    """
    High-throughput protective DNS firewall and sinkhole inspection engine.
    """

    DEFAULT_SINKHOLE_IP = "10.254.254.254"

    SUSPICIOUS_TLDS = {".top", ".buzz", ".country", ".kim", ".work", ".gq", ".ml", ".cf"}

    def __init__(self):
        self._rules: Dict[str, DNSFirewallRule] = {}
        self._sinkhole_hits: List[DNSSinkholeHit] = []
        self._total_queries_inspected = 0
        self._total_blocked_or_sinkholed = 0
        self._dga_detections_count = 0
        self._tunneling_detections_count = 0
        self._init_default_rpz_rules()

    def _init_default_rpz_rules(self):
        """Pre-populate enterprise Response Policy Zone rules for known threat campaigns."""
        default_rules = [
            DNSFirewallRule(
                rule_id="RPZ-C2-001",
                domain_pattern="*.cobaltstrike-beacon.net",
                action=DNSAction.SINKHOLE,
                redirect_ip=self.DEFAULT_SINKHOLE_IP,
                category="C2_COBALTSTRIKE",
                description="Cobalt Strike Malleable C2 DNS listener wildcard pattern",
                hit_count=12
            ),
            DNSFirewallRule(
                rule_id="RPZ-C2-002",
                domain_pattern="*.apt29-exfil.org",
                action=DNSAction.SINKHOLE,
                redirect_ip=self.DEFAULT_SINKHOLE_IP,
                category="STATE_SPONSORED_C2",
                description="Known APT29 staging domain pattern",
                hit_count=5
            ),
            DNSFirewallRule(
                rule_id="RPZ-PHISH-003",
                domain_pattern="*login-microsoft-auth-verify.com",
                action=DNSAction.BLOCK_NXDOMAIN,
                redirect_ip=None,
                category="CREDENTIAL_PHISHING",
                description="O365 Credential harvesting replica domain",
                hit_count=34
            ),
            DNSFirewallRule(
                rule_id="RPZ-RANSOM-004",
                domain_pattern="*.lockbit-payment-portal.onion.ly",
                action=DNSAction.SINKHOLE,
                redirect_ip=self.DEFAULT_SINKHOLE_IP,
                category="RANSOMWARE_PAYMENT",
                description="Ransomware payment clearing proxy domain",
                hit_count=8
            ),
        ]
        for r in default_rules:
            self._rules[r.rule_id] = r

    @staticmethod
    def calculate_entropy(s: str) -> float:
        """Calculates Shannon entropy for domain strings."""
        if not s:
            return 0.0
        length = len(s)
        counts: Dict[str, int] = {}
        for c in s:
            counts[c] = counts.get(c, 0) + 1

        ent = 0.0
        for count in counts.values():
            p = count / length
            ent -= p * math.log2(p)
        return round(ent, 4)

    def is_dga_domain(self, domain: str) -> Tuple[bool, float]:
        """
        Detects algorithmic domain generation using Shannon entropy,
        consonant clustering, and character distribution.
        """
        parts = domain.lower().split(".")
        if len(parts) < 2:
            return False, 0.0

        # Primary label before public suffix
        label = parts[0]
        if len(label) < 7:
            return False, 0.0

        entropy = self.calculate_entropy(label)

        # Consonant run count and ratio
        vowels = set("aeiou")
        consonants = set("bcdfghjklmnpqrstvwxyz")
        c_count = sum(1 for ch in label if ch in consonants)
        v_count = sum(1 for ch in label if ch in vowels)

        # High consonant ratio or high entropy indicates DGA
        is_consonant_dense = (v_count == 0 and len(label) >= 8) or (v_count > 0 and (c_count / v_count) > 5.0)
        has_digit_mixing = bool(re.search(r"[a-z]+[0-9]+[a-z]+", label)) and len(label) >= 10

        is_dga = (entropy >= 3.35 and (is_consonant_dense or has_digit_mixing)) or (entropy >= 3.8)
        return is_dga, entropy

    def is_dns_tunneling(self, domain: str, query_type: DNSQueryType) -> bool:
        """Detects data exfiltration over DNS tunnels."""
        # Long FQDN or excessive subdomain label
        if len(domain) > 110:
            return True

        parts = domain.split(".")
        for p in parts:
            if len(p) > 40:
                ent = self.calculate_entropy(p)
                if ent > 3.4:
                    return True

        # Base32/Base64 high entropy chunks in TXT queries
        if query_type in (DNSQueryType.TXT, DNSQueryType.NULL) and len(parts) >= 3:
            sub = parts[0]
            if len(sub) >= 20 and self.calculate_entropy(sub) >= 3.3:
                return True

        return False

    def inspect_query(self, request: DNSInspectionRequest) -> DNSInspectionResponse:
        """Inspects outbound DNS resolution request against policies and threat engines."""
        self._total_queries_inspected += 1
        domain_clean = request.domain.strip().lower()

        # 1. Match against configured RPZ rules
        for rule in self._rules.values():
            if not rule.is_active:
                continue
            pattern = rule.domain_pattern.lower()
            if fnmatch.fnmatch(domain_clean, pattern) or domain_clean == pattern:
                rule.hit_count += 1
                self._total_blocked_or_sinkholed += 1
                return DNSInspectionResponse(
                    action=rule.action,
                    domain=request.domain,
                    resolved_ip=rule.redirect_ip if rule.action == DNSAction.SINKHOLE else None,
                    block_reason=f"Matched RPZ policy '{rule.rule_id}': {rule.description}",
                    matched_rule_id=rule.rule_id,
                )

        # 2. Check for DNS Tunneling exfiltration
        is_tunneling = self.is_dns_tunneling(domain_clean, request.query_type)
        if is_tunneling:
            self._total_blocked_or_sinkholed += 1
            self._tunneling_detections_count += 1
            return DNSInspectionResponse(
                action=DNSAction.SINKHOLE,
                domain=request.domain,
                resolved_ip=self.DEFAULT_SINKHOLE_IP,
                block_reason="DNS Tunneling / Data Exfiltration detected: anomalous subdomain payload length and entropy",
                is_tunneling_detected=True,
                entropy_score=self.calculate_entropy(domain_clean),
            )

        # 3. Check for Algorithmic DGA C2 domains
        is_dga, ent_score = self.is_dga_domain(domain_clean)
        if is_dga:
            self._total_blocked_or_sinkholed += 1
            self._dga_detections_count += 1
            return DNSInspectionResponse(
                action=DNSAction.SINKHOLE,
                domain=request.domain,
                resolved_ip=self.DEFAULT_SINKHOLE_IP,
                block_reason=f"Domain Generation Algorithm (DGA) pattern detected (Entropy: {ent_score})",
                is_dga_detected=True,
                shannon_entropy=ent_score,
            )

        # 4. Check for high-risk suspicious TLD
        for tld in self.SUSPICIOUS_TLDS:
            if domain_clean.endswith(tld):
                # We log low-priority block / quarantine
                self._total_blocked_or_sinkholed += 1
                return DNSInspectionResponse(
                    action=DNSAction.BLOCK_NXDOMAIN,
                    domain=request.domain,
                    block_reason=f"Restricted high-abuse Top-Level Domain '{tld}'",
                )

        # 5. Normal resolution permitted
        return DNSInspectionResponse(
            action=DNSAction.ALLOW,
            domain=request.domain,
            resolved_ip="192.0.2.1",  # Mock upstream standard resolver response
            block_reason=None,
        )

    def record_sinkhole_hit(self, hit: DNSSinkholeHit) -> None:
        """Records a TCP/HTTP connection attempt intercepted by the sinkhole server."""
        self._sinkhole_hits.append(hit)

    def list_rules(self) -> List[DNSFirewallRule]:
        return list(self._rules.values())

    def add_rule(self, rule: DNSFirewallRule) -> DNSFirewallRule:
        self._rules[rule.rule_id] = rule
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False

    def list_sinkhole_hits(self, limit: int = 100) -> List[DNSSinkholeHit]:
        return list(reversed(self._sinkhole_hits[-limit:]))

    def get_overview_metrics(self) -> Dict[str, Any]:
        return {
            "total_queries_inspected": self._total_queries_inspected,
            "total_interceptions": self._total_blocked_or_sinkholed,
            "dga_detections": self._dga_detections_count,
            "tunneling_detections": self._tunneling_detections_count,
            "active_rpz_rules": len(self._rules),
            "captured_sinkhole_hits": len(self._sinkhole_hits),
            "default_sinkhole_target": self.DEFAULT_SINKHOLE_IP,
        }
