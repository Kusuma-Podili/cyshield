"""
Microsegmentation Policy Compiler and East-West Flow Evaluator.
Translates high-level zero trust tier policies into nftables, iptables, Windows Firewall, and Kubernetes NetworkPolicies.
"""

import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from cybershield.microseg.schemas import (
    CompiledFirewallRuleset,
    FlowEvaluationRequest,
    FlowViolationEvent,
    MicrosegmentationRule,
    NetworkAction,
    TargetFirewallFormat,
    WorkloadTier,
)


DEFAULT_MICROSEG_RULES: List[MicrosegmentationRule] = [
    MicrosegmentationRule(
        rule_id="RULE-WEB-TO-APP",
        name="Allow Web Frontend to Application Backend",
        source_tier=WorkloadTier.WEB_FRONTEND,
        destination_tier=WorkloadTier.APP_BACKEND,
        protocol="TCP",
        port_range="8080",
        action=NetworkAction.ALLOW,
        description="Permits web reverse proxies to route API traffic to backend cluster.",
    ),
    MicrosegmentationRule(
        rule_id="RULE-APP-TO-DB",
        name="Allow Application Backend to Database Cluster",
        source_tier=WorkloadTier.APP_BACKEND,
        destination_tier=WorkloadTier.DATABASE,
        protocol="TCP",
        port_range="5432",
        action=NetworkAction.ALLOW,
        description="Allows application tier to query database on PostgreSQL port 5432.",
    ),
    MicrosegmentationRule(
        rule_id="RULE-BLOCK-WEB-TO-DB",
        name="Block Direct Web Frontend Access to Database",
        source_tier=WorkloadTier.WEB_FRONTEND,
        destination_tier=WorkloadTier.DATABASE,
        protocol="ANY",
        port_range="ANY",
        action=NetworkAction.DENY,
        description="Zero Trust isolation: Web tier must never access DB cluster directly.",
    ),
    MicrosegmentationRule(
        rule_id="RULE-BLOCK-LATERAL-WORKSTATION",
        name="Block Peer-to-Peer Lateral Workstation Traffic",
        source_tier=WorkloadTier.CORP_WORKSTATION,
        destination_tier=WorkloadTier.CORP_WORKSTATION,
        protocol="ANY",
        port_range="ANY",
        action=NetworkAction.DENY,
        description="Prevents lateral ransomware infection between corporate client workstations.",
    ),
]


class MicrosegmentationCompiler:
    """Zero Trust Microsegmentation Policy Manager and Code Generator."""

    def __init__(self):
        self._rules: Dict[str, MicrosegmentationRule] = {r.rule_id: r for r in DEFAULT_MICROSEG_RULES}
        self._violations: List[FlowViolationEvent] = []

    def list_rules(self) -> List[MicrosegmentationRule]:
        return list(self._rules.values())

    def get_rule(self, rule_id: str) -> Optional[MicrosegmentationRule]:
        return self._rules.get(rule_id)

    def add_rule(self, rule: MicrosegmentationRule) -> MicrosegmentationRule:
        self._rules[rule.rule_id] = rule
        return rule

    def compile_ruleset(
        self, target_format: TargetFirewallFormat, rule_ids: Optional[List[str]] = None
    ) -> CompiledFirewallRuleset:
        """Translate high-level policies into target firewall syntax."""
        active_rules = [
            r for r in self._rules.values()
            if r.enabled and (rule_ids is None or r.rule_id in rule_ids)
        ]

        if target_format == TargetFirewallFormat.NFTABLES:
            code = self._generate_nftables(active_rules)
        elif target_format == TargetFirewallFormat.IPTABLES:
            code = self._generate_iptables(active_rules)
        elif target_format == TargetFirewallFormat.WINDOWS_FIREWALL:
            code = self._generate_windows_firewall(active_rules)
        elif target_format == TargetFirewallFormat.KUBERNETES_NETWORK_POLICY:
            code = self._generate_k8s_network_policy(active_rules)
        elif target_format == TargetFirewallFormat.AWS_SECURITY_GROUP:
            code = self._generate_aws_sg(active_rules)
        else:
            raise ValueError(f"Unsupported format {target_format}")

        return CompiledFirewallRuleset(
            target_format=target_format,
            rule_count=len(active_rules),
            generated_code=code,
            compiled_at=datetime.utcnow(),
        )

    @staticmethod
    def _generate_nftables(rules: List[MicrosegmentationRule]) -> str:
        lines = [
            "#!/usr/sbin/nft -f",
            "flush ruleset",
            "table inet cybershield_microseg {",
            "    chain forward {",
            "        type filter hook forward priority 0; policy drop;",
            "        ct state established,related accept",
            "        iifname \"lo\" accept",
        ]
        for r in rules:
            act = "accept" if r.action == NetworkAction.ALLOW else "drop"
            proto = r.protocol.lower() if r.protocol != "ANY" else "ip"
            port_clause = f" dport {r.port_range}" if r.port_range != "ANY" else ""
            lines.append(f"        # {r.name}")
            lines.append(f"        {proto}{port_clause} {act}")
        lines.append("    }")
        lines.append("}")
        return "\n".join(lines)

    @staticmethod
    def _generate_iptables(rules: List[MicrosegmentationRule]) -> str:
        lines = [
            "#!/bin/bash",
            "# CyberShield Enterprise iptables Microsegmentation Policy",
            "iptables -F FORWARD",
            "iptables -P FORWARD DROP",
            "iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        ]
        for r in rules:
            target = "ACCEPT" if r.action == NetworkAction.ALLOW else "DROP"
            proto = f"-p {r.protocol.lower()}" if r.protocol != "ANY" else ""
            port = f"--dport {r.port_range}" if r.port_range != "ANY" and proto else ""
            lines.append(f"# {r.name}")
            lines.append(f"iptables -A FORWARD {proto} {port} -j {target}".replace("  ", " "))
        return "\n".join(lines)

    @staticmethod
    def _generate_windows_firewall(rules: List[MicrosegmentationRule]) -> str:
        lines = [
            "# PowerShell Windows Defender Firewall with Advanced Security Microsegmentation",
            "Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block",
        ]
        for r in rules:
            action = "Allow" if r.action == NetworkAction.ALLOW else "Block"
            port_clause = f"-LocalPort {r.port_range}" if r.port_range != "ANY" else ""
            lines.append(
                f'New-NetFirewallRule -DisplayName "{r.name}" -Direction Inbound -Action {action} -Protocol {r.protocol} {port_clause} -Enabled True'.replace("  ", " ")
            )
        return "\n".join(lines)

    @staticmethod
    def _generate_k8s_network_policy(rules: List[MicrosegmentationRule]) -> str:
        manifests = []
        for r in rules:
            if r.action == NetworkAction.ALLOW:
                manifest = {
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "NetworkPolicy",
                    "metadata": {"name": r.rule_id.lower().replace("_", "-")},
                    "spec": {
                        "podSelector": {"matchLabels": {"tier": r.destination_tier.value.lower()}},
                        "policyTypes": ["Ingress"],
                        "ingress": [
                            {
                                "from": [{"podSelector": {"matchLabels": {"tier": r.source_tier.value.lower()}}}],
                                "ports": [{"protocol": r.protocol, "port": int(r.port_range)}] if r.port_range.isdigit() else [],
                            }
                        ],
                    },
                }
                manifests.append(json.dumps(manifest, indent=2))
        return "\n---\n".join(manifests) if manifests else "# No ingress allow policies defined"

    @staticmethod
    def _generate_aws_sg(rules: List[MicrosegmentationRule]) -> str:
        sg_rules = []
        for r in rules:
            if r.action == NetworkAction.ALLOW:
                sg_rules.append({
                    "Description": r.name,
                    "IpProtocol": r.protocol.lower(),
                    "FromPort": int(r.port_range) if r.port_range.isdigit() else 0,
                    "ToPort": int(r.port_range) if r.port_range.isdigit() else 65535,
                    "SourceWorkloadTier": r.source_tier.value,
                    "DestinationWorkloadTier": r.destination_tier.value,
                })
        return json.dumps({"SecurityGroupRules": sg_rules}, indent=2)

    def evaluate_flow(self, flow: FlowEvaluationRequest) -> Optional[FlowViolationEvent]:
        """Evaluate an observed network flow against microsegmentation policy."""
        # 1. Check explicit DENY rules first
        for r in self._rules.values():
            if not r.enabled:
                continue
            if r.source_tier == flow.src_tier and r.destination_tier == flow.dst_tier:
                if r.action == NetworkAction.DENY:
                    violation = FlowViolationEvent(
                        violation_id=f"VIOL-{uuid.uuid4().hex[:8].upper()}",
                        timestamp=datetime.utcnow(),
                        src_ip=flow.src_ip,
                        dst_ip=flow.dst_ip,
                        src_tier=flow.src_tier,
                        dst_tier=flow.dst_tier,
                        dst_port=flow.dst_port,
                        protocol=flow.protocol,
                        reason=f"Explicit microsegmentation DENY policy matched: '{r.name}'",
                        severity="CRITICAL" if flow.src_tier == WorkloadTier.WEB_FRONTEND and flow.dst_tier == WorkloadTier.DATABASE else "HIGH",
                    )
                    self._violations.append(violation)
                    return violation

        # 2. Check if an explicit ALLOW rule permits this flow
        matched_allow = False
        for r in self._rules.values():
            if not r.enabled or r.action != NetworkAction.ALLOW:
                continue
            if r.source_tier == flow.src_tier and r.destination_tier == flow.dst_tier:
                if r.protocol == "ANY" or r.protocol.upper() == flow.protocol.upper():
                    if r.port_range == "ANY" or str(flow.dst_port) == r.port_range:
                        matched_allow = True
                        break

        # If no ALLOW rule matches in a Zero Trust architecture, it is an implicit deny violation!
        if not matched_allow:
            violation = FlowViolationEvent(
                violation_id=f"VIOL-{uuid.uuid4().hex[:8].upper()}",
                timestamp=datetime.utcnow(),
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                src_tier=flow.src_tier,
                dst_tier=flow.dst_tier,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                reason=f"Zero Trust Default Deny: No microsegmentation rule permits {flow.src_tier.value} to access {flow.dst_tier.value} on port {flow.dst_port}",
                severity="MEDIUM",
            )
            self._violations.append(violation)
            return violation

        return None

    def list_violations(self, limit: int = 50) -> List[FlowViolationEvent]:
        return list(reversed(self._violations))[:limit]
