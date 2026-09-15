"""CyberShield Enterprise - Autonomous LLM Guardrail & Prompt Injection Sentinel Engine.
Evaluates user prompts and RAG context for prompt injections, jailbreaks, and unicode evasion,
while filtering LLM completions for system prompt leakage and weaponized exploit synthesis.
"""

import re
import uuid
import base64
import time
from typing import Dict, List, Optional, Tuple, Set, Any
from datetime import datetime, timezone

from .schemas import (
    LLMThreatCategory,
    GuardrailAction,
    PromptInspectionRequest,
    CompletionInspectionRequest,
    LLMGuardrailAlert,
    PromptInspectionResponse,
    CompletionInspectionResponse,
    LLMGuardrailMetrics,
)


class LLMGuardrailSentinel:
    """Enterprise AI firewall and prompt injection defense engine."""

    # Direct prompt injection and instruction override signatures
    INJECTION_SIGNATURES: Dict[LLMThreatCategory, Tuple[re.Pattern, str, str]] = {
        LLMThreatCategory.DIRECT_PROMPT_INJECTION: (
            re.compile(
                r'(?i)\b(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|'
                r'disregard\s+(?:all\s+)?prior\s+guidelines|'
                r'forget\s+(?:all\s+)?previous\s+rules|'
                r'bypass\s+safety\s+filter)\b'
            ),
            "AML.T0051 - LLM Prompt Injection: Direct",
            "Prompt attempted to override system instructions and core guardrails.",
        ),
        LLMThreatCategory.JAILBREAK_ROLEPLAY_OVERRIDE: (
            re.compile(
                r'(?i)\b(?:dan\s+mode|developer\s+mode\s+enabled|jailbreak\s+activated|'
                r'do\s+anything\s+now|unfiltered\s+ai|evil\s+bot\s+persona|'
                r'you\s+are\s+now\s+an\s+unconstrained\s+model)\b'
            ),
            "AML.T0054 - LLM Jailbreaking: Persona Manipulation",
            "Jailbreak persona manipulation attempting to unlock unconstrained generation.",
        ),
        LLMThreatCategory.SYSTEM_PROMPT_EXTRACTION: (
            re.compile(
                r'(?i)\b(?:repeat\s+the\s+words\s+above|show\s+me\s+your\s+system\s+prompt|'
                r'output\s+initial\s+instructions|print\s+(?:your\s+)?system\s+prompt|'
                r'what\s+is\s+your\s+exact\s+system\s+instruction)\b'
            ),
            "AML.T0043 - Adversarial Extraction: System Prompt Leakage",
            "Attacker attempting to induce model into revealing confidential enterprise system prompts.",
        ),
    }

    # Weaponized exploit patterns forbidden in completions
    EXPLOIT_PATTERNS = [
        re.compile(r'(?i)\bbash\s+-i\s+>&?\s+/dev/tcp/[0-9\.]+/'),
        re.compile(r'(?i)\bpowershell(?:\.exe)?\s+-(?:enc|encodedcommand)\s+[a-z0-9+/=]{30,}'),
        re.compile(r'(?i)\bVirtualAlloc(?:Ex)?.*PAGE_EXECUTE_READWRITE'),
        re.compile(r'(?i)\/bin\/(?:ba)?sh\s+-c\s+["\']exec\s+[0-9]+<>\/dev\/tcp'),
    ]

    def __init__(self):
        self.alerts: List[LLMGuardrailAlert] = []
        self.total_scans: int = 0
        self.blocked_injections_counter: int = 0
        self.jailbreak_counter: int = 0
        self.canary_leaks_counter: int = 0

    @staticmethod
    def _strip_unicode_evasion(text: str) -> Tuple[str, bool]:
        """Strip invisible zero-width spaces and bidi control chars, returning clean text and evasion flag."""
        suspicious_chars = {
            '\u200b', '\u200c', '\u200d', '\u200e', '\u200f',
            '\ufeff', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e'
        }
        evasion_detected = any(c in text for c in suspicious_chars)
        cleaned = "".join(c for c in text if c not in suspicious_chars)
        return cleaned, evasion_detected

    def _unwrap_base64_payloads(self, text: str) -> str:
        """Find and decode potential base64 tokens embedded in the prompt for deep inspection."""
        b64_tokens = re.findall(r'\b[a-zA-Z0-9+/]{20,}={0,2}\b', text)
        unwrapped_parts = [text]
        for tok in b64_tokens:
            try:
                decoded = base64.b64decode(tok).decode("utf-8", errors="ignore")
                if len(decoded) > 10:
                    unwrapped_parts.append(decoded)
            except Exception:
                pass
        return " ".join(unwrapped_parts)

    def inspect_prompt(self, req: PromptInspectionRequest) -> PromptInspectionResponse:
        """Scan prompt for injection attacks, jailbreaks, and unicode evasion."""
        start_time = time.perf_counter()
        self.total_scans += 1

        # 1. Unicode Evasion Check
        clean_text, unicode_evasion = self._strip_unicode_evasion(req.prompt_text)
        if unicode_evasion:
            # Check if after stripping unicode, it triggers an injection
            pass

        # 2. Base64 Unwrapping
        full_inspect_text = self._unwrap_base64_payloads(clean_text)

        # 3. Signature Matching
        for category, (pat, mitre_atlas, desc) in self.INJECTION_SIGNATURES.items():
            match = pat.search(full_inspect_text)
            if match:
                self.blocked_injections_counter += 1
                if category == LLMThreatCategory.JAILBREAK_ROLEPLAY_OVERRIDE:
                    self.jailbreak_counter += 1

                alert = LLMGuardrailAlert(
                    alert_id=f"llm-{uuid.uuid4().hex[:8]}",
                    category=category,
                    severity="HIGH",
                    mitre_atlas_technique=mitre_atlas,
                    action_enforced=GuardrailAction.BLOCK_REQUEST,
                    raw_trigger_snippet=match.group(0),
                    details=desc,
                    countermeasure="Block input prompt and return sanitized corporate policy refusal message.",
                )
                self.alerts.append(alert)
                duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

                return PromptInspectionResponse(
                    is_safe=False,
                    detected_threat=category,
                    action_taken=GuardrailAction.BLOCK_REQUEST,
                    sanitized_prompt="[REQUEST BLOCKED: Security Guardrail Policy Violation]",
                    alert=alert,
                    latency_ms=duration_ms,
                )

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return PromptInspectionResponse(
            is_safe=True,
            detected_threat=None,
            action_taken=GuardrailAction.AUDIT_ONLY,
            sanitized_prompt=clean_text,
            alert=None,
            latency_ms=duration_ms,
        )

    def inspect_completion(self, req: CompletionInspectionRequest) -> CompletionInspectionResponse:
        """Scan model output for system prompt canary leaks or weaponized exploit payload generation."""
        comp = req.completion_text

        # 1. Secret Canary Leak Check
        if req.system_prompt_canary and req.system_prompt_canary in comp:
            self.canary_leaks_counter += 1
            alert = LLMGuardrailAlert(
                alert_id=f"llm-canary-{uuid.uuid4().hex[:8]}",
                category=LLMThreatCategory.CANARY_TOKEN_LEAK,
                severity="CRITICAL",
                mitre_atlas_technique="AML.T0043 - Model Extraction: Canary Exfiltration",
                action_enforced=GuardrailAction.BLOCK_REQUEST,
                raw_trigger_snippet=req.system_prompt_canary,
                details="Model completion contained confidential system prompt canary token! Exfiltration blocked.",
                countermeasure="Drop completion stream immediately and redact confidential canary.",
            )
            self.alerts.append(alert)

            return CompletionInspectionResponse(
                is_safe=False,
                detected_threat=LLMThreatCategory.CANARY_TOKEN_LEAK,
                canary_leaked=True,
                alert=alert,
                sanitized_completion="[RESPONSE SUPPRESSED: System Prompt Confidentiality Policy Enforced]",
            )

        # 2. Weaponized Exploit Code Check
        for exp_pat in self.EXPLOIT_PATTERNS:
            match = exp_pat.search(comp)
            if match:
                alert = LLMGuardrailAlert(
                    alert_id=f"llm-exploit-{uuid.uuid4().hex[:8]}",
                    category=LLMThreatCategory.WEAPONIZED_EXPLOIT_OUTPUT,
                    severity="CRITICAL",
                    mitre_atlas_technique="AML.T0048 - Harmful Output Generation: Weaponized Exploit",
                    action_enforced=GuardrailAction.BLOCK_REQUEST,
                    raw_trigger_snippet=match.group(0),
                    details="LLM output generated weaponized shellcode / reverse shell one-liner payload.",
                    countermeasure="Suppress response and record model safety telemetry.",
                )
                self.alerts.append(alert)

                return CompletionInspectionResponse(
                    is_safe=False,
                    detected_threat=LLMThreatCategory.WEAPONIZED_EXPLOIT_OUTPUT,
                    canary_leaked=False,
                    alert=alert,
                    sanitized_completion="[RESPONSE SUPPRESSED: Malicious Exploit Code Synthesis Prohibited]",
                )

        return CompletionInspectionResponse(
            is_safe=True,
            detected_threat=None,
            canary_leaked=False,
            alert=None,
            sanitized_completion=comp,
        )

    def get_metrics(self) -> LLMGuardrailMetrics:
        """Retrieve overall LLM defense metrics."""
        return LLMGuardrailMetrics(
            total_prompts_scanned=self.total_scans,
            total_injections_blocked=self.blocked_injections_counter,
            jailbreak_attempts_stopped=self.jailbreak_counter,
            canary_leaks_prevented=self.canary_leaks_counter,
            active_firewall_status="ACTIVE_DEFENSE_OPTIMAL",
        )
