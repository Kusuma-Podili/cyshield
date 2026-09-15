"""CyberShield Enterprise - Autonomous LLM Guardrail & Prompt Injection Sentinel Routes.
Exposes endpoints for prompt injection inspection, LLM completion sanitization,
threat alerts, and AI firewall metrics.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    PromptInspectionRequest,
    CompletionInspectionRequest,
    PromptInspectionResponse,
    CompletionInspectionResponse,
    LLMGuardrailAlert,
    LLMGuardrailMetrics,
)
from .sentinel import LLMGuardrailSentinel

router = APIRouter(prefix="/api/v1/llmguard", tags=["LLM Guardrail & AI Security Sentinel"])

# Singleton guardrail instance
_LLM_GUARD = LLMGuardrailSentinel()


@router.post("/inspect/prompt", response_model=PromptInspectionResponse, status_code=status.HTTP_200_OK)
def inspect_user_prompt(request: PromptInspectionRequest):
    """Inspect user input or RAG document context for direct/indirect prompt injection and jailbreaks."""
    return _LLM_GUARD.inspect_prompt(request)


@router.post("/inspect/completion", response_model=CompletionInspectionResponse, status_code=status.HTTP_200_OK)
def inspect_llm_completion(request: CompletionInspectionRequest):
    """Inspect LLM generation for system prompt canary leaks or weaponized exploit synthesis."""
    return _LLM_GUARD.inspect_completion(request)


@router.get("/threats", response_model=List[LLMGuardrailAlert])
def list_llm_threat_alerts():
    """Retrieve all blocked prompt injections, jailbreak attempts, and canary leak alerts."""
    return _LLM_GUARD.alerts


@router.get("/status", response_model=LLMGuardrailMetrics)
def get_llm_firewall_status():
    """Query AI firewall operational performance and blocked threat metrics."""
    return _LLM_GUARD.get_metrics()
