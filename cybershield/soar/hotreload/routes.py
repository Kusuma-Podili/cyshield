"""CyberShield Enterprise - SOAR Playbook Hot-Reload API Routes.
Exposes endpoints for dynamic Python playbook compilation, AST validation,
natural language code synthesis, sandboxed execution, and version rollback.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    PlaybookTriggerType,
    DynamicPlaybookSpec,
    ASTValidationResult,
    PlaybookExecutionResult,
    HotReloadRegistryMetrics,
)
from .sandbox import PlaybookHotReloadManager

router = APIRouter(prefix="/api/v1/soar/hotreload", tags=["SOAR Dynamic Playbooks & Hot-Reload"])

# Active singleton hot-reload manager
_HOT_RELOAD_MGR = PlaybookHotReloadManager()


@router.post("/compile", response_model=ASTValidationResult, status_code=status.HTTP_201_CREATED)
def compile_playbook(spec: DynamicPlaybookSpec):
    """Compile, AST validate, and hot-reload a dynamic Python security playbook."""
    res = _HOT_RELOAD_MGR.compile_and_register(spec)
    if not res.is_safe:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Playbook rejected by security AST validator.",
                "violations": res.detected_violations,
            },
        )
    return res


@router.post("/synthesize")
def synthesize_code(
    intent: str = Query(..., description="Natural language incident response objective"),
    trigger_type: PlaybookTriggerType = Query(PlaybookTriggerType.ALERT_SEVERITY),
):
    """Automatically synthesize safe, executable Python playbook code from prompt."""
    code = _HOT_RELOAD_MGR.synthesize_playbook_code(intent=intent, trigger_type=trigger_type)
    return {
        "status": "synthesized",
        "intent": intent,
        "trigger_type": trigger_type.value,
        "python_source_code": code,
    }


@router.post("/execute/{playbook_id}", response_model=PlaybookExecutionResult)
def execute_playbook(
    playbook_id: str,
    context: Dict[str, Any],
):
    """Execute active version of dynamic playbook within restricted sandbox runtime."""
    try:
        return _HOT_RELOAD_MGR.execute_playbook(playbook_id=playbook_id, context=context)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/rollback/{playbook_id}", response_model=DynamicPlaybookSpec)
def rollback_playbook(playbook_id: str):
    """Roll back active playbook to its immediately preceding version."""
    try:
        return _HOT_RELOAD_MGR.rollback(playbook_id=playbook_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/playbooks", response_model=List[DynamicPlaybookSpec])
def list_playbooks():
    """Retrieve all active dynamic hot-loaded playbooks."""
    return list(_HOT_RELOAD_MGR.active_playbooks.values())


@router.get("/metrics", response_model=HotReloadRegistryMetrics)
def get_metrics():
    """Retrieve hot-reload compilation, sandbox rejection, and execution metrics."""
    return _HOT_RELOAD_MGR.get_metrics()
