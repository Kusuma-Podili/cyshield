"""SOAR Automation & Containment REST API Endpoints."""

from __future__ import annotations

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from cybershield.core.models import PlaybookExecution
from cybershield.soar.playbook import soar_engine
from cybershield.soar.actions import SOARActionRegistry

router = APIRouter(prefix="/api/v1/soar", tags=["SOAR"])


class PlaybookExecuteRequest(BaseModel):
    playbook_id: str
    target_entity: str
    context: Optional[Dict[str, Any]] = None
    executed_by: str = "SOC Analyst"


@router.get("/playbooks")
async def list_playbooks():
    """Retrieve catalog of automated containment and response playbooks."""
    pbs = soar_engine.get_all_playbooks()
    return [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "trigger_criteria": p.trigger_criteria,
            "steps_count": len(p.steps),
            "steps": p.steps,
            "author": p.author,
        }
        for p in pbs
    ]


@router.get("/executions", response_model=List[PlaybookExecution])
async def list_executions(limit: int = 50):
    """Retrieve audit history of automated and manual playbook runs."""
    return list(reversed(soar_engine.get_execution_history(limit=limit)))


@router.post("/execute", response_model=PlaybookExecution)
async def execute_playbook(payload: PlaybookExecuteRequest):
    """Execute a SOAR response playbook against an infected host, user, or IP."""
    try:
        return await soar_engine.execute_playbook(
            playbook_id=payload.playbook_id,
            target_entity=payload.target_entity,
            executed_by=payload.executed_by,
            context_vars=payload.context,
        )
    except ValueError as ex:
        raise HTTPException(status_code=404, detail=str(ex))


@router.get("/containment")
async def get_containment_status():
    """Get active network isolation, firewall blocks, and account lockouts."""
    return {
        "isolated_hosts": SOARActionRegistry.ISOLATED_HOSTS,
        "blocked_ips": SOARActionRegistry.BLOCKED_IPS,
        "revoked_users": SOARActionRegistry.REVOKED_USERS,
        "terminated_pids": SOARActionRegistry.TERMINATED_PIDS,
    }
