"""REST API Endpoints for Platform Settings & Runtime Configuration."""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.session import get_db
from cybershield.database.models import User, Permission
from cybershield.auth.dependencies import require_permission
from cybershield.settings.manager import SettingsManager
from cybershield.settings.schemas import (
    SettingResponse,
    SettingUpdateRequest,
    CategoryGroupResponse,
)

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get(
    "",
    response_model=List[SettingResponse],
    summary="List all dynamic platform configuration parameters",
)
async def list_settings(
    category: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SETTINGS_VIEW)),
):
    """Retrieve runtime settings for security policy, detection thresholds, retention, and ML."""
    settings = await SettingsManager.list_settings(db, category=category)
    return [SettingResponse(**s) for s in settings]


@router.get(
    "/{key}",
    response_model=SettingResponse,
    summary="Get single platform setting by key",
)
async def get_setting(
    key: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SETTINGS_VIEW)),
):
    """Retrieve single configuration parameter."""
    setting = await SettingsManager.get_setting(db, key)
    if not setting:
        raise HTTPException(status_code=404, detail=f"Configuration setting '{key}' not found.")
    return SettingResponse(**setting)


@router.put(
    "/{key}",
    response_model=SettingResponse,
    summary="Update platform configuration setting",
)
async def update_setting(
    key: str,
    req: SettingUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SETTINGS_EDIT)),
):
    """Update setting value and write an immutable audit block to the WORM ledger."""
    try:
        updated = await SettingsManager.update_setting(
            db, key=key, value_str=req.value, actor=current_user.username
        )
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))

    if not updated:
        raise HTTPException(status_code=404, detail=f"Configuration setting '{key}' not found.")
    return SettingResponse(**updated)


@router.post(
    "/{key}/reset",
    response_model=SettingResponse,
    summary="Reset platform setting to factory default",
)
async def reset_setting(
    key: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SETTINGS_MANAGE)),
):
    """Reset configuration parameter back to its built-in default value."""
    reset = await SettingsManager.reset_setting(db, key=key, actor=current_user.username)
    if not reset:
        raise HTTPException(status_code=404, detail=f"Configuration setting '{key}' not found.")
    return SettingResponse(**reset)
