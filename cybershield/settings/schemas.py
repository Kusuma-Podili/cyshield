"""Pydantic Schemas for Platform Configuration Settings."""

from __future__ import annotations

from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class SettingResponse(BaseModel):
    key: str
    category: str
    display_name: str
    description: str
    value_type: str
    value: Any
    raw_value: str
    default_value: str
    is_secret: bool
    requires_restart: bool
    updated_by: str
    updated_at: Optional[str] = None


class SettingUpdateRequest(BaseModel):
    value: str = Field(..., description="New value serialized as string")


class CategoryGroupResponse(BaseModel):
    category: str
    display_name: str
    settings: List[SettingResponse]
