"""
CyberShield Enterprise - Detection & Threat Classification REST Endpoints
Provides APIs for Sigma & YARA rule inspection, custom rule creation,
dry-run condition testing, and detection KPI analytics.
"""

from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.session import get_db
from cybershield.auth.dependencies import get_current_user, require_role, require_permission
from cybershield.database.models.user import User
from cybershield.database.models.role import UserRole, Permission
from cybershield.audit.service import AuditService
from cybershield.detection.service import detection_rule_service

router = APIRouter(prefix="/api/detection", tags=["Threat Detection & Rules"])


# Pydantic Schemas
class CreateRuleRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=256)
    description: str = Field(..., min_length=5)
    rule_type: str = Field(default="SIGMA", pattern="^(SIGMA|YARA)$")
    severity: str = Field(default="MEDIUM", pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$")
    raw_content: str = Field(..., min_length=10)


class TestRuleRequest(BaseModel):
    rule_type: str = Field(default="SIGMA", pattern="^(SIGMA|YARA)$")
    raw_content: str = Field(..., min_length=10)
    test_payload: Dict[str, Any] = Field(default_factory=dict)


@router.get("/rules")
async def list_detection_rules(
    rule_type: Optional[str] = Query("ALL"),
    severity: Optional[str] = Query("ALL"),
    is_enabled: Optional[bool] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve paginated detection rules catalog."""
    return await detection_rule_service.list_rules(
        session=db,
        rule_type=rule_type,
        severity=severity,
        is_enabled=is_enabled,
        search=search,
        page=page,
        page_size=page_size,
    )


@router.get("/rules/{rule_id}")
async def get_detection_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get full details of a specific detection rule."""
    rule = await detection_rule_service.get_rule_by_id(db, rule_id)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found")
    return rule.to_dict()


@router.post("/rules", status_code=status.HTTP_201_CREATED)
async def create_detection_rule(
    req: CreateRuleRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RULES_MANAGE)),
):
    """Create a new custom Sigma or YARA detection rule."""
    try:
        rule = await detection_rule_service.create_custom_rule(
            session=db,
            name=req.name,
            description=req.description,
            rule_type=req.rule_type,
            raw_content=req.raw_content,
            severity=req.severity,
            author=current_user.username,
        )

        await AuditService.log_event(
            db=db,
            action="CREATE_DETECTION_RULE",
            resource=f"rule:{rule.id}",
            username=current_user.username,
            user_id=current_user.id,
            details={"rule_type": rule.rule_type, "name": rule.name, "severity": rule.severity},
            status="SUCCESS",
        )
        return rule.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/rules/{rule_id}/toggle")
async def toggle_detection_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RULES_MANAGE)),
):
    """Enable or disable a detection rule."""
    rule = await detection_rule_service.toggle_rule(db, rule_id)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found")

    await AuditService.log_event(
        db=db,
        action="TOGGLE_DETECTION_RULE",
        resource=f"rule:{rule.id}",
        username=current_user.username,
        user_id=current_user.id,
        details={"is_enabled": rule.is_enabled},
        status="SUCCESS",
    )
    return rule.to_dict()


@router.post("/rules/test")
async def dry_run_test_rule(
    req: TestRuleRequest,
    current_user: User = Depends(get_current_user),
):
    """Dry-run test a rule definition against a mock telemetry payload."""
    return await detection_rule_service.dry_run_test_rule(
        raw_content=req.raw_content,
        rule_type=req.rule_type,
        test_payload=req.test_payload,
    )


@router.get("/kpis")
async def get_detection_kpis(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve operational detection rules metrics."""
    return await detection_rule_service.get_detection_kpis(db)
