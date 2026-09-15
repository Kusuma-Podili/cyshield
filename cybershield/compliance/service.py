"""Compliance Management Service for CyberShield Enterprise."""

from __future__ import annotations

from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from cybershield.database.models.compliance import (
    ComplianceFrameworkModel,
    ComplianceControlModel,
    ComplianceAssessmentModel,
    ComplianceStatus,
)
from cybershield.compliance.engine import ComplianceEngine


class ComplianceService:
    """Enterprise service for auditing regulatory frameworks and controls."""

    @classmethod
    async def get_overview(cls, db: AsyncSession) -> Dict[str, Any]:
        """Calculate global cross-framework posture, letter grade, and remediation gaps."""
        await ComplianceEngine.seed_frameworks_if_empty(db)

        fw_res = await db.execute(select(ComplianceFrameworkModel).order_by(ComplianceFrameworkModel.id))
        frameworks = fw_res.scalars().all()

        total_score = 0.0
        total_ctrls = 0
        total_compliant = 0
        total_partial = 0
        total_non_compliant = 0

        for fw in frameworks:
            total_score += fw.overall_score
            total_ctrls += fw.total_controls
            total_compliant += fw.compliant_controls
            total_partial += fw.partial_controls
            total_non_compliant += fw.non_compliant_controls

        avg_score = round(total_score / len(frameworks), 1) if frameworks else 100.0

        if avg_score >= 95.0:
            letter = "A+"
        elif avg_score >= 90.0:
            letter = "A"
        elif avg_score >= 80.0:
            letter = "B"
        elif avg_score >= 70.0:
            letter = "C"
        elif avg_score >= 60.0:
            letter = "D"
        else:
            letter = "F"

        # Query highest priority gaps (NON_COMPLIANT or PARTIALLY_COMPLIANT)
        gaps_query = (
            select(ComplianceControlModel)
            .where(ComplianceControlModel.status != ComplianceStatus.COMPLIANT)
            .order_by(ComplianceControlModel.score.asc())
            .limit(10)
        )
        gaps_res = await db.execute(gaps_query)
        critical_gaps = [c.to_dict() for c in gaps_res.scalars().all()]

        return {
            "global_compliance_score": avg_score,
            "letter_grade": letter,
            "frameworks": [f.to_dict() for f in frameworks],
            "total_controls": total_ctrls,
            "compliant_controls": total_compliant,
            "partial_controls": total_partial,
            "non_compliant_controls": total_non_compliant,
            "critical_gaps": critical_gaps,
        }

    @classmethod
    async def list_frameworks(cls, db: AsyncSession) -> List[Dict[str, Any]]:
        """List all supported regulatory compliance frameworks."""
        await ComplianceEngine.seed_frameworks_if_empty(db)
        res = await db.execute(select(ComplianceFrameworkModel).order_by(ComplianceFrameworkModel.id))
        return [f.to_dict() for f in res.scalars().all()]

    @classmethod
    async def get_framework_controls(
        cls,
        db: AsyncSession,
        framework_id: str,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List individual controls for a framework with optional status filter."""
        query = select(ComplianceControlModel).where(ComplianceControlModel.framework_id == framework_id.upper())
        if status:
            query = query.where(ComplianceControlModel.status == status.upper())
        query = query.order_by(ComplianceControlModel.control_code)
        res = await db.execute(query)
        return [c.to_dict() for c in res.scalars().all()]

    @classmethod
    async def list_assessments(
        cls,
        db: AsyncSession,
        framework_id: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """List historical compliance assessment runs."""
        query = select(ComplianceAssessmentModel)
        if framework_id:
            query = query.where(ComplianceAssessmentModel.framework_id == framework_id.upper())
        query = query.order_by(desc(ComplianceAssessmentModel.created_at)).limit(limit)
        res = await db.execute(query)
        return [a.to_dict() for a in res.scalars().all()]
