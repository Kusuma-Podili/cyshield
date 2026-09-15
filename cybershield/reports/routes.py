"""REST API Endpoints for Enterprise Report Generation."""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.session import get_db
from cybershield.database.models import User, Permission
from cybershield.auth.dependencies import require_permission
from cybershield.reports.service import ReportGeneratorService
from cybershield.reports.schemas import (
    ReportGenerateRequest,
    ReportSummaryResponse,
    ReportDetailResponse,
)

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.post(
    "/generate",
    response_model=ReportDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a publication-grade enterprise security report",
)
async def generate_report(
    req: ReportGenerateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REPORTS_GENERATE)),
):
    """Compile telemetry into HTML, JSON, or CSV and archive in persistent storage."""
    report = await ReportGeneratorService.generate_report(
        db=db,
        report_type_str=req.report_type,
        format_str=req.format,
        title=req.title,
        parameters=req.parameters,
        actor=current_user.username,
    )
    return report.to_dict(include_content=True)


@router.get(
    "",
    summary="List all archived generated reports",
)
async def list_reports(
    report_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REPORTS_VIEW)),
):
    """Retrieve paginated index of generated executive summaries and audit attestations."""
    offset = (page - 1) * page_size
    items, total = await ReportGeneratorService.list_reports(
        db, limit=page_size, offset=offset, report_type=report_type
    )
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get(
    "/{report_id}",
    response_model=ReportDetailResponse,
    summary="Get full report details and rendered HTML",
)
async def get_report_detail(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REPORTS_VIEW)),
):
    """Retrieve full content, metrics, and rendered HTML for viewing in the SOC console."""
    report = await ReportGeneratorService.get_report_by_id(db, report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    return report


@router.get(
    "/{report_id}/download",
    summary="Download report content as file attachment",
)
async def download_report_file(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REPORTS_DOWNLOAD)),
):
    """Download the raw HTML or JSON payload as an attachment."""
    report = await ReportGeneratorService.get_report_by_id(db, report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")

    fmt = report.get("format", "HTML")
    if fmt == "HTML":
        media_type = "text/html"
        filename = f"{report_id}.html"
        content = report.get("content_html", "")
    elif fmt == "JSON":
        media_type = "application/json"
        filename = f"{report_id}.json"
        content = str(report.get("raw_data", {}))
    else:
        media_type = "text/plain"
        filename = f"{report_id}.txt"
        content = report.get("summary", "")

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
