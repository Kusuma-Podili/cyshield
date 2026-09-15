"""Automated Enterprise Report Generation Subsystem."""

from cybershield.reports.service import ReportGeneratorService
from cybershield.reports.routes import router as reports_router

__all__ = ["ReportGeneratorService", "reports_router"]
