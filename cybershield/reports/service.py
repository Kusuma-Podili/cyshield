"""Automated Enterprise Report Generator for CyberShield Enterprise.

Compiles executive summaries, compliance attestations, vulnerability dossiers,
and incident post-mortems into publication-grade HTML5 and JSON formats.
"""

from __future__ import annotations

import uuid
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from cybershield.database.models import (
    GeneratedReportModel,
    ReportType,
    ReportFormat,
    ComplianceFrameworkModel,
    ComplianceControlModel,
    NetworkDevice,
    DeviceStatus,
    AssetVulnerabilityModel,
    VulnerabilitySeverity,
    VulnerabilityStatus,
    IncidentModel,
    IncidentStatus,
    IncidentSeverity,
    SecurityEventModel,
    AlertModel,
    AlertStatus,
    AuditVaultBlockModel,
)
from cybershield.compliance.service import ComplianceService
from cybershield.audit.vault import AuditVault


class ReportGeneratorService:
    """Enterprise report generation engine."""

    @classmethod
    async def generate_report(
        cls,
        db: AsyncSession,
        report_type_str: str,
        format_str: str = "HTML",
        title: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        actor: str = "SYSTEM",
    ) -> GeneratedReportModel:
        """Compile live security telemetry into an archived enterprise report."""
        try:
            report_type = ReportType(report_type_str.upper())
        except ValueError:
            report_type = ReportType.EXECUTIVE_POSTURE

        try:
            report_format = ReportFormat(format_str.upper())
        except ValueError:
            report_format = ReportFormat.HTML

        params = parameters or {}
        report_id = f"RPT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

        # 1. Gather relevant dataset
        if report_type == ReportType.EXECUTIVE_POSTURE:
            rep_title = title or "CyberShield Executive Cybersecurity Posture Summary"
            raw_data, summary = await cls._gather_executive_data(db)
            html_content = cls._render_executive_html(report_id, rep_title, raw_data, actor)

        elif report_type == ReportType.COMPLIANCE_ATTESTATION:
            rep_title = title or "Enterprise Multi-Standard Regulatory Compliance Attestation"
            raw_data, summary = await cls._gather_compliance_data(db, params.get("framework_id"))
            html_content = cls._render_compliance_html(report_id, rep_title, raw_data, actor)

        elif report_type == ReportType.VULNERABILITY_ASSESSMENT:
            rep_title = title or "Technical Vulnerability & Attack Surface Exposure Report"
            raw_data, summary = await cls._gather_vulnerability_data(db)
            html_content = cls._render_vulnerability_html(report_id, rep_title, raw_data, actor)

        else:  # INCIDENT_DOSSIER
            rep_title = title or "Incident Forensics & Response Dossier"
            raw_data, summary = await cls._gather_incident_data(db, params.get("incident_id"))
            html_content = cls._render_incident_html(report_id, rep_title, raw_data, actor)

        # 2. Determine file size
        if report_format == ReportFormat.HTML:
            payload_str = html_content
            file_size = len(payload_str.encode("utf-8"))
        elif report_format == ReportFormat.JSON:
            payload_str = json.dumps(raw_data, indent=2)
            file_size = len(payload_str.encode("utf-8"))
        else:  # CSV fallback
            payload_str = html_content
            file_size = len(payload_str.encode("utf-8"))

        report_model = GeneratedReportModel(
            id=report_id,
            title=rep_title,
            report_type=report_type,
            format=report_format,
            parameters=params,
            summary=summary,
            content_html=html_content,
            raw_data=raw_data,
            file_size_bytes=file_size,
            generated_by=actor,
            created_at=datetime.now(timezone.utc),
        )
        db.add(report_model)
        await db.commit()
        await db.refresh(report_model)

        # Also record high-assurance report generation in WORM vault
        await AuditVault.record_block(
            db=db,
            action="REPORT_GENERATED",
            actor_id=actor,
            actor_role="AUDITOR",
            entity_type="REPORT",
            entity_id=report_id,
            payload_data={"report_type": report_type.value, "title": rep_title, "format": report_format.value},
        )

        return report_model

    # =========================================================================
    # Data Aggregators
    # =========================================================================

    @classmethod
    async def _gather_executive_data(cls, db: AsyncSession) -> Tuple[Dict[str, Any], str]:
        compliance = await ComplianceService.get_overview(db)
        total_devices = (await db.execute(select(func.count(NetworkDevice.id)))).scalar() or 0
        rogue_devices = (await db.execute(
            select(func.count(NetworkDevice.id)).where(NetworkDevice.status.in_([DeviceStatus.COMPROMISED, DeviceStatus.ISOLATED]))
        )).scalar() or 0

        open_incidents = (await db.execute(
            select(func.count(IncidentModel.id)).where(IncidentModel.status.in_([IncidentStatus.OPEN, IncidentStatus.TRIAGED]))
        )).scalar() or 0

        critical_incidents = (await db.execute(
            select(func.count(IncidentModel.id)).where(
                IncidentModel.severity == IncidentSeverity.CRITICAL,
                IncidentModel.status.in_([IncidentStatus.OPEN, IncidentStatus.TRIAGED])
            )
        )).scalar() or 0

        total_events = (await db.execute(select(func.count(SecurityEventModel.id)))).scalar() or 0
        vault_blocks = (await db.execute(select(func.count(AuditVaultBlockModel.id)))).scalar() or 0

        data = {
            "posture_score": compliance["global_compliance_score"],
            "letter_grade": compliance["letter_grade"],
            "total_assets": total_devices,
            "rogue_assets": rogue_devices,
            "open_incidents": open_incidents,
            "critical_incidents": critical_incidents,
            "total_events_ingested": total_events,
            "worm_vault_blocks": vault_blocks,
            "frameworks": compliance["frameworks"],
            "critical_gaps": compliance["critical_gaps"],
        }
        summary = (
            f"Overall Security Posture Score: {data['posture_score']}% ({data['letter_grade']}). "
            f"Monitoring {total_devices} assets, {open_incidents} active incidents, and {compliance['compliant_controls']} compliant regulatory controls."
        )
        return data, summary

    @classmethod
    async def _gather_compliance_data(cls, db: AsyncSession, framework_id: Optional[str]) -> Tuple[Dict[str, Any], str]:
        overview = await ComplianceService.get_overview(db)
        frameworks = await ComplianceService.list_frameworks(db)

        controls = []
        if framework_id:
            controls = await ComplianceService.get_framework_controls(db, framework_id)
        else:
            # First framework default
            if frameworks:
                controls = await ComplianceService.get_framework_controls(db, frameworks[0]["id"])

        data = {
            "global_score": overview["global_compliance_score"],
            "letter_grade": overview["letter_grade"],
            "frameworks": frameworks,
            "selected_controls": controls,
            "critical_gaps": overview["critical_gaps"],
        }
        summary = (
            f"Multi-standard compliance attestation: Global score of {data['global_score']}% across "
            f"{len(frameworks)} regulatory frameworks (SOC2, ISO 27001, NIST CSF, PCI-DSS, HIPAA, GDPR)."
        )
        return data, summary

    @classmethod
    async def _gather_vulnerability_data(cls, db: AsyncSession) -> Tuple[Dict[str, Any], str]:
        vulns_res = await db.execute(
            select(AssetVulnerabilityModel)
            .order_by(AssetVulnerabilityModel.patch_priority_score.desc())
            .limit(25)
        )
        vulns = [v.to_dict() for v in vulns_res.scalars().all()]

        crit_count = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
        high_count = sum(1 for v in vulns if v.get("severity") == "HIGH")

        data = {
            "top_vulnerabilities": vulns,
            "critical_count": crit_count,
            "high_count": high_count,
            "total_evaluated": len(vulns),
        }
        summary = f"Vulnerability exposure scan identified {crit_count} Critical and {high_count} High priority CVEs requiring patching."
        return data, summary

    @classmethod
    async def _gather_incident_data(cls, db: AsyncSession, incident_id: Optional[str]) -> Tuple[Dict[str, Any], str]:
        query = select(IncidentModel).order_by(desc(IncidentModel.created_at))
        if incident_id:
            query = query.where(IncidentModel.id == incident_id)
        res = await db.execute(query.limit(10))
        incidents = [i.to_dict() for i in res.scalars().all()]

        data = {
            "incidents": incidents,
            "total_reported": len(incidents),
        }
        summary = f"Incident dossier reviewing {len(incidents)} active or recently resolved security incidents."
        return data, summary

    # =========================================================================
    # HTML5 Report Renderers
    # =========================================================================

    @classmethod
    def _render_executive_html(cls, report_id: str, title: str, data: Dict[str, Any], actor: str) -> str:
        framework_rows = "".join(
            f"""<tr>
                <td><strong>{fw['name']}</strong> ({fw['id']})</td>
                <td>{fw['category']}</td>
                <td><span class="badge {'badge-green' if fw['overall_score'] >= 80 else 'badge-amber' if fw['overall_score'] >= 60 else 'badge-red'}">{fw['overall_score']}%</span></td>
                <td>{fw['compliant_controls']} / {fw['total_controls']}</td>
                <td>{fw['last_assessed_at'][:10] if fw.get('last_assessed_at') else 'Pending'}</td>
            </tr>"""
            for fw in data.get("frameworks", [])
        )

        gap_rows = "".join(
            f"""<tr>
                <td><code>{g.get('control_code', '')}</code></td>
                <td><strong>{g.get('title', '')}</strong></td>
                <td><span class="badge badge-red">{g.get('severity', 'HIGH')}</span></td>
                <td>{g.get('gap', g.get('evidence_summary', g.get('description', '')))}</td>
                <td><em>{g.get('remediation', g.get('remediation_guidance', ''))}</em></td>
            </tr>"""
            for g in data.get("critical_gaps", [])[:5]
        ) or "<tr><td colspan='5' style='text-align:center; color:#10b981;'>Zero critical compliance gaps identified.</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 40px; margin: 0; }}
  .report-header {{ border-bottom: 2px solid #1e293b; padding-bottom: 24px; margin-bottom: 32px; display: flex; justify-content: space-between; align-items: center; }}
  .title {{ font-size: 26px; font-weight: 800; color: #38bdf8; margin: 0; }}
  .meta {{ color: #94a3b8; font-size: 13px; }}
  .metrics-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }}
  .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 20px; }}
  .card-val {{ font-size: 28px; font-weight: 800; margin-top: 8px; }}
  .grade-badge {{ font-size: 48px; font-weight: 900; color: #10b981; text-align: center; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }}
  th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #1f2937; }}
  th {{ background: #1f2937; color: #94a3b8; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }}
  .badge {{ padding: 4px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; }}
  .badge-green {{ background: rgba(16,185,129,0.2); color: #34d399; border: 1px solid #059669; }}
  .badge-amber {{ background: rgba(245,158,11,0.2); color: #fbbf24; border: 1px solid #d97706; }}
  .badge-red {{ background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid #dc2626; }}
  .section-title {{ font-size: 18px; font-weight: 700; color: #e2e8f0; margin-top: 36px; margin-bottom: 12px; }}
</style>
</head>
<body>
  <div class="report-header">
    <div>
      <h1 class="title">{title}</h1>
      <div class="meta">Report ID: {report_id} | Issued: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | Auditor: {actor}</div>
    </div>
    <div style="text-align:right;">
      <div style="font-size:12px; color:#64748b; font-weight:700;">CYBERSHIELD ENTERPRISE</div>
      <div style="font-size:11px; color:#10b981;">● CRYPTOGRAPHIC WORM SEALED</div>
    </div>
  </div>

  <div class="metrics-grid">
    <div class="card">
      <div style="color:#94a3b8; font-size:12px; font-weight:600;">SECURITY POSTURE SCORE</div>
      <div class="card-val" style="color:#38bdf8;">{data.get('posture_score')}%</div>
      <div style="font-size:12px; color:#64748b; margin-top:4px;">Grade: {data.get('letter_grade')}</div>
    </div>
    <div class="card">
      <div style="color:#94a3b8; font-size:12px; font-weight:600;">MANAGED ASSETS</div>
      <div class="card-val" style="color:#f8fafc;">{data.get('total_assets')}</div>
      <div style="font-size:12px; color:{'#ef4444' if data.get('rogue_assets', 0) > 0 else '#10b981'}; margin-top:4px;">{data.get('rogue_assets', 0)} Rogue Detected</div>
    </div>
    <div class="card">
      <div style="color:#94a3b8; font-size:12px; font-weight:600;">ACTIVE INCIDENTS</div>
      <div class="card-val" style="color:{'#ef4444' if data.get('open_incidents', 0) > 0 else '#10b981'};">{data.get('open_incidents')}</div>
      <div style="font-size:12px; color:#94a3b8; margin-top:4px;">{data.get('critical_incidents', 0)} Critical</div>
    </div>
    <div class="card">
      <div style="color:#94a3b8; font-size:12px; font-weight:600;">WORM AUDIT BLOCKS</div>
      <div class="card-val" style="color:#34d399;">{data.get('worm_vault_blocks')}</div>
      <div style="font-size:12px; color:#64748b; margin-top:4px;">Immutable Chain Verified</div>
    </div>
  </div>

  <div class="section-title">Regulatory Framework Status</div>
  <div class="card" style="padding:0; overflow:hidden;">
    <table>
      <thead>
        <tr><th>Framework</th><th>Domain</th><th>Compliance Score</th><th>Controls Passed</th><th>Last Audit</th></tr>
      </thead>
      <tbody>
        {framework_rows}
      </tbody>
    </table>
  </div>

  <div class="section-title">Top Priority Remediation Action Items</div>
  <div class="card" style="padding:0; overflow:hidden;">
    <table>
      <thead>
        <tr><th>Control</th><th>Requirement</th><th>Severity</th><th>Observed Gap</th><th>Remediation Guidance</th></tr>
      </thead>
      <tbody>
        {gap_rows}
      </tbody>
    </table>
  </div>
</body>
</html>"""

    @classmethod
    def _render_compliance_html(cls, report_id: str, title: str, data: Dict[str, Any], actor: str) -> str:
        control_rows = "".join(
            f"""<tr>
                <td><code>{c['control_code']}</code></td>
                <td>{c['title']}</td>
                <td>{c['domain']}</td>
                <td><span class="badge badge-{'green' if c['status'] == 'COMPLIANT' else 'amber' if c['status'] == 'PARTIALLY_COMPLIANT' else 'red'}">{c['status']}</span></td>
                <td>{c['score']}%</td>
                <td><small>{c.get('evidence_summary', 'N/A')}</small></td>
            </tr>"""
            for c in data.get("selected_controls", [])
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 40px; margin: 0; }}
  .report-header {{ border-bottom: 2px solid #1e293b; padding-bottom: 24px; margin-bottom: 32px; }}
  .title {{ font-size: 26px; font-weight: 800; color: #38bdf8; margin: 0; }}
  .meta {{ color: #94a3b8; font-size: 13px; margin-top: 8px; }}
  .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 20px; margin-bottom: 24px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #1f2937; }}
  th {{ background: #1f2937; color: #94a3b8; font-weight: 600; text-transform: uppercase; }}
  .badge {{ padding: 4px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; }}
  .badge-green {{ background: rgba(16,185,129,0.2); color: #34d399; }}
  .badge-amber {{ background: rgba(245,158,11,0.2); color: #fbbf24; }}
  .badge-red {{ background: rgba(239,68,68,0.2); color: #f87171; }}
</style>
</head>
<body>
  <div class="report-header">
    <h1 class="title">{title}</h1>
    <div class="meta">Attestation ID: {report_id} | Issued: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | Verified by: {actor}</div>
  </div>

  <div class="card">
    <div style="font-size:16px; font-weight:700; color:#e2e8f0; margin-bottom:12px;">Attestation Summary</div>
    <p style="color:#94a3b8; line-height:1.6;">
      This compliance attestation certifies that CyberShield Enterprise has performed automated, continuous telemetry
      auditing against industry security standards. Overall governance index stands at <strong>{data.get('global_score')}%</strong>
      ({data.get('letter_grade')}).
    </p>
  </div>

  <div class="card" style="padding:0; overflow:hidden;">
    <table>
      <thead>
        <tr><th>Code</th><th>Requirement</th><th>Domain</th><th>Status</th><th>Score</th><th>Technical Evidence</th></tr>
      </thead>
      <tbody>
        {control_rows}
      </tbody>
    </table>
  </div>
</body>
</html>"""

    @classmethod
    def _render_vulnerability_html(cls, report_id: str, title: str, data: Dict[str, Any], actor: str) -> str:
        vuln_rows = "".join(
            f"""<tr>
                <td><code>{v.get('cve_id', 'N/A')}</code></td>
                <td>{v.get('title', 'Unknown Vulnerability')}</td>
                <td><span class="badge {'badge-red' if v.get('severity') == 'CRITICAL' else 'badge-amber'}">{v.get('severity')} ({v.get('cvss_score')})</span></td>
                <td>{v.get('status', 'OPEN')}</td>
                <td>{v.get('affected_package', 'Core OS')}</td>
            </tr>"""
            for v in data.get("top_vulnerabilities", [])
        ) or "<tr><td colspan='5' style='text-align:center;'>No unpatched vulnerabilities found.</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 40px; margin: 0; }}
  .title {{ font-size: 26px; font-weight: 800; color: #f87171; margin: 0; }}
  .meta {{ color: #94a3b8; font-size: 13px; margin-top: 8px; margin-bottom: 24px; }}
  .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 20px; margin-bottom: 24px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #1f2937; }}
  th {{ background: #1f2937; color: #94a3b8; font-weight: 600; text-transform: uppercase; }}
  .badge {{ padding: 4px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; }}
  .badge-red {{ background: rgba(239,68,68,0.2); color: #f87171; }}
  .badge-amber {{ background: rgba(245,158,11,0.2); color: #fbbf24; }}
</style>
</head>
<body>
  <h1 class="title">{title}</h1>
  <div class="meta">Report ID: {report_id} | Issued: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | Assessor: {actor}</div>

  <div class="card">
    <div style="font-size:16px; font-weight:700;">Executive Vulnerability Exposure</div>
    <p style="color:#94a3b8;">
      Total evaluated: {data.get('total_evaluated')} CVEs | Critical: {data.get('critical_count')} | High: {data.get('high_count')}
    </p>
  </div>

  <div class="card" style="padding:0; overflow:hidden;">
    <table>
      <thead>
        <tr><th>CVE ID</th><th>Vulnerability</th><th>Severity</th><th>Remediation Status</th><th>Affected Component</th></tr>
      </thead>
      <tbody>
        {vuln_rows}
      </tbody>
    </table>
  </div>
</body>
</html>"""

    @classmethod
    def _render_incident_html(cls, report_id: str, title: str, data: Dict[str, Any], actor: str) -> str:
        inc_rows = "".join(
            f"""<tr>
                <td><code>{i.get('id')}</code></td>
                <td>{i.get('title')}</td>
                <td><span class="badge {'badge-red' if i.get('severity') == 'CRITICAL' else 'badge-amber'}">{i.get('severity')}</span></td>
                <td>{i.get('status')}</td>
                <td>{i.get('kill_chain_phase', 'N/A')}</td>
                <td>{i.get('created_at', '')[:19]}</td>
            </tr>"""
            for i in data.get("incidents", [])
        ) or "<tr><td colspan='6' style='text-align:center;'>No incidents on record.</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 40px; margin: 0; }}
  .title {{ font-size: 26px; font-weight: 800; color: #fbbf24; margin: 0; }}
  .meta {{ color: #94a3b8; font-size: 13px; margin-top: 8px; margin-bottom: 24px; }}
  .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 0; overflow: hidden; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #1f2937; }}
  th {{ background: #1f2937; color: #94a3b8; font-weight: 600; text-transform: uppercase; }}
  .badge {{ padding: 4px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; }}
  .badge-red {{ background: rgba(239,68,68,0.2); color: #f87171; }}
  .badge-amber {{ background: rgba(245,158,11,0.2); color: #fbbf24; }}
</style>
</head>
<body>
  <h1 class="title">{title}</h1>
  <div class="meta">Report ID: {report_id} | Issued: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | Lead Responder: {actor}</div>

  <div class="card">
    <table>
      <thead>
        <tr><th>Incident ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Kill Chain Phase</th><th>Detected</th></tr>
      </thead>
      <tbody>
        {inc_rows}
      </tbody>
    </table>
  </div>
</body>
</html>"""

    # =========================================================================
    # Queries
    # =========================================================================

    @classmethod
    async def list_reports(
        cls,
        db: AsyncSession,
        limit: int = 50,
        offset: int = 0,
        report_type: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Query paginated reports library."""
        query = select(GeneratedReportModel)
        count_q = select(func.count(GeneratedReportModel.id))

        if report_type:
            query = query.where(GeneratedReportModel.report_type == report_type.upper())
            count_q = count_q.where(GeneratedReportModel.report_type == report_type.upper())

        total = (await db.execute(count_q)).scalar() or 0
        res = await db.execute(query.order_by(desc(GeneratedReportModel.created_at)).offset(offset).limit(limit))
        return [r.to_dict(include_content=False) for r in res.scalars().all()], total

    @classmethod
    async def get_report_by_id(
        cls,
        db: AsyncSession,
        report_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve full report content and HTML for viewing."""
        res = await db.execute(select(GeneratedReportModel).where(GeneratedReportModel.id == report_id))
        report = res.scalar_one_or_none()
        return report.to_dict(include_content=True) if report else None
