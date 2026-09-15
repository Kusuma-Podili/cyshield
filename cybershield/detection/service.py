"""
CyberShield Enterprise - Threat Detection & Rule Management Service
Manages Sigma & YARA rule lifecycles, executes AST condition evaluation
against telemetry event streams, and triggers automated incident synthesis.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

import yaml
from sqlalchemy import select, func, update, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.models.incidents_and_rules import (
    DetectionRuleModel,
    IncidentModel,
    IncidentTimelineModel,
    IncidentSeverity,
    IncidentStatus,
    IncidentType,
    KillChainPhase,
    RuleType,
)
from cybershield.database.models.events_and_alerts import (
    SecurityEventModel,
    AlertModel,
    AlertStatus,
    DetectionEngineType,
    EventSeverity,
)
from cybershield.engines.sigma_engine import sigma_engine, SigmaRule
from cybershield.engines.yara_engine import yara_engine
from cybershield.core.models import NormalizedEvent, LogSourceType
from cybershield.detection.correlator import attack_chain_correlator

logger = logging.getLogger("cybershield.detection.service")


class DetectionRuleService:
    """Enterprise service for Sigma/YARA detection rules and telemetry evaluation."""

    def __init__(self, rules_base_path: Optional[Path] = None):
        self.rules_base_path = rules_base_path or Path("rules")

    async def seed_rules_if_empty(self, session: AsyncSession) -> int:
        """Seed default Sigma and YARA rules into the database on startup."""
        count_stmt = select(func.count(DetectionRuleModel.id))
        total_rules = (await session.execute(count_stmt)).scalar() or 0
        if total_rules > 0:
            return 0

        seeded_count = 0
        now = datetime.utcnow()

        # 1. Seed Sigma rules from rules/sigma/
        sigma_dir = self.rules_base_path / "sigma"
        if sigma_dir.exists():
            for rule_file in sigma_dir.glob("*.y*ml"):
                try:
                    text = rule_file.read_text(encoding="utf-8")
                    doc = yaml.safe_load(text)
                    if not isinstance(doc, dict):
                        continue

                    rule_id = str(doc.get("id") or f"SIGMA-{uuid.uuid4().hex[:8].upper()}")
                    title = str(doc.get("title", rule_file.stem.replace("_", " ").title()))
                    desc = str(doc.get("description", "Enterprise Sigma threat detection signature"))
                    level = str(doc.get("level", "medium")).upper()
                    tags = doc.get("tags", [])

                    tactics = []
                    techniques = []
                    for t in tags:
                        t_lower = str(t).lower()
                        if t_lower.startswith("attack.t"):
                            techniques.append(t_lower.replace("attack.", "").upper())
                        elif t_lower.startswith("attack."):
                            tactics.append(t_lower.replace("attack.", "").replace("_", " ").title())

                    parsed_ast = {
                        "logsource": doc.get("logsource", {}),
                        "detection": doc.get("detection", {}),
                        "condition": doc.get("detection", {}).get("condition", "selection"),
                    }

                    rule_record = DetectionRuleModel(
                        id=rule_id,
                        name=title,
                        description=desc,
                        rule_type=RuleType.SIGMA.value,
                        severity=level if level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else "MEDIUM",
                        mitre_tactics=tactics or ["Execution"],
                        mitre_techniques=techniques or ["T1059"],
                        raw_content=text,
                        parsed_ast=parsed_ast,
                        is_enabled=True,
                        match_count=0,
                        author=str(doc.get("author", "CyberShield Labs")),
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(rule_record)
                    seeded_count += 1
                except Exception as ex:
                    logger.warning("Failed to parse seed Sigma rule %s: %s", rule_file.name, ex)

        # 2. Seed YARA rules from rules/yara/
        yara_dir = self.rules_base_path / "yara"
        if yara_dir.exists():
            for yara_file in yara_dir.glob("*.yar*"):
                try:
                    text = yara_file.read_text(encoding="utf-8")
                    rule_id = f"YARA-{uuid.uuid4().hex[:8].upper()}"
                    name = yara_file.stem.replace("_", " ").title() + " Pattern"
                    
                    rule_record = DetectionRuleModel(
                        id=rule_id,
                        name=name,
                        description=f"YARA malware and exploit payload signature for {yara_file.name}",
                        rule_type=RuleType.YARA.value,
                        severity="HIGH",
                        mitre_tactics=["Persistence", "Defense Evasion"],
                        mitre_techniques=["T1027", "T1505"],
                        raw_content=text,
                        parsed_ast={"file_target": yara_file.name},
                        is_enabled=True,
                        match_count=0,
                        author="CyberShield Threat Labs",
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(rule_record)
                    seeded_count += 1
                except Exception as ex:
                    logger.warning("Failed to parse seed YARA rule %s: %s", yara_file.name, ex)

        await session.commit()
        logger.info("Seeded %d detection rules into database", seeded_count)
        return seeded_count

    async def list_rules(
        self,
        session: AsyncSession,
        rule_type: Optional[str] = None,
        severity: Optional[str] = None,
        is_enabled: Optional[bool] = None,
        search: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Dict[str, Any]:
        """Query detection rules with pagination and filters."""
        query = select(DetectionRuleModel)

        if rule_type and rule_type != "ALL":
            query = query.where(DetectionRuleModel.rule_type == rule_type.upper())
        if severity and severity != "ALL":
            query = query.where(DetectionRuleModel.severity == severity.upper())
        if is_enabled is not None:
            query = query.where(DetectionRuleModel.is_enabled == is_enabled)
        if search:
            s = f"%{search.strip()}%"
            query = query.where(
                or_(
                    DetectionRuleModel.name.ilike(s),
                    DetectionRuleModel.description.ilike(s),
                    DetectionRuleModel.id.ilike(s),
                )
            )

        # Count total
        count_stmt = select(func.count()).select_from(query.subquery())
        total = (await session.execute(count_stmt)).scalar() or 0

        # Pagination
        query = query.order_by(DetectionRuleModel.match_count.desc(), DetectionRuleModel.created_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)

        result = await session.execute(query)
        items = result.scalars().all()

        return {
            "items": [r.to_dict() for r in items],
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": max(1, (total + page_size - 1) // page_size),
        }

    async def get_rule_by_id(self, session: AsyncSession, rule_id: str) -> Optional[DetectionRuleModel]:
        """Fetch a single detection rule by ID."""
        stmt = select(DetectionRuleModel).where(DetectionRuleModel.id == rule_id)
        res = await session.execute(stmt)
        return res.scalar_one_or_none()

    async def toggle_rule(self, session: AsyncSession, rule_id: str) -> Optional[DetectionRuleModel]:
        """Toggle is_enabled flag for a detection rule."""
        rule = await self.get_rule_by_id(session, rule_id)
        if not rule:
            return None
        rule.is_enabled = not rule.is_enabled
        rule.updated_at = datetime.utcnow()
        await session.commit()
        await session.refresh(rule)
        return rule

    async def create_custom_rule(
        self,
        session: AsyncSession,
        name: str,
        description: str,
        rule_type: str,
        raw_content: str,
        severity: str = "MEDIUM",
        author: str = "Security Analyst",
    ) -> DetectionRuleModel:
        """Create and validate a new custom detection rule."""
        now = datetime.utcnow()
        rule_type_upper = rule_type.upper()

        tactics: List[str] = ["Execution"]
        techniques: List[str] = ["T1059"]
        parsed_ast: Dict[str, Any] = {}

        if rule_type_upper == RuleType.SIGMA.value:
            rule_id = f"SIGMA-{uuid.uuid4().hex[:8].upper()}"
            try:
                doc = yaml.safe_load(raw_content)
                if not isinstance(doc, dict):
                    raise ValueError("Sigma rule YAML must be a valid mapping dictionary")
                parsed_ast = {
                    "logsource": doc.get("logsource", {}),
                    "detection": doc.get("detection", {}),
                    "condition": doc.get("detection", {}).get("condition", "selection"),
                }
                # Extract tags
                for t in doc.get("tags", []):
                    t_str = str(t).lower()
                    if t_str.startswith("attack.t"):
                        techniques.append(t_str.replace("attack.", "").upper())
                    elif t_str.startswith("attack."):
                        tactics.append(t_str.replace("attack.", "").replace("_", " ").title())
            except Exception as e:
                raise ValueError(f"Invalid Sigma YAML content: {e}")
        else:
            rule_id = f"YARA-{uuid.uuid4().hex[:8].upper()}"
            parsed_ast = {"syntax": "yara_v4", "length": len(raw_content)}

        rule = DetectionRuleModel(
            id=rule_id,
            name=name,
            description=description,
            rule_type=rule_type_upper,
            severity=severity.upper(),
            mitre_tactics=tactics,
            mitre_techniques=techniques,
            raw_content=raw_content,
            parsed_ast=parsed_ast,
            is_enabled=True,
            match_count=0,
            author=author,
            created_at=now,
            updated_at=now,
        )
        session.add(rule)
        await session.commit()
        await session.refresh(rule)
        return rule

    async def dry_run_test_rule(
        self,
        raw_content: str,
        rule_type: str,
        test_payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a dry-run test of a rule against a mock event payload without persistence.
        """
        start_time = datetime.utcnow()
        rule_type_upper = rule_type.upper()

        if rule_type_upper == RuleType.SIGMA.value:
            try:
                # Compile temporary SigmaRule
                temp_rule = sigma_engine.load_rule_from_yaml(raw_content)

                # Build mock event
                mock_event = NormalizedEvent(
                    log_source=LogSourceType.SYSMON,
                    process_name=test_payload.get("process_name") or test_payload.get("image"),
                    command_line=test_payload.get("command_line") or test_payload.get("commandline"),
                    parent_process_name=test_payload.get("parent_process_name") or test_payload.get("parentimage"),
                    host_name=test_payload.get("host_name") or test_payload.get("computername", "TEST-HOST"),
                    user_name=test_payload.get("user_name") or test_payload.get("user", "test_user"),
                    source_ip=test_payload.get("source_ip"),
                    destination_ip=test_payload.get("destination_ip"),
                    destination_port=int(test_payload.get("destination_port", 0)) if test_payload.get("destination_port") else None,
                    http_url=test_payload.get("http_url") or test_payload.get("c-uri"),
                    file_name=test_payload.get("file_name") or test_payload.get("targetfilename"),
                )

                # Evaluate rule
                alerts = sigma_engine.evaluate_event(mock_event)
                matched = any(a.rule_name == temp_rule.title or a.rule_id == temp_rule.id for a in alerts)
                
                duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

                return {
                    "matched": matched,
                    "rule_title": temp_rule.title,
                    "severity": temp_rule.level,
                    "execution_time_ms": round(duration_ms, 2),
                    "details": f"Sigma condition '{temp_rule.condition}' evaluated to {matched}",
                    "mitre_tactics": temp_rule.mitre_tactics,
                    "mitre_techniques": temp_rule.mitre_techniques,
                }
            except Exception as ex:
                return {
                    "matched": False,
                    "error": str(ex),
                    "execution_time_ms": 0.0,
                }
        else:
            # YARA dry run
            try:
                content_str = str(test_payload.get("content", ""))
                matches = yara_engine.scan_data(content_str)
                duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
                matched_names = [rule.name for rule, _ in matches]
                return {
                    "matched": len(matched_names) > 0,
                    "matched_rules": matched_names,
                    "execution_time_ms": round(duration_ms, 2),
                    "details": f"YARA matched {len(matched_names)} signatures in payload.",
                }
            except Exception as ex:
                return {
                    "matched": False,
                    "error": str(ex),
                    "execution_time_ms": 0.0,
                }

    async def evaluate_event_and_correlate(
        self,
        session: AsyncSession,
        event: SecurityEventModel
    ) -> List[AlertModel]:
        """
        Evaluate an ingested telemetry event against enabled Sigma rules.
        Creates AlertModel records and triggers multi-stage correlation for new incidents.
        """
        # Convert event to NormalizedEvent for engine
        norm_evt = NormalizedEvent(
            log_source=LogSourceType(event.source_type) if event.source_type in LogSourceType.__members__ else LogSourceType.SYSMON,
            process_name=event.event_data.get("process_name") or event.event_data.get("image") or event.event_data.get("CommandLine"),
            command_line=event.event_data.get("command_line") or event.raw_log,
            parent_process_name=event.event_data.get("parent_process_name"),
            host_name=event.host_name or event.source_ip,
            user_name=event.user_name,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            destination_port=event.destination_port,
            http_url=event.event_data.get("http_url"),
            file_name=event.event_data.get("file_name"),
        )

        sigma_alerts = sigma_engine.evaluate_event(norm_evt)
        created_alerts: List[AlertModel] = []
        now = datetime.utcnow()

        for sa in sigma_alerts:
            # Check if matching rule is enabled in DB
            rule_stmt = select(DetectionRuleModel).where(
                or_(
                    DetectionRuleModel.name == sa.rule_name,
                    DetectionRuleModel.id == sa.rule_id
                )
            )
            rule_res = await session.execute(rule_stmt)
            rule = rule_res.scalar_one_or_none()

            if rule and not rule.is_enabled:
                continue

            alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"
            sev_str = sa.severity.value if hasattr(sa.severity, "value") else str(sa.severity)
            sev_enum = EventSeverity.HIGH if sev_str == "HIGH" else EventSeverity.CRITICAL if sev_str == "CRITICAL" else EventSeverity.MEDIUM
            tactics = sa.mitre_tactics or ["Execution"]
            techniques = sa.mitre_techniques or ["T1059"]

            alert_model = AlertModel(
                id=alert_id,
                alert_code=f"ALT-{now.year}-{uuid.uuid4().hex[:4].upper()}",
                title=sa.title or sa.rule_name,
                description=sa.description or f"Triggered Sigma rule: {sa.rule_name}",
                severity=sev_enum,
                status=AlertStatus.NEW,
                engine=DetectionEngineType.SIGMA,
                rule_id=sa.rule_id,
                rule_name=sa.rule_name,
                source_event_id=event.id,
                host_name=event.host_name or event.source_ip,
                host_ip=event.source_ip,
                user_name=event.user_name,
                mitre_tactic=tactics[0] if tactics else "Execution",
                mitre_technique_id=techniques[0] if techniques else "T1059",
                mitre_technique_name=sa.rule_name,
                deduplication_hash=f"SIGMA:{sa.rule_name}:{event.host_name or event.source_ip}",
                triage_notes=[],
                created_at=now,
                updated_at=now,
            )
            session.add(alert_model)
            created_alerts.append(alert_model)

            # Update rule match count
            if rule:
                rule.match_count += 1
                rule.last_matched_at = now

        if created_alerts:
            await session.commit()
            for a in created_alerts:
                await session.refresh(a)

            # Multi-Stage Attack Chain Correlation check
            target_entity = event.host_name or event.source_ip
            if target_entity:
                await self._check_correlation_and_create_incident(session, target_entity)

        return created_alerts

    async def _check_correlation_and_create_incident(
        self,
        session: AsyncSession,
        entity_key: str
    ) -> Optional[IncidentModel]:
        """
        Query recent alerts on the entity, evaluate correlation, and generate an incident if triggered.
        """
        stmt = select(AlertModel).where(
            or_(
                AlertModel.host_name == entity_key,
                AlertModel.host_ip == entity_key,
            )
        ).order_by(AlertModel.created_at.desc()).limit(20)

        alerts_res = await session.execute(stmt)
        alerts = alerts_res.scalars().all()

        incident_data = attack_chain_correlator.evaluate_alert_cluster(entity_key, alerts)
        if not incident_data:
            return None

        # Check if an open incident already exists for this entity
        existing_stmt = select(IncidentModel).where(
            and_(
                IncidentModel.title == incident_data["title"],
                IncidentModel.status.in_([IncidentStatus.OPEN.value, IncidentStatus.TRIAGED.value, IncidentStatus.CONTAINED.value])
            )
        )
        existing = (await session.execute(existing_stmt)).scalar_one_or_none()
        if existing:
            # Update existing incident with newly associated alerts
            current_alerts = set(existing.associated_alert_ids or [])
            current_alerts.update(incident_data["associated_alert_ids"])
            existing.associated_alert_ids = list(current_alerts)
            existing.updated_at = datetime.utcnow()
            await session.commit()
            return existing

        now = datetime.utcnow()
        inc_id = f"INC-{now.year}-{uuid.uuid4().hex[:4].upper()}"

        incident = IncidentModel(
            id=inc_id,
            title=incident_data["title"],
            summary=incident_data["summary"],
            severity=incident_data["severity"],
            status=IncidentStatus.OPEN.value,
            incident_type=incident_data["incident_type"],
            kill_chain_phase=incident_data["kill_chain_phase"],
            lead_analyst="autonomous_correlator",
            impacted_hosts=incident_data["impacted_hosts"],
            impacted_users=incident_data["impacted_users"],
            associated_alert_ids=incident_data["associated_alert_ids"],
            assigned_playbook=incident_data["assigned_playbook"],
            containment_actions_taken=[],
            created_at=now,
            updated_at=now,
        )
        session.add(incident)

        # Add initial timeline log
        timeline_entry = IncidentTimelineModel(
            incident_id=inc_id,
            timestamp=now,
            author="Autonomous Correlator",
            action_type="CORRELATION_DETECTION",
            description=f"Automated incident synthesis triggered across {len(incident_data['associated_alert_ids'])} alerts.",
            evidence_reference=f"Threat Score: {incident_data.get('risk_score')}",
        )
        session.add(timeline_entry)

        await session.commit()
        await session.refresh(incident)
        logger.warning("Synthesized new Attack Chain Incident '%s': %s", inc_id, incident.title)
        return incident

    async def get_detection_kpis(self, session: AsyncSession) -> Dict[str, Any]:
        """Aggregate KPI metrics for detection rules and threat classification."""
        total_stmt = select(func.count(DetectionRuleModel.id))
        active_stmt = select(func.count(DetectionRuleModel.id)).where(DetectionRuleModel.is_enabled == True)
        matches_stmt = select(func.sum(DetectionRuleModel.match_count))
        sigma_stmt = select(func.count(DetectionRuleModel.id)).where(DetectionRuleModel.rule_type == RuleType.SIGMA.value)
        yara_stmt = select(func.count(DetectionRuleModel.id)).where(DetectionRuleModel.rule_type == RuleType.YARA.value)

        total = (await session.execute(total_stmt)).scalar() or 0
        active = (await session.execute(active_stmt)).scalar() or 0
        total_matches = (await session.execute(matches_stmt)).scalar() or 0
        sigma_count = (await session.execute(sigma_stmt)).scalar() or 0
        yara_count = (await session.execute(yara_stmt)).scalar() or 0

        # Severity breakdown
        sev_stmt = select(DetectionRuleModel.severity, func.count(DetectionRuleModel.id)).group_by(DetectionRuleModel.severity)
        sev_counts = dict((await session.execute(sev_stmt)).all())

        return {
            "total_rules": total,
            "active_rules": active,
            "sigma_rules": sigma_count,
            "yara_rules": yara_count,
            "total_detections_triggered": total_matches,
            "rules_by_severity": sev_counts,
        }


detection_rule_service = DetectionRuleService()
