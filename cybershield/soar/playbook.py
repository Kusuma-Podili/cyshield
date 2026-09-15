"""SOAR Playbook Execution Engine for CyberShield Enterprise.

Loads, validates, and runs multi-step security response workflows:
- Automated containment on critical alert triggers
- Step-by-step latency tracking and error handling
- Auditable execution history for compliance and post-incident review
"""

from __future__ import annotations

import json
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from cybershield.core.models import (
    PlaybookExecution,
    PlaybookStep,
    Alert,
    generate_id,
    now_utc,
)
from cybershield.core.bus import event_bus
from cybershield.soar.actions import SOARActionRegistry

logger = logging.getLogger("cybershield.soar.playbook")


@dataclass
class PlaybookDefinition:
    """Static schema defining an automation playbook."""
    id: str
    name: str
    description: str
    trigger_criteria: Dict[str, Any]
    steps: List[Dict[str, Any]]
    author: str = "CyberShield Security Engineering"


class SOAREngine:
    """Automated security incident response orchestration engine."""

    def __init__(self, playbooks_dir: Optional[Path] = None):
        if playbooks_dir is None:
            default_dir = Path(__file__).resolve().parent / "playbooks"
            if default_dir.exists():
                playbooks_dir = default_dir
        self.playbooks_dir = playbooks_dir
        self._definitions: Dict[str, PlaybookDefinition] = {}
        self._executions: Dict[str, PlaybookExecution] = {}
        if playbooks_dir and playbooks_dir.exists():
            self.load_playbooks_from_dir(playbooks_dir)

    def load_playbook_from_json(self, json_text: str) -> PlaybookDefinition:
        """Parse JSON playbook definition into memory."""
        data = json.loads(json_text)
        pb = PlaybookDefinition(
            id=data.get("id") or generate_id("PB"),
            name=data.get("name", "Untitled Playbook"),
            description=data.get("description", ""),
            trigger_criteria=data.get("trigger_criteria", {}),
            steps=data.get("steps", []),
            author=data.get("author", "CyberShield Labs"),
        )
        self._definitions[pb.id] = pb
        return pb

    def load_playbooks_from_dir(self, directory: Path) -> int:
        """Load all .json playbooks from directory."""
        count = 0
        for file_path in directory.glob("**/*.json"):
            try:
                content = file_path.read_text(encoding="utf-8")
                self.load_playbook_from_json(content)
                count += 1
            except Exception as ex:
                logger.warning("Failed to load playbook %s: %s", file_path.name, ex)
        logger.info("Loaded %d SOAR playbooks from %s", count, directory)
        return count

    def get_playbook(self, playbook_id: str) -> Optional[PlaybookDefinition]:
        """Fetch playbook by ID."""
        return self._definitions.get(playbook_id)

    def get_all_playbooks(self) -> List[PlaybookDefinition]:
        """Return all available playbooks."""
        return list(self._definitions.values())

    async def execute_playbook(
        self,
        playbook_id: str,
        target_entity: str,
        trigger_alert: Optional[Alert] = None,
        executed_by: str = "AUTOMATION",
        context_vars: Optional[Dict[str, Any]] = None,
    ) -> PlaybookExecution:
        """Execute all steps of a playbook against a target entity."""
        definition = self.get_playbook(playbook_id)
        if not definition:
            raise ValueError(f"Playbook '{playbook_id}' not found.")

        context = {
            "target": target_entity,
            "alert_id": trigger_alert.alert_id if trigger_alert else "MANUAL",
            "source_ip": trigger_alert.primary_source_ip if trigger_alert else "",
            "dest_ip": trigger_alert.primary_dest_ip if trigger_alert else "",
            "host": trigger_alert.impacted_host if trigger_alert else target_entity,
            "user": trigger_alert.impacted_user if trigger_alert else target_entity,
        }
        if context_vars:
            context.update(context_vars)

        # Initialize execution record
        execution = PlaybookExecution(
            playbook_id=definition.id,
            playbook_name=definition.name,
            trigger_alert_id=trigger_alert.alert_id if trigger_alert else None,
            target_entity=target_entity,
            status="RUNNING",
            executed_by=executed_by,
        )
        self._executions[execution.execution_id] = execution
        await event_bus.publish("soar.started", execution, priority=5)

        logger.info("Beginning SOAR Playbook '%s' execution (%s) on target '%s'", definition.name, execution.execution_id, target_entity)

        all_passed = True
        for step_spec in definition.steps:
            step_name = step_spec.get("name", "Unnamed Step")
            action_type = step_spec.get("action", "")
            raw_target = step_spec.get("target", "{{target}}")
            # Replace placeholder variables: {{target}}, {{source_ip}}, etc.
            resolved_target = raw_target
            for var_k, var_v in context.items():
                resolved_target = resolved_target.replace(f"{{{{{var_k}}}}}", str(var_v))

            raw_params = step_spec.get("parameters", {})
            resolved_params = {}
            for pk, pv in raw_params.items():
                if isinstance(pv, str):
                    for var_k, var_v in context.items():
                        pv = pv.replace(f"{{{{{var_k}}}}}", str(var_v))
                resolved_params[pk] = pv

            step_record = PlaybookStep(
                name=step_name,
                action_type=action_type,
                target=resolved_target,
                parameters=resolved_params,
                status="RUNNING",
                executed_at=now_utc(),
            )
            execution.steps.append(step_record)

            start_t = time.perf_counter()
            success, msg, output = await SOARActionRegistry.execute(action_type, resolved_target, resolved_params)
            duration_ms = (time.perf_counter() - start_t) * 1000.0

            step_record.duration_ms = round(duration_ms, 2)
            step_record.result_message = msg
            step_record.status = "COMPLETED" if success else "FAILED"

            if not success:
                all_passed = False
                logger.error("Playbook step '%s' failed: %s", step_name, msg)
                if step_spec.get("abort_on_failure", True):
                    execution.error_message = f"Aborted at step '{step_name}': {msg}"
                    break

        execution.status = "COMPLETED" if all_passed else "FAILED"
        execution.completed_at = now_utc()
        await event_bus.publish("soar.completed", execution, priority=5)

        logger.info("SOAR Playbook '%s' finished with status: %s", definition.name, execution.status)
        return execution

    def get_execution_history(self, limit: int = 50) -> List[PlaybookExecution]:
        """Fetch recent execution traces."""
        return list(self._executions.values())[-limit:]


# Global singleton SOAR engine
soar_engine = SOAREngine()
