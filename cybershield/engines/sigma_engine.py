"""Sigma Detection Rule Compiler & Matching Engine for CyberShield Enterprise.

Parses industry-standard Sigma YAML detection rules, compiles condition ASTs,
evaluates field modifiers (|contains, |startswith, |endswith, |re), and evaluates
streamed NormalizedEvent telemetry against rule sets with MITRE ATT&CK mapping.
"""

from __future__ import annotations

import re
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Union
from dataclasses import dataclass, field

from cybershield.core.models import (
    NormalizedEvent,
    Alert,
    Severity,
    DetectionEngineType,
    generate_id,
    now_utc,
)
from cybershield.core.exceptions import SigmaCompilationError

logger = logging.getLogger("cybershield.engine.sigma")


@dataclass
class SigmaRule:
    """Compiled in-memory representation of a Sigma detection rule."""
    id: str
    title: str
    description: str
    status: str
    level: str  # informational, low, medium, high, critical
    logsource: Dict[str, Any]
    detection: Dict[str, Any]
    condition: str
    tags: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    false_positives: List[str] = field(default_factory=list)
    author: str = "CyberShield Threat Labs"


class SigmaEngine:
    """Evaluates telemetry events against Sigma detection rules."""

    def __init__(self, rules_dir: Optional[Path] = None):
        if rules_dir is None:
            default_dir = Path(__file__).resolve().parent.parent.parent / "rules" / "sigma"
            if default_dir.exists():
                rules_dir = default_dir
        self.rules_dir = rules_dir
        self._rules: Dict[str, SigmaRule] = {}
        if rules_dir and rules_dir.exists():
            self.load_rules_from_dir(rules_dir)

    def load_rule_from_yaml(self, yaml_text: str) -> SigmaRule:
        """Parse raw YAML string into a SigmaRule object."""
        try:
            doc = yaml.safe_load(yaml_text)
            if not isinstance(doc, dict):
                raise SigmaCompilationError("Sigma rule YAML must be a mapping dictionary")

            rule_id = str(doc.get("id") or generate_id("SIGMA"))
            title = str(doc.get("title", "Untitled Sigma Rule"))
            desc = str(doc.get("description", ""))
            status = str(doc.get("status", "experimental"))
            level = str(doc.get("level", "medium")).upper()
            logsource = doc.get("logsource", {})
            detection = doc.get("detection", {})
            condition = str(detection.get("condition", "selection"))
            tags = doc.get("tags", [])

            # Extract MITRE tactics and techniques from tags
            tactics = []
            techniques = []
            for tag in tags:
                tag_lower = str(tag).lower()
                if tag_lower.startswith("attack.t"):
                    tech_id = tag_lower.replace("attack.", "").upper()
                    techniques.append(tech_id)
                elif tag_lower.startswith("attack."):
                    tactic_name = tag_lower.replace("attack.", "").replace("_", " ").title()
                    tactics.append(tactic_name)

            rule = SigmaRule(
                id=rule_id,
                title=title,
                description=desc,
                status=status,
                level=level,
                logsource=logsource,
                detection=detection,
                condition=condition,
                tags=tags,
                mitre_tactics=tactics,
                mitre_techniques=techniques,
                false_positives=doc.get("falsepositives", []),
                author=doc.get("author", "CyberShield Labs"),
            )
            self._rules[rule_id] = rule
            return rule
        except Exception as ex:
            raise SigmaCompilationError(f"Failed to compile Sigma rule: {ex}") from ex

    def load_rules_from_dir(self, directory: Path) -> int:
        """Load and compile all .yml / .yaml Sigma rules in directory recursively."""
        count = 0
        for file_path in directory.glob("**/*.y*ml"):
            try:
                content = file_path.read_text(encoding="utf-8")
                self.load_rule_from_yaml(content)
                count += 1
            except Exception as ex:
                logger.warning("Could not load Sigma rule file %s: %s", file_path.name, ex)
        logger.info("Compiled %d Sigma detection rules from %s", count, directory)
        return count

    def add_rule(self, rule: SigmaRule) -> None:
        """Register a pre-built SigmaRule."""
        self._rules[rule.id] = rule

    def _get_event_field(self, event: NormalizedEvent, field_name: str) -> Optional[Any]:
        """Extract a field from NormalizedEvent by name, checking common aliases."""
        field_map = {
            "image": event.process_name,
            "processname": event.process_name,
            "process_name": event.process_name,
            "commandline": event.command_line,
            "command_line": event.command_line,
            "parentimage": event.parent_process_name,
            "parent_process_name": event.parent_process_name,
            "user": event.user_name,
            "username": event.user_name,
            "user_name": event.user_name,
            "computername": event.host_name,
            "host_name": event.host_name,
            "sourceip": event.source_ip,
            "source_ip": event.source_ip,
            "destinationip": event.destination_ip,
            "destination_ip": event.destination_ip,
            "destinationport": event.destination_port,
            "destination_port": event.destination_port,
            "c-uri": event.http_url,
            "http_url": event.http_url,
            "targetfilename": event.file_name,
            "file_name": event.file_name,
            "file_path": event.file_path,
            "hashes": event.file_hash_sha256,
        }
        val = field_map.get(field_name.lower())
        if val is not None:
            return val
        # Check event metadata
        return event.metadata.get(field_name)

    def _match_value(self, actual_value: Any, expected_pattern: Any, modifier: str = "") -> bool:
        """Evaluate pattern match given modifier (|contains, |startswith, |endswith, |re)."""
        if actual_value is None:
            return False

        actual_str = str(actual_value).lower()
        if isinstance(expected_pattern, list):
            # Any match in list
            return any(self._match_value(actual_value, item, modifier) for item in expected_pattern)

        pattern_str = str(expected_pattern).lower()

        if modifier == "contains":
            return pattern_str in actual_str
        elif modifier == "startswith":
            return actual_str.startswith(pattern_str)
        elif modifier == "endswith":
            return actual_str.endswith(pattern_str)
        elif modifier == "re":
            try:
                return bool(re.search(str(expected_pattern), str(actual_value), re.IGNORECASE))
            except Exception:
                return False
        else:
            # Exact or wildcard match
            if "*" in pattern_str or "?" in pattern_str:
                regex_pat = "^" + re.escape(pattern_str).replace(r"\*", ".*").replace(r"\?", ".") + "$"
                return bool(re.match(regex_pat, actual_str))
            return pattern_str == actual_str

    def _evaluate_selection(self, event: NormalizedEvent, selection_dict: Any) -> bool:
        """Evaluate a single Sigma selection block against an event."""
        if not isinstance(selection_dict, dict):
            return False

        for key, expected_val in selection_dict.items():
            parts = key.split("|")
            field_name = parts[0]
            modifier = parts[1] if len(parts) > 1 else ""

            actual_val = self._get_event_field(event, field_name)
            if not self._match_value(actual_val, expected_val, modifier):
                return False

        return True

    def _evaluate_condition(self, condition: str, selection_results: Dict[str, bool]) -> bool:
        """Evaluate boolean condition string e.g. 'selection and not filter'."""
        cond = condition.strip().lower()

        # Handle simple cases
        if cond in selection_results:
            return selection_results[cond]

        # Handle '1 of selection*' or 'all of selection*'
        if "1 of selection*" in cond or "any of selection*" in cond:
            return any(val for k, val in selection_results.items() if k.startswith("selection"))
        if "all of selection*" in cond:
            matches = [val for k, val in selection_results.items() if k.startswith("selection")]
            return all(matches) if matches else False

        # Boolean expression evaluator for standard Sigma: 'sel and not filter'
        # Tokenize and replace known selection names with True/False
        for sel_name, res in selection_results.items():
            pattern = r"\b" + re.escape(sel_name) + r"\b"
            cond = re.sub(pattern, str(res), cond)

        # Sanitize string to prevent arbitrary code execution
        sanitized = re.sub(r"[^a-zA-Z0-9_\s\(\)]", "", cond)
        sanitized = sanitized.replace("and", " and ").replace("or", " or ").replace("not", " not ")

        try:
            # Safe evaluation with strict empty globals/locals
            return bool(eval(sanitized, {"__builtins__": {}}, {"true": True, "false": False, "True": True, "False": False}))
        except Exception:
            # Fallback to checking if main 'selection' passed
            return selection_results.get("selection", False)

    def evaluate_event(self, event: NormalizedEvent) -> List[Alert]:
        """Evaluate all loaded Sigma rules against an incoming event.
        
        Returns a list of Alerts for any matched rules.
        """
        alerts: List[Alert] = []

        for rule in self._rules.values():
            detection = rule.detection
            selection_results: Dict[str, bool] = {}

            for block_name, block_def in detection.items():
                if block_name == "condition":
                    continue
                selection_results[block_name.lower()] = self._evaluate_selection(event, block_def)

            is_match = self._evaluate_condition(rule.condition, selection_results)
            if is_match:
                # Map Sigma level to Severity
                level_map = {
                    "CRITICAL": Severity.CRITICAL,
                    "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM,
                    "LOW": Severity.LOW,
                    "INFORMATIONAL": Severity.INFORMATIONAL,
                }
                severity = level_map.get(rule.level.upper(), Severity.MEDIUM)

                alert = Alert(
                    title=f"[Sigma Alert] {rule.title}",
                    description=f"{rule.description} (Rule ID: {rule.id})",
                    severity=severity,
                    confidence=0.90,
                    detection_engine=DetectionEngineType.SIGMA_RULE,
                    rule_id=rule.id,
                    rule_name=rule.title,
                    mitre_tactics=rule.mitre_tactics or ["Execution"],
                    mitre_techniques=rule.mitre_techniques or ["T1059"],
                    primary_source_ip=event.source_ip,
                    primary_dest_ip=event.destination_ip,
                    impacted_host=event.host_name,
                    impacted_user=event.user_name,
                    source_event_ids=[event.event_id],
                    metadata={
                        "rule_id": rule.id,
                        "rule_status": rule.status,
                        "sigma_tags": rule.tags,
                        "process_name": event.process_name,
                        "command_line": event.command_line,
                    },
                )
                alerts.append(alert)

        return alerts

    def get_loaded_rules(self) -> List[Dict[str, Any]]:
        """Return metadata summary of all loaded rules."""
        return [
            {
                "id": r.id,
                "title": r.title,
                "level": r.level,
                "description": r.description,
                "mitre_tactics": r.mitre_tactics,
                "mitre_techniques": r.mitre_techniques,
            }
            for r in self._rules.values()
        ]


# Global singleton Sigma engine
sigma_engine = SigmaEngine()
