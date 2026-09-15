"""YARA Pattern Matching Engine for CyberShield Enterprise.

Parses YARA-style rule definitions supporting plain strings, hex bytecode patterns,
and regular expressions. Evaluates memory buffers, process dumps, and files without
external dependencies or native binary compilation issues.
"""

from __future__ import annotations

import re
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

from cybershield.core.models import (
    Alert,
    Severity,
    DetectionEngineType,
    generate_id,
    now_utc,
)
from cybershield.core.exceptions import YaraExecutionError

logger = logging.getLogger("cybershield.engine.yara")


@dataclass
class YaraStringPattern:
    """An individual string, hex, or regex pattern inside a YARA rule."""
    identifier: str
    pattern_type: str  # text, hex, regex
    raw_value: str
    compiled_regex: re.Pattern
    modifiers: Set[str] = field(default_factory=set)  # nocase, wide, ascii


@dataclass
class CompiledYaraRule:
    """Compiled in-memory representation of a YARA rule."""
    name: str
    meta: Dict[str, str] = field(default_factory=dict)
    strings: Dict[str, YaraStringPattern] = field(default_factory=dict)
    condition: str = "any of them"
    severity: Severity = Severity.HIGH


class YaraEngine:
    """High-performance YARA pattern matcher."""

    def __init__(self, rules_dir: Optional[Path] = None):
        if rules_dir is None:
            default_dir = Path(__file__).resolve().parent.parent.parent / "rules" / "yara"
            if default_dir.exists():
                rules_dir = default_dir
        self.rules_dir = rules_dir
        self._rules: Dict[str, CompiledYaraRule] = {}
        if rules_dir and rules_dir.exists():
            self.load_rules_from_dir(rules_dir)

    def _compile_hex_string(self, hex_str: str) -> re.Pattern:
        """Convert YARA hex pattern e.g. '{ 4D 5A 90 ?? ?? 00 }' to regex bytes pattern."""
        cleaned = hex_str.replace("{", "").replace("}", "").strip()
        tokens = cleaned.split()
        regex_parts = []
        for token in tokens:
            if token == "??" or token == "?":
                regex_parts.append(b".")
            else:
                byte_val = bytes.fromhex(token)
                regex_parts.append(re.escape(byte_val))
        return re.compile(b"".join(regex_parts), re.DOTALL)

    def compile_rule_text(self, rule_text: str) -> List[CompiledYaraRule]:
        """Parse raw YARA text containing one or more rules."""
        compiled_rules: List[CompiledYaraRule] = []

        # Match blocks: rule <name> { ... }
        rule_blocks = re.findall(r"rule\s+([A-Za-z0-9_]+)\s*\{([^}]+)\}", rule_text, re.DOTALL)

        for name, body in rule_blocks:
            meta: Dict[str, str] = {}
            strings_dict: Dict[str, YaraStringPattern] = {}
            condition_str = "any of them"

            # Parse meta block
            meta_match = re.search(r"meta:\s*(.*?)(?=strings:|condition:|\Z)", body, re.DOTALL)
            if meta_match:
                for line in meta_match.group(1).strip().splitlines():
                    line = line.strip()
                    if "=" in line:
                        k, v = line.split("=", 1)
                        meta[k.strip()] = v.strip().strip('"').strip("'")

            # Parse strings block
            strings_match = re.search(r"strings:\s*(.*?)(?=condition:|\Z)", body, re.DOTALL)
            if strings_match:
                for line in strings_match.group(1).strip().splitlines():
                    line = line.strip()
                    if not line.startswith("$"):
                        continue
                    # Match: $identifier = "string" [nocase] or $identifier = { ... }
                    m_str = re.match(r"(\$[a-zA-Z0-9_]+)\s*=\s*([\"\{/].+)", line)
                    if not m_str:
                        continue
                    ident, val_with_mods = m_str.groups()
                    ident = ident.strip()
                    val_with_mods = val_with_mods.strip()

                    modifiers = set()
                    if val_with_mods.startswith('"'):
                        # Text pattern
                        end_quote = val_with_mods.rfind('"')
                        text_val = val_with_mods[1:end_quote]
                        tail = val_with_mods[end_quote + 1:].lower()
                        flags = 0
                        if "nocase" in tail:
                            flags |= re.IGNORECASE
                            modifiers.add("nocase")
                        pat = re.compile(re.escape(text_val.encode("latin1")), flags)
                        strings_dict[ident] = YaraStringPattern(
                            identifier=ident,
                            pattern_type="text",
                            raw_value=text_val,
                            compiled_regex=pat,
                            modifiers=modifiers
                        )
                    elif val_with_mods.startswith("{"):
                        # Hex pattern
                        hex_val = val_with_mods[:val_with_mods.find("}") + 1]
                        pat = self._compile_hex_string(hex_val)
                        strings_dict[ident] = YaraStringPattern(
                            identifier=ident,
                            pattern_type="hex",
                            raw_value=hex_val,
                            compiled_regex=pat
                        )
                    elif val_with_mods.startswith("/"):
                        # Regex pattern
                        end_slash = val_with_mods.rfind("/")
                        reg_val = val_with_mods[1:end_slash]
                        flags = re.DOTALL
                        if "i" in val_with_mods[end_slash + 1:].lower():
                            flags |= re.IGNORECASE
                        pat = re.compile(reg_val.encode("latin1"), flags)
                        strings_dict[ident] = YaraStringPattern(
                            identifier=ident,
                            pattern_type="regex",
                            raw_value=reg_val,
                            compiled_regex=pat
                        )

            # Parse condition block
            cond_match = re.search(r"condition:\s*(.*?)$", body, re.DOTALL)
            if cond_match:
                condition_str = cond_match.group(1).strip()

            # Severity mapping from meta
            sev_str = meta.get("severity", "HIGH").upper()
            sev = Severity.HIGH
            if sev_str in Severity.__members__:
                sev = Severity[sev_str]

            rule = CompiledYaraRule(
                name=name,
                meta=meta,
                strings=strings_dict,
                condition=condition_str,
                severity=sev,
            )
            self._rules[name] = rule
            compiled_rules.append(rule)

        return compiled_rules

    def load_rules_from_dir(self, directory: Path) -> int:
        """Load and compile all .yar / .yara files in directory."""
        count = 0
        for file_path in directory.glob("**/*.yar*"):
            try:
                content = file_path.read_text(encoding="utf-8")
                rules = self.compile_rule_text(content)
                count += len(rules)
            except Exception as ex:
                logger.warning("Failed to parse YARA file %s: %s", file_path.name, ex)
        logger.info("Compiled %d YARA rules from %s", count, directory)
        return count

    def scan_data(self, data: bytes | str) -> List[Tuple[CompiledYaraRule, Dict[str, int]]]:
        """Scan buffer against all registered YARA rules.
        
        Returns a list of tuples: (matched_rule, {matched_ident: match_offset})
        """
        if isinstance(data, str):
            raw_bytes = data.encode("utf-8", errors="ignore")
        else:
            raw_bytes = data

        matches: List[Tuple[CompiledYaraRule, Dict[str, int]]] = []

        for rule in self._rules.values():
            string_matches: Dict[str, int] = {}
            for ident, pattern in rule.strings.items():
                m = pattern.compiled_regex.search(raw_bytes)
                if m:
                    string_matches[ident] = m.start()

            # Evaluate condition
            cond = rule.condition.lower()
            matched = False
            if "any of them" in cond or "1 of them" in cond:
                matched = len(string_matches) > 0
            elif "all of them" in cond:
                matched = len(string_matches) == len(rule.strings) and len(rule.strings) > 0
            else:
                # Custom boolean logic: '$a or ($b and $c)'
                eval_cond = cond
                for ident in rule.strings.keys():
                    is_present = ident in string_matches
                    eval_cond = re.sub(r"\\" + re.escape(ident) + r"\b", str(is_present), eval_cond)
                sanitized = re.sub(r"[^a-z0-9_\s\(\)]", "", eval_cond)
                try:
                    matched = bool(eval(sanitized, {"__builtins__": {}}, {"true": True, "false": False, "True": True, "False": False}))
                except Exception:
                    matched = len(string_matches) > 0

            if matched:
                matches.append((rule, string_matches))

        return matches

    def scan_and_alert(self, data: bytes | str, source_label: str = "Buffer") -> List[Alert]:
        """Scan data and return Alert objects for all rule triggers."""
        alerts: List[Alert] = []
        hits = self.scan_data(data)

        for rule, string_hits in hits:
            tactics = [rule.meta.get("tactic", "Execution")]
            techniques = [rule.meta.get("technique", "T1059")]

            alert = Alert(
                title=f"[YARA Match] {rule.name} in {source_label}",
                description=rule.meta.get("description", f"Rule {rule.name} matched {len(string_hits)} signature patterns."),
                severity=rule.severity,
                confidence=float(rule.meta.get("confidence", 0.92)),
                detection_engine=DetectionEngineType.YARA_SCANNER,
                rule_id=f"YARA-{rule.name}",
                rule_name=rule.name,
                mitre_tactics=tactics,
                mitre_techniques=techniques,
                metadata={
                    "yara_meta": rule.meta,
                    "matched_strings": {k: f"offset: 0x{v:X}" for k, v in string_hits.items()}
                }
            )
            alerts.append(alert)

        return alerts

    def get_loaded_rules(self) -> List[Dict[str, Any]]:
        """Return metadata summary of all loaded YARA rules."""
        return [
            {
                "id": f"YARA-{r.name}",
                "name": r.name,
                "meta": r.meta,
                "severity": r.severity.value,
                "condition": r.condition,
            }
            for r in self._rules.values()
        ]


# Global singleton YARA engine
yara_engine = YaraEngine()

