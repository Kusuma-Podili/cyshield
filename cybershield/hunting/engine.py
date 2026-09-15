"""
Threat Hunting Engine.
Coordinates hypothesis-driven proactive hunting over multi-source telemetry,
evaluates complex search patterns, and extracts indicators of compromise.
"""

import math
import re
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from cybershield.hunting.queries import BUILTIN_HUNT_TEMPLATES, get_hunting_template
from cybershield.hunting.schemas import (
    HuntConfidence,
    HuntExecutionRequest,
    HuntExecutionResult,
    HuntFinding,
    HuntHypothesis,
    HuntStatus,
)


class ThreatHuntingEngine:
    """Proactive Threat Hunting Engine for SOC Analysts and Automated Hunters."""

    def __init__(self):
        self._hypotheses: Dict[str, HuntHypothesis] = {}
        self._results: Dict[str, HuntExecutionResult] = {}
        self._load_default_hypotheses()

    def _load_default_hypotheses(self):
        """Initialize hypotheses from built-in hunting templates."""
        for template in BUILTIN_HUNT_TEMPLATES:
            hypo = HuntHypothesis(
                id=f"HYPO-{template.id}",
                title=template.name,
                description=template.description,
                mitre_tactics=[template.category],
                mitre_technique_ids=[template.mitre_technique_id],
                author="System Threat Hunter",
                target_data_sources=template.data_sources,
                query_template=template.default_query,
                status=HuntStatus.SCHEDULED,
                tags=[template.category.lower(), "builtin"],
            )
            self._hypotheses[hypo.id] = hypo

    def create_hypothesis(self, hypothesis: HuntHypothesis) -> HuntHypothesis:
        """Register a new hunting hypothesis."""
        if not hypothesis.id:
            hypothesis.id = f"HYPO-{uuid.uuid4().hex[:8].upper()}"
        hypothesis.created_at = datetime.utcnow()
        hypothesis.updated_at = datetime.utcnow()
        self._hypotheses[hypothesis.id] = hypothesis
        return hypothesis

    def get_hypothesis(self, hypothesis_id: str) -> Optional[HuntHypothesis]:
        return self._hypotheses.get(hypothesis_id)

    def list_hypotheses(self, status: Optional[HuntStatus] = None) -> List[HuntHypothesis]:
        if status:
            return [h for h in self._hypotheses.values() if h.status == status]
        return list(self._hypotheses.values())

    def delete_hypothesis(self, hypothesis_id: str) -> bool:
        if hypothesis_id in self._hypotheses:
            del self._hypotheses[hypothesis_id]
            return True
        return False

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob)

    @staticmethod
    def _extract_iocs_from_text(text: str) -> List[Dict[str, str]]:
        """Extract IPs, domains, and hashes from text strings."""
        iocs = []
        # IP regex
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        for ip in re.findall(ip_pattern, text):
            if not ip.startswith(("127.", "0.", "255.")):
                iocs.append({"type": "ip", "value": ip})

        # SHA256 / MD5
        hash_pattern = r"\b[a-fA-F0-9]{32,64}\b"
        for h in re.findall(hash_pattern, text):
            iocs.append({"type": "hash", "value": h.lower()})

        # Basic domain extractor
        domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
        for dom in re.findall(domain_pattern, text):
            if not any(dom.endswith(s) for s in [".exe", ".dll", ".sys", ".txt", ".json", ".log"]):
                iocs.append({"type": "domain", "value": dom.lower()})

        # Deduplicate
        seen = set()
        unique_iocs = []
        for item in iocs:
            key = (item["type"], item["value"])
            if key not in seen:
                seen.add(key)
                unique_iocs.append(item)
        return unique_iocs

    def _evaluate_event_against_hypothesis(
        self, event: Dict[str, Any], hypothesis: HuntHypothesis
    ) -> Optional[HuntFinding]:
        """Test a telemetry event against hypothesis parameters and queries."""
        query = hypothesis.query_template.lower()
        event_str = " ".join(f"{k}:{v}" for k, v in event.items()).lower()

        matched = False
        details = {}
        risk = 40.0
        confidence = HuntConfidence.MEDIUM

        # Check for encoded powershell
        if "t1059.001" in [t.lower() for t in hypothesis.mitre_technique_ids]:
            cmd = str(event.get("command_line", "") or event.get("process_command_line", ""))
            if any(flg in cmd.lower() for flg in ["-enc", "-encodedcommand", "downloadstring", "iex("]):
                matched = True
                risk = 85.0
                confidence = HuntConfidence.HIGH
                details = {"flagged_cmd": cmd, "technique": "PowerShell Obfuscation"}

        # Check for LOLBAS
        elif "t1218" in [t.lower() for t in hypothesis.mitre_technique_ids]:
            proc = str(event.get("process_name", "") or event.get("image", "")).lower()
            cmd = str(event.get("command_line", "")).lower()
            lolbins = ["certutil", "bitsadmin", "mshta", "regsvr32", "rundll32"]
            if any(lb in proc for lb in lolbins):
                if any(x in cmd for x in ["http", "urlcache", "/transfer", "scrobj.dll", ".vbs"]):
                    matched = True
                    risk = 90.0
                    confidence = HuntConfidence.CRITICAL
                    details = {"binary": proc, "command": cmd, "technique": "LOLBAS Execution"}

        # Check for LSASS memory dump
        elif "t1003.001" in [t.lower() for t in hypothesis.mitre_technique_ids]:
            cmd = str(event.get("command_line", "")).lower()
            if "comsvcs" in cmd and "minidump" in cmd:
                matched = True
                risk = 98.0
                confidence = HuntConfidence.CRITICAL
                details = {"command": cmd, "technique": "Comsvcs MiniDump LSASS"}
            elif "lsass" in cmd and ("procdump" in cmd or "dump" in cmd):
                matched = True
                risk = 95.0
                confidence = HuntConfidence.CRITICAL
                details = {"command": cmd, "technique": "LSASS Dump"}

        # Check for DNS Tunneling
        elif "t1048" in [t.lower() for t in hypothesis.mitre_technique_ids]:
            query_str = str(event.get("query", "") or event.get("dns_query", ""))
            if query_str:
                entropy = self._calculate_entropy(query_str)
                if len(query_str) > 50 or entropy > 4.1 or event.get("query_type") == "TXT":
                    matched = True
                    risk = 75.0
                    confidence = HuntConfidence.HIGH
                    details = {"query": query_str, "length": len(query_str), "entropy": round(entropy, 2)}

        # Check for Lateral Movement (WMI, PsExec)
        elif "t1021" in [t.lower() for t in hypothesis.mitre_technique_ids]:
            cmd = str(event.get("command_line", "")).lower()
            proc = str(event.get("process_name", "")).lower()
            if ("wmic" in proc and "call create" in cmd) or "psexec" in proc or "admin$" in cmd:
                matched = True
                risk = 88.0
                confidence = HuntConfidence.HIGH
                details = {"binary": proc, "command": cmd, "technique": "Remote Process Spawn"}

        # Fallback keyword and regex evaluation
        else:
            # Simple substring matching based on query tokens
            tokens = [t.strip() for t in re.split(r"\s+(?:AND|OR)\s+", hypothesis.query_template, flags=re.IGNORECASE)]
            token_matches = sum(1 for tok in tokens if any(part in event_str for part in tok.lower().split()))
            if token_matches >= max(1, len(tokens) // 2):
                matched = True
                risk = 50.0
                confidence = HuntConfidence.LOW
                details = {"matched_tokens": token_matches, "total_tokens": len(tokens)}

        if matched:
            entity_id = (
                event.get("host_id")
                or event.get("hostname")
                or event.get("agent_id")
                or event.get("user_name")
                or event.get("src_ip")
                or "unknown-entity"
            )
            entity_type = "host" if "host" in str(entity_id) else "user" if "user" in event else "network"

            finding = HuntFinding(
                id=f"FIND-{uuid.uuid4().hex[:8].upper()}",
                source_event_id=str(event.get("id", uuid.uuid4().hex[:8])),
                technique_id=hypothesis.mitre_technique_ids[0] if hypothesis.mitre_technique_ids else "T1000",
                technique_name=hypothesis.title,
                entity_id=str(entity_id),
                entity_type=entity_type,
                details=details,
                confidence=confidence,
                risk_score=risk,
                recommended_action=f"Investigate activity on {entity_id} and review associated parent processes.",
            )
            return finding
        return None

    def execute_hunt(
        self, request: HuntExecutionRequest, event_stream: List[Dict[str, Any]]
    ) -> HuntExecutionResult:
        """Run a proactive threat hunt across provided event telemetry."""
        hypothesis = self._hypotheses.get(request.hypothesis_id)
        if not hypothesis:
            raise ValueError(f"Hypothesis {request.hypothesis_id} not found")

        started_at = datetime.utcnow()
        t0 = time.perf_counter()

        findings: List[HuntFinding] = []
        raw_text_for_iocs = []

        for event in event_stream[: request.limit]:
            finding = self._evaluate_event_against_hypothesis(event, hypothesis)
            if finding:
                findings.append(finding)
                raw_text_for_iocs.append(str(event))

        # Extract IOCs
        iocs = self._extract_iocs_from_text(" ".join(raw_text_for_iocs))
        duration_ms = (time.perf_counter() - t0) * 1000

        # Calculate aggregate risk
        avg_risk = sum(f.risk_score for f in findings) / len(findings) if findings else 0.0

        result = HuntExecutionResult(
            execution_id=f"HEX-{uuid.uuid4().hex[:8].upper()}",
            hypothesis_id=hypothesis.id,
            status=HuntStatus.COMPLETED,
            started_at=started_at,
            completed_at=datetime.utcnow(),
            duration_ms=round(duration_ms, 2),
            total_events_scanned=len(event_stream),
            matched_events_count=len(findings),
            findings=findings,
            extracted_iocs=iocs,
            aggregate_risk_score=round(avg_risk, 1),
            summary=f"Hunt '{hypothesis.title}' identified {len(findings)} suspicious events across {len(event_stream)} evaluated logs.",
        )

        self._results[result.execution_id] = result
        hypothesis.status = HuntStatus.COMPLETED
        hypothesis.updated_at = datetime.utcnow()

        return result

    def get_execution_result(self, execution_id: str) -> Optional[HuntExecutionResult]:
        return self._results.get(execution_id)

    def list_execution_results(self) -> List[HuntExecutionResult]:
        return list(self._results.values())

    def get_hunt_metrics(self) -> Dict[str, Any]:
        """Summary metrics across all threat hunting activity."""
        total_hypotheses = len(self._hypotheses)
        total_executions = len(self._results)
        total_findings = sum(len(r.findings) for r in self._results.values())
        total_iocs = sum(len(r.extracted_iocs) for r in self._results.values())

        by_tactic: Dict[str, int] = {}
        for h in self._hypotheses.values():
            for t in h.mitre_tactics:
                by_tactic[t] = by_tactic.get(t, 0) + 1

        return {
            "total_hypotheses": total_hypotheses,
            "total_executions": total_executions,
            "total_findings": total_findings,
            "total_extracted_iocs": total_iocs,
            "hypotheses_by_tactic": by_tactic,
        }
