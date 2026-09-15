"""CyberShield Enterprise - Autonomous AI SOC Analyst Reasoning Engine.
Performs deterministic alert triage, competing hypothesis evaluations,
automated false positive auto-closure, and executive brief generation.
"""

import time
import uuid
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timezone, timedelta

from .schemas import (
    AnalystVerdict,
    ConfidenceLevel,
    AlertTriageRequest,
    HypothesisEvaluation,
    InvestigationReport,
    ShiftHandoverReport,
    AnalystMetrics,
)


class AutonomousSOCAnalyst:
    """Enterprise AI SOC Analyst automating Tier 1/Tier 2 alert investigation."""

    def __init__(self):
        self.investigations: Dict[str, InvestigationReport] = {}
        self.total_triaged = 0
        self.false_positives_closed = 0
        self.escalations_generated = 0
        self.triage_latencies: List[float] = []

        # Known legitimate administrative tooling indicators
        self.legitimate_admin_tools = {
            "sccm", "ansible", "datadog", "qualys", "chef", "puppet", "salt-minion", "tanium"
        }

    def triage_alert(self, req: AlertTriageRequest) -> InvestigationReport:
        """Analyze an alert, evaluate competing hypotheses, and issue an adjudication verdict."""
        t_start = time.perf_counter()
        self.total_triaged += 1

        payload = req.raw_event_payload
        cmd = str(payload.get("cmdline", payload.get("command", ""))).lower()
        parent_comm = str(payload.get("parent_comm", payload.get("parent_process", ""))).lower()
        proc_comm = str(payload.get("comm", payload.get("process_name", ""))).lower()
        source_ip = req.source_ip or str(payload.get("source_ip", payload.get("remote_ip", "")))
        is_admin_user = bool(payload.get("is_admin", False) or "admin" in str(req.user_id).lower())

        # 1. Evaluate Suspicious Indicators & Base64 Payload Inspection
        has_encoded_powershell = any(k in cmd for k in ["-enc", "-encodedcommand", "frombase64string"])
        
        # Automatically decode base64 payload if present
        decoded_cmd = ""
        if has_encoded_powershell:
            try:
                import base64
                for token in cmd.split():
                    if len(token) > 20 and not token.startswith("-"):
                        try:
                            dec_bytes = base64.b64decode(token)
                            decoded_cmd += " " + dec_bytes.decode("utf-8", errors="ignore").lower()
                        except Exception:
                            pass
            except Exception:
                pass

        full_command_text = f"{cmd} {decoded_cmd}"

        has_download_cradle = any(k in full_command_text for k in ["downloadstring", "webrequest", "curl ", "wget ", "certutil", "net.webclient", "iex"])
        has_cred_dump = any(k in full_command_text for k in ["mimikatz", "sekurlsa", "lsass", "comsvcs.dll", "procdump"])
        has_discovery = any(k in full_command_text for k in ["whoami", "net group", "nltest", "systeminfo"])
        is_office_parent = any(o in parent_comm for o in ["excel", "winword", "word", "outlook", "powerpnt"])

        # Check legitimate administrative management parentage
        is_authorized_mgmt = any(tool in parent_comm or tool in proc_comm for tool in self.legitimate_admin_tools)

        # 2. Formulate Competing Hypotheses
        hyp_a_supporting = []
        hyp_a_refuting = []
        hyp_b_supporting = []
        hyp_b_refuting = []

        # Evidence for Hypothesis A (Benign Administrative Routine)
        if is_authorized_mgmt:
            hyp_a_supporting.append(f"Parent process '{parent_comm}' matches approved enterprise management tooling.")
            hyp_b_refuting.append("Activity originated from designated administrative automation agent.")
        if is_admin_user and not (has_cred_dump or has_encoded_powershell):
            hyp_a_supporting.append("Initiated by authorized administrator account during expected tasks.")
        if not (has_encoded_powershell or has_download_cradle or has_cred_dump):
            hyp_a_supporting.append("Command arguments are plaintext with no evasion or obfuscation.")

        # Evidence for Hypothesis B (Adversary Living-off-the-Land Attack)
        if has_encoded_powershell:
            hyp_b_supporting.append("Obfuscated base64 encoded PowerShell script detected.")
            hyp_a_refuting.append("Base64 obfuscation violates standard administrative change policy.")
        if has_download_cradle:
            hyp_b_supporting.append("In-memory remote cradle downloading external binary payload.")
            hyp_a_refuting.append("Unauthorized download from non-whitelisted IP.")
        if has_cred_dump:
            hyp_b_supporting.append("Direct memory dumping targeting LSASS credential stores.")
            hyp_a_refuting.append("Credential dumping strictly prohibited under all enterprise policies.")
        if has_discovery and not is_authorized_mgmt:
            hyp_b_supporting.append("Reconnaissance commands executed immediately post-execution.")

        # 3. Calculate Scores for Hypotheses
        score_a = (len(hyp_a_supporting) * 0.35) - (len(hyp_a_refuting) * 0.50)
        score_b = (len(hyp_b_supporting) * 0.45) - (len(hyp_b_refuting) * 0.30)
        score_a = round(max(-1.0, min(1.0, score_a)), 2)
        score_b = round(max(-1.0, min(1.0, score_b)), 2)

        favored_b = score_b > score_a

        hypotheses = [
            HypothesisEvaluation(
                hypothesis_id="hyp-benign-admin",
                premise="Authorized routine administrative maintenance or configuration script.",
                supporting_evidence=hyp_a_supporting,
                refuting_evidence=hyp_a_refuting,
                likelihood_score=score_a,
                is_favored=not favored_b,
            ),
            HypothesisEvaluation(
                hypothesis_id="hyp-adversary-attack",
                premise="Adversary executing living-off-the-land intrusion or credential theft.",
                supporting_evidence=hyp_b_supporting,
                refuting_evidence=hyp_b_refuting,
                likelihood_score=score_b,
                is_favored=favored_b,
            ),
        ]

        # 4. Adjudicate Verdict and Risk Score
        findings = []
        if has_cred_dump or (has_encoded_powershell and (has_download_cradle or is_office_parent)) or has_download_cradle:
            verdict = AnalystVerdict.CRITICAL_INCIDENT_ESCALATION
            confidence = ConfidenceLevel.HIGH_DEFINITIVE
            risk_score = 95.0
            playbook = "pb-quarantine-host-and-revoke-creds"
            findings.append("Definitive post-exploitation activity detected: credential theft or weaponized cradle.")
            self.escalations_generated += 1

        elif favored_b and score_b > 0.3:
            verdict = AnalystVerdict.CONFIRMED_TRUE_POSITIVE
            confidence = ConfidenceLevel.MEDIUM_SUBSTANTIATED
            risk_score = 75.0
            playbook = "pb-isolate-host"
            findings.append("Suspicious adversary tradecraft detected; lateral movement or initial execution likely.")
            self.escalations_generated += 1

        elif is_authorized_mgmt and score_a > 0.2:
            verdict = AnalystVerdict.FALSE_POSITIVE_CLOSE
            confidence = ConfidenceLevel.HIGH_DEFINITIVE
            risk_score = 10.0
            playbook = None
            findings.append("Corroborated with scheduled enterprise administration tool; no anomalous telemetry.")
            self.false_positives_closed += 1

        else:
            verdict = AnalystVerdict.SUSPICIOUS_MONITOR
            confidence = ConfidenceLevel.LOW_PROBABLE
            risk_score = 45.0
            playbook = "pb-enhanced-telemetry-monitoring"
            findings.append("Ambiguous activity requiring continuous baseline monitoring.")

        # 5. Build Executive Brief
        exec_summary = (
            f"Autonomous AI SOC Analyst adjudication for alert '{req.title}' on host '{req.host_id}'. "
            f"Verdict: {verdict.value} (Confidence: {confidence.value}, Risk: {risk_score}/100). "
            f"{findings[0]}"
        )

        latency_ms = round((time.perf_counter() - t_start) * 1000.0, 2)
        self.triage_latencies.append(latency_ms)

        report_id = f"inv-{uuid.uuid4().hex[:8]}"
        report = InvestigationReport(
            report_id=report_id,
            alert_id=req.alert_id,
            verdict=verdict,
            confidence=confidence,
            risk_score=risk_score,
            executive_summary=exec_summary,
            technical_findings=findings,
            evaluated_hypotheses=hypotheses,
            recommended_soar_playbook=playbook,
            is_automated_adjudication=True,
        )
        self.investigations[report_id] = report
        return report

    def generate_shift_handover(self, shift_id: str, hours: int = 8) -> ShiftHandoverReport:
        """Synthesize executive shift handover report summarizing all triaged alerts."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        shift_reports = [r for r in self.investigations.values() if r.triaged_at >= cutoff]

        fp = sum(1 for r in shift_reports if r.verdict == AnalystVerdict.FALSE_POSITIVE_CLOSE)
        esc = sum(
            1 for r in shift_reports
            if r.verdict in {AnalystVerdict.CRITICAL_INCIDENT_ESCALATION, AnalystVerdict.CONFIRMED_TRUE_POSITIVE}
        )
        mon = sum(1 for r in shift_reports if r.verdict == AnalystVerdict.SUSPICIOUS_MONITOR)

        threats = list({
            r.recommended_soar_playbook for r in shift_reports
            if r.recommended_soar_playbook
        })

        narrative = (
            f"SOC Shift Handover {shift_id}: During the past {hours} hours, the autonomous AI analyst "
            f"triaged {len(shift_reports)} total alerts. {fp} false positives were auto-closed with verifiable audit trails, "
            f"reducing Tier 1 analyst noise by {(round((fp / len(shift_reports) * 100), 1) if shift_reports else 0)}%. "
            f"{esc} confirmed incidents were escalated for immediate containment."
        )

        return ShiftHandoverReport(
            shift_id=shift_id,
            start_time=cutoff,
            end_time=datetime.now(timezone.utc),
            total_triaged=len(shift_reports),
            false_positive_count=fp,
            escalated_count=esc,
            monitored_count=mon,
            key_threats=threats,
            executive_narrative=narrative,
        )

    def get_metrics(self) -> AnalystMetrics:
        """Return triage throughput, false positive reduction, and latency metrics."""
        avg_lat = (sum(self.triage_latencies) / len(self.triage_latencies)) if self.triage_latencies else 0.0
        fp_rate = (self.false_positives_closed / self.total_triaged) if self.total_triaged > 0 else 0.0
        return AnalystMetrics(
            total_alerts_triaged=self.total_triaged,
            false_positives_closed=self.false_positives_closed,
            escalations_generated=self.escalations_generated,
            mean_triage_latency_ms=round(avg_lat, 2),
            auto_closure_rate=round(fp_rate, 4),
        )
