"""
CyberShield Enterprise - Phishing Service
Manages email security inspection workflows, connects attachment hashes to threat intelligence,
and maintains recent analysis logs and telemetry KPIs.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from collections import deque

from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.phishing.email_analyzer import EmailSecurityAnalyzer
from cybershield.intel.feed_service import threat_intel_service


class PhishingService:
    """Enterprise Phishing & Email Threat Defense Service."""

    def __init__(self, max_history: int = 200):
        self._history: deque = deque(maxlen=max_history)
        self._total_scanned = 0
        self._blocked_count = 0
        self._suspicious_count = 0
        self._clean_count = 0
        self._quishing_count = 0
        self._brand_counter: Dict[str, int] = {}
        self._seed_sample_history()

    def _seed_sample_history(self) -> None:
        """Seed initial baseline email analysis telemetry."""
        samples = [
            ("Microsoft Security <no-reply@micros0ft.com>", "Urgent password reset required", "PHISHING", 78.0, "Microsoft"),
            ("PayPal Notifications <service@paypa1-verify.net>", "Unauthorized transaction of $499 detected. Confirm identity.", "MALICIOUS", 92.0, "PayPal"),
            ("HR Dept <hr@company.internal>", "Quarterly benefits review update and open enrollment.", "CLEAN", 10.0, None),
            ("Docusign Signer <sign@docus1gn-cloud.org>", "Sign employment contract document attached.", "PHISHING", 82.0, "DocuSign"),
        ]
        for sender, subj, cls_name, score, brand in samples:
            self._total_scanned += 1
            if cls_name in ("PHISHING", "MALICIOUS"):
                self._blocked_count += 1
            elif cls_name == "SUSPICIOUS":
                self._suspicious_count += 1
            else:
                self._clean_count += 1

            if brand:
                self._brand_counter[brand] = self._brand_counter.get(brand, 0) + 1

            self._history.appendleft({
                "id": f"EML-{uuid.uuid4().hex[:8].upper()}",
                "timestamp": datetime.utcnow().isoformat(),
                "sender": sender,
                "subject": subj,
                "classification": cls_name,
                "score": score,
                "brand_impersonated": brand,
            })

    async def analyze_email(
        self,
        session: Optional[AsyncSession],
        headers: Dict[str, str],
        body: str,
        attachments: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Perform full inspection and record telemetry."""
        # Collect known malicious hashes from attachments
        known_hashes = []
        if attachments and session:
            for att in attachments:
                h = att.get("sha256")
                if h:
                    # Quick lookup in threat intel
                    res = await threat_intel_service.lookup_indicator(session, h)
                    if res["matched"]:
                        known_hashes.append(h.lower())

        report = EmailSecurityAnalyzer.evaluate_email(
            headers=headers,
            body=body,
            attachments=attachments,
            known_malicious_hashes=known_hashes,
        )

        # Update telemetry
        self._total_scanned += 1
        cls_name = report["classification"]
        if cls_name in ("PHISHING", "MALICIOUS"):
            self._blocked_count += 1
        elif cls_name == "SUSPICIOUS":
            self._suspicious_count += 1
        else:
            self._clean_count += 1

        if report["body_analysis"].get("quishing_detected"):
            self._quishing_count += 1

        brand_found = None
        for imp in report["body_analysis"].get("impersonated_brands", []):
            brand_name = imp.get("impersonated_brand", "Unknown")
            self._brand_counter[brand_name] = self._brand_counter.get(brand_name, 0) + 1
            brand_found = brand_name

        record = {
            "id": f"EML-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": datetime.utcnow().isoformat(),
            "sender": headers.get("From", "Unknown"),
            "subject": headers.get("Subject", "No Subject"),
            "classification": cls_name,
            "score": report["phishing_score"],
            "brand_impersonated": brand_found,
            "report": report,
        }
        self._history.appendleft(record)
        return record

    def get_recent_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recently analyzed email reports."""
        return list(self._history)[:limit]

    def get_kpis(self) -> Dict[str, Any]:
        """Compute email defense summary metrics."""
        top_brands = [
            {"brand": k, "count": v}
            for k, v in sorted(self._brand_counter.items(), key=lambda x: x[1], reverse=True)[:5]
        ]
        return {
            "total_emails_scanned": self._total_scanned,
            "phishing_blocked": self._blocked_count,
            "suspicious_tagged": self._suspicious_count,
            "clean_delivered": self._clean_count,
            "quishing_attacks_detected": self._quishing_count,
            "top_impersonated_brands": top_brands,
        }


phishing_service = PhishingService()
