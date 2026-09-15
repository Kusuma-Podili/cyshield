"""
CyberShield Enterprise - Phishing & Email Security Analysis Engine
Provides deep inspection of email headers (SPF/DKIM/DMARC), body link extraction,
Levenshtein typosquatting brand impersonation, credential harvesting heuristics,
attachment macro checks, and composite phishing risk scoring.
"""

from __future__ import annotations

import re
import math
import hashlib
from typing import Dict, Any, List, Optional, Tuple


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


class EmailSecurityAnalyzer:
    """Enterprise multi-stage email inspection and phishing classifier."""

    ENTERPRISE_BRANDS = [
        "microsoft.com", "office365.com", "google.com", "paypal.com",
        "amazon.com", "apple.com", "netflix.com", "bankofamerica.com",
        "chase.com", "wellsfargo.com", "citigroup.com", "linkedin.com",
        "dropbox.com", "docusign.com", "adobe.com", "zoom.us", "irs.gov"
    ]

    CREDENTIAL_HARVESTING_KEYWORDS = [
        "urgent account suspension",
        "verify your identity",
        "confirm password",
        "reset your credentials",
        "unauthorized login attempt",
        "action required within 24 hours",
        "security notice",
        "payment declined",
        "invoice attached",
        "wire transfer confirmation",
        "direct deposit update",
        "mailbox quota exceeded",
        "tax refund notification",
    ]

    HIGH_RISK_ATTACHMENT_EXTENSIONS = {
        ".exe", ".scr", ".vbs", ".js", ".hta", ".iso", ".img",
        ".docm", ".xlsm", ".pptm", ".dotm", ".iqy", ".bat", ".cmd", ".ps1"
    }

    SUSPICIOUS_MACRO_STRINGS = [
        "autoopen", "document_open", "workbook_open",
        "wscript.shell", "powershell", "cmd.exe", "urldownloadtofile",
        "environ", "shell.run", "createobject", "winmgmts"
    ]

    @classmethod
    def analyze_headers(cls, headers: Dict[str, str]) -> Dict[str, Any]:
        """Inspect email transport headers for spoofing, SPF, DKIM, and DMARC alignment."""
        h_lower = {k.lower(): v for k, v in headers.items()}
        from_hdr = h_lower.get("from", "")
        return_path = h_lower.get("return-path", "")
        auth_results = h_lower.get("authentication-results", "")
        spf_hdr = h_lower.get("received-spf", "")
        dkim_hdr = h_lower.get("dkim-signature", "")

        # Extract From email domain
        from_email_match = re.search(r"[\w\.-]+@([\w\.-]+)", from_hdr)
        from_domain = from_email_match.group(1).lower() if from_email_match else ""

        # Extract Return-Path domain
        rp_match = re.search(r"[\w\.-]+@([\w\.-]+)", return_path)
        rp_domain = rp_match.group(1).lower() if rp_match else ""

        # 1. SPF Evaluation
        spf_status = "PASS"
        if "fail" in spf_hdr.lower() or "spf=fail" in auth_results.lower():
            spf_status = "FAIL"
        elif "softfail" in spf_hdr.lower() or "spf=softfail" in auth_results.lower():
            spf_status = "SOFTFAIL"
        elif not spf_hdr and "spf" not in auth_results.lower():
            spf_status = "NONE"

        # 2. DKIM Evaluation
        dkim_status = "PASS"
        if "dkim=fail" in auth_results.lower():
            dkim_status = "FAIL"
        elif not dkim_hdr and "dkim" not in auth_results.lower():
            dkim_status = "NONE"

        # 3. DMARC Evaluation
        dmarc_status = "PASS"
        if "dmarc=fail" in auth_results.lower() or "dmarc=reject" in auth_results.lower():
            dmarc_status = "FAIL"
        elif spf_status == "FAIL" or dkim_status == "FAIL":
            dmarc_status = "FAIL"
        elif spf_status == "NONE" and dkim_status == "NONE":
            dmarc_status = "NONE"

        # Domain Mismatch Detection (Display Name / Sender Mismatch)
        domain_mismatch = False
        if from_domain and rp_domain and from_domain != rp_domain:
            domain_mismatch = True

        header_risk = 0
        reasons = []
        if dmarc_status == "FAIL":
            header_risk += 35
            reasons.append("DMARC alignment failed (Sender domain unauthorized)")
        elif dmarc_status == "NONE":
            header_risk += 15
            reasons.append("No DMARC protection configured on sender domain")

        if spf_status == "FAIL":
            header_risk += 25
            reasons.append("SPF check failed (Unauthorized sending MTA IP)")
        elif spf_status == "SOFTFAIL":
            header_risk += 15
            reasons.append("SPF softfail observed")

        if dkim_status == "FAIL":
            header_risk += 20
            reasons.append("DKIM cryptographic signature verification failed")

        if domain_mismatch:
            header_risk += 20
            reasons.append(f"Header domain mismatch: From '{from_domain}' vs Return-Path '{rp_domain}'")

        return {
            "from_domain": from_domain,
            "return_path_domain": rp_domain,
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
            "domain_mismatch": domain_mismatch,
            "header_risk_points": min(100, header_risk),
            "findings": reasons,
        }

    @classmethod
    def check_brand_impersonation(cls, domain: str) -> Optional[Dict[str, Any]]:
        """Detect lookalike and typosquatted domains using Levenshtein distance."""
        clean_d = domain.lower().strip()
        # Remove common prefixes / subdomains
        clean_d = re.sub(r"^(?:https?://)?(?:www\.)?", "", clean_d).split("/")[0]

        for target in cls.ENTERPRISE_BRANDS:
            if clean_d == target:
                continue

            # Direct substring check with prefixes/suffixes (e.g. login-microsoft.com)
            brand_name = target.split(".")[0]
            if brand_name in clean_d:
                return {
                    "impersonated_brand": target,
                    "suspicious_domain": domain,
                    "technique": "BRAND_SUBSTRING_COMBOSQUATTING",
                    "edit_distance": 0,
                }

            # Levenshtein distance check on domain label
            domain_label = clean_d.split(".")[0]
            dist = levenshtein_distance(domain_label, brand_name)
            if 0 < dist <= 2 and abs(len(domain_label) - len(brand_name)) <= 2:
                return {
                    "impersonated_brand": target,
                    "suspicious_domain": domain,
                    "technique": "TYPOSQUATTING_LEVENSHTEIN",
                    "edit_distance": dist,
                }

        return None

    @classmethod
    def analyze_body(cls, body: str, sender_domain: str = "") -> Dict[str, Any]:
        """Inspect email body text for extracted URLs, urgency triggers, and brand spoofing."""
        # 1. URL Extraction
        url_regex = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*\b"
        urls = re.findall(url_regex, body)

        impersonated_brands = []
        suspicious_urls = []

        for u in urls:
            domain_match = re.search(r"https?://([^/]+)", u)
            if domain_match:
                d = domain_match.group(1).lower()
                imp = cls.check_brand_impersonation(d)
                if imp:
                    impersonated_brands.append(imp)
                    suspicious_urls.append(u)
                elif sender_domain and sender_domain not in d and not any(t in d for t in [".gov", ".edu", ".org"]):
                    suspicious_urls.append(u)

        # 2. Urgency & Credential Harvesting Heuristics
        body_lower = body.lower()
        matched_keywords = []
        for kw in cls.CREDENTIAL_HARVESTING_KEYWORDS:
            if kw in body_lower:
                matched_keywords.append(kw)

        # 3. QR Code Phishing (Quishing) check
        quishing_detected = False
        if "qr code" in body_lower or "scan the code" in body_lower or "camera to scan" in body_lower:
            quishing_detected = True

        body_risk = 0
        if impersonated_brands:
            body_risk += 45
        if len(matched_keywords) >= 2:
            body_risk += 30
        elif len(matched_keywords) == 1:
            body_risk += 15
        if quishing_detected:
            body_risk += 25
        if len(urls) >= 3 and not sender_domain:
            body_risk += 15

        return {
            "total_urls_extracted": len(urls),
            "urls": urls,
            "suspicious_urls": suspicious_urls,
            "impersonated_brands": impersonated_brands,
            "matched_keywords": matched_keywords,
            "quishing_detected": quishing_detected,
            "body_risk_points": min(100, body_risk),
        }

    @classmethod
    def analyze_attachments(
        cls,
        attachments: List[Dict[str, Any]],
        known_malicious_hashes: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Inspect attachments for dangerous extensions, macro heuristics, and known hash matches."""
        known_hashes = set((known_malicious_hashes or []))
        dangerous_attachments = []
        macro_detected_list = []
        hash_matches = []
        attach_risk = 0

        for att in attachments:
            fname = att.get("filename", "unknown.bin")
            ext = "." + fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
            content_sample = att.get("content_sample", "") or ""
            file_hash = att.get("sha256", "")

            if not file_hash and content_sample:
                file_hash = hashlib.sha256(content_sample.encode("utf-8", errors="ignore")).hexdigest()

            # High risk file extension check
            if ext in cls.HIGH_RISK_ATTACHMENT_EXTENSIONS:
                dangerous_attachments.append({"filename": fname, "extension": ext, "risk": "DANGEROUS_EXTENSION"})
                attach_risk += 35

            # Macro heuristics check
            content_lower = content_sample.lower()
            if any(m in content_lower for m in cls.SUSPICIOUS_MACRO_STRINGS):
                macro_detected_list.append({"filename": fname, "indicator": "SUSPICIOUS_VBA_MACRO_BEHAVIOR"})
                attach_risk += 40

            # Hash lookup
            if file_hash and file_hash.lower() in known_hashes:
                hash_matches.append({"filename": fname, "sha256": file_hash})
                attach_risk += 60

        return {
            "total_attachments": len(attachments),
            "dangerous_attachments": dangerous_attachments,
            "macro_detected": macro_detected_list,
            "known_hash_matches": hash_matches,
            "attachment_risk_points": min(100, attach_risk),
        }

    @classmethod
    def evaluate_email(
        cls,
        headers: Dict[str, str],
        body: str,
        attachments: Optional[List[Dict[str, Any]]] = None,
        known_malicious_hashes: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Execute comprehensive end-to-end email security inspection and compute composite phishing score.
        """
        hdr_res = cls.analyze_headers(headers)
        body_res = cls.analyze_body(body, sender_domain=hdr_res["from_domain"])
        att_res = cls.analyze_attachments(attachments or [], known_malicious_hashes)

        # Composite Phishing Risk Calculation (0 - 100)
        # Weighted: 30% Headers + 40% Body & Brand + 30% Attachments
        composite_score = (
            (hdr_res["header_risk_points"] * 0.30) +
            (body_res["body_risk_points"] * 0.40) +
            (att_res["attachment_risk_points"] * 0.30)
        )

        # Immediate escalation override if known malware hash or blatant brand typosquatting
        if att_res["known_hash_matches"]:
            composite_score = max(composite_score, 95.0)
        if body_res["impersonated_brands"] and (hdr_res["spf"] == "FAIL" or hdr_res["dmarc"] == "FAIL"):
            composite_score = max(composite_score, 90.0)

        composite_score = round(min(100.0, composite_score), 1)

        if composite_score >= 85.0:
            classification = "MALICIOUS"
            verdict = "BLOCK_AND_QUARANTINE"
        elif composite_score >= 60.0:
            classification = "PHISHING"
            verdict = "QUARANTINE_WARNING"
        elif composite_score >= 25.0:
            classification = "SUSPICIOUS"
            verdict = "TAG_EXTERNAL_WARNING"
        else:
            classification = "CLEAN"
            verdict = "DELIVER_INBOX"

        all_findings = []
        all_findings.extend(hdr_res["findings"])
        for imp in body_res["impersonated_brands"]:
            all_findings.append(f"Brand Impersonation detected: Target '{imp['impersonated_brand']}' spoofed by '{imp['suspicious_domain']}' ({imp['technique']})")
        if body_res["quishing_detected"]:
            all_findings.append("Quishing heuristic: Image/QR code credential bypass prompt detected")
        for kw in body_res["matched_keywords"]:
            all_findings.append(f"Urgency trigger phrase: '{kw}'")
        for att in att_res["dangerous_attachments"]:
            all_findings.append(f"Dangerous attachment payload: '{att['filename']}' ({att['extension']})")
        for m in att_res["macro_detected"]:
            all_findings.append(f"Suspicious Office macro in attachment: '{m['filename']}'")
        for h in att_res["known_hash_matches"]:
            all_findings.append(f"Critical IoC hit on attachment hash: '{h['sha256']}'")

        return {
            "classification": classification,
            "phishing_score": composite_score,
            "recommended_action": verdict,
            "header_analysis": hdr_res,
            "body_analysis": body_res,
            "attachment_analysis": att_res,
            "findings_summary": all_findings,
        }
