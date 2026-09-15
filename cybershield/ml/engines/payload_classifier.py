"""
CyberShield Enterprise - Multi-Class Payload Attack Classifier
Uses TF-IDF Character/Word N-Gram Vectorization and Multinomial Naive Bayes
to detect and classify Web & API attacks (SQLi, XSS, Command Injection, Path Traversal).
"""

from __future__ import annotations

import os
import re
import time
import pickle
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score


class PayloadClassifierEngine:
    """Enterprise Web Attack Payload Classifier Engine."""

    CLASSES = [
        "BENIGN",
        "SQL_INJECTION",
        "CROSS_SITE_SCRIPTING",
        "COMMAND_INJECTION",
        "PATH_TRAVERSAL",
    ]

    EXPLAINABILITY_RULES = {
        "SQL_INJECTION": [
            r"(?i)\bUNION\b\s+\bSELECT\b",
            r"(?i)'\s*OR\s*'?[0-9a-z]'?='?[0-9a-z]",
            r"(?i)\bWAITFOR\b\s+\bDELAY\b",
            r"(?i)\bDROP\b\s+\bTABLE\b",
            r"(?i)\bSLEEP\s*\(\s*\d+\s*\)",
            r"--|#|/\*.*?\*/",
        ],
        "CROSS_SITE_SCRIPTING": [
            r"(?i)<script\b",
            r"(?i)onerror\s*=",
            r"(?i)onload\s*=",
            r"(?i)javascript:",
            r"(?i)document\.cookie",
            r"(?i)alert\s*\(",
        ],
        "COMMAND_INJECTION": [
            r";\s*(cat|ls|id|whoami|uname|rm|curl|wget)\b",
            r"\|\s*(cat|ls|id|whoami|uname|nc|bash|sh)\b",
            r"&&\s*(powershell|cmd|whoami|cat|id)\b",
            r"\$\(whoami\)",
            r"`cat\s+",
        ],
        "PATH_TRAVERSAL": [
            r"\.\./\.\./",
            r"\.\.\\\.\.\\",
            r"/etc/(passwd|shadow|hosts)",
            r"system32\\drivers\\etc\\hosts",
            r"%2e%2e%2f",
            r"\.\.%2f",
        ],
    }

    def __init__(self, max_features: int = 5000):
        self.max_features = max_features
        self.vectorizer: Optional[TfidfVectorizer] = None
        self.classifier: Optional[MultinomialNB] = None
        self.is_trained: bool = False
        self.training_metrics: Dict[str, Any] = {}

    def fit(self, dataset: List[Tuple[str, str]]) -> Dict[str, Any]:
        """
        Train TF-IDF Vectorizer and Multinomial Naive Bayes classifier on payload data.
        dataset: List of (payload_text, label)
        """
        start_time = time.perf_counter()

        if len(dataset) < 20:
            raise ValueError("Dataset must contain at least 20 samples for training.")

        texts = [p[0] for p in dataset]
        labels = [p[1] for p in dataset]

        # Stratified train/test split
        X_train_raw, X_test_raw, y_train, y_test = train_test_split(
            texts, labels, test_size=0.2, random_state=42, stratify=labels
        )

        # Fit Vectorizer using sub-word char and word n-grams
        self.vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(2, 5),
            max_features=self.max_features,
            sublinear_tf=True,
        )
        X_train = self.vectorizer.fit_transform(X_train_raw)
        X_test = self.vectorizer.transform(X_test_raw)

        # Fit Classifier
        self.classifier = MultinomialNB(alpha=0.1)
        self.classifier.fit(X_train, y_train)
        self.is_trained = True

        duration = time.perf_counter() - start_time

        # Evaluate performance
        y_pred = self.classifier.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)
        c_matrix = confusion_matrix(y_test, y_pred, labels=self.CLASSES).tolist()
        report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

        self.training_metrics = {
            "samples_total": len(dataset),
            "samples_train": len(X_train_raw),
            "samples_test": len(X_test_raw),
            "accuracy": round(float(acc), 4),
            "weighted_f1": round(float(f1), 4),
            "confusion_matrix": c_matrix,
            "classes": self.CLASSES,
            "classification_report": report,
            "training_duration_sec": round(duration, 3),
        }
        return self.training_metrics

    def predict(self, payload: str) -> Dict[str, Any]:
        """
        Classify a single payload string and return class probabilities,
        confidence score, and matched explainability tokens.
        """
        start_time = time.perf_counter()

        if not self.is_trained or self.vectorizer is None or self.classifier is None:
            # Auto-train default model if not yet trained
            from cybershield.ml.datasets.generator import SecurityDatasetGenerator
            synth = SecurityDatasetGenerator.generate_payload_dataset(n_samples=500)
            self.fit(synth)

        X_vec = self.vectorizer.transform([payload])
        probs = self.classifier.predict_proba(X_vec)[0]
        classes = list(self.classifier.classes_)

        prob_dict: Dict[str, float] = {}
        for c, p in zip(classes, probs):
            prob_dict[c] = round(float(p), 4)

        # Ensure all standard classes exist in prob_dict
        for c in self.CLASSES:
            if c not in prob_dict:
                prob_dict[c] = 0.0

        best_class = max(prob_dict, key=prob_dict.get)
        confidence = prob_dict[best_class]

        # Extract explainability indicators
        matched_indicators = []
        rules = self.EXPLAINABILITY_RULES.get(best_class, [])
        for pattern in rules:
            match = re.search(pattern, payload)
            if match:
                matched_indicators.append(match.group(0))

        # Risk Level
        if best_class == "BENIGN":
            risk_level = "CLEAN"
        elif confidence > 0.85:
            risk_level = "CRITICAL"
        elif confidence > 0.60:
            risk_level = "HIGH"
        else:
            risk_level = "MEDIUM"

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)

        return {
            "payload": payload,
            "predicted_class": best_class,
            "confidence": confidence,
            "probabilities": prob_dict,
            "matched_indicators": list(set(matched_indicators)),
            "risk_level": risk_level,
            "latency_ms": elapsed_ms,
        }

    def save(self, filepath: str) -> None:
        """Serialize model to disk."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "wb") as f:
            pickle.dump({
                "vectorizer": self.vectorizer,
                "classifier": self.classifier,
                "max_features": self.max_features,
                "training_metrics": self.training_metrics,
            }, f)

    def load(self, filepath: str) -> None:
        """Deserialize model from disk."""
        with open(filepath, "rb") as f:
            data = pickle.load(f)
            self.vectorizer = data["vectorizer"]
            self.classifier = data["classifier"]
            self.max_features = data["max_features"]
            self.training_metrics = data.get("training_metrics", {})
            self.is_trained = True
