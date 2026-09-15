"""Domain Generation Algorithm (DGA) Sequence & N-Gram Classifier.

Classifies domain names queried across DNS telemetry as legitimate or algorithmically
generated C2 domains (Conficker, Locky, Suppobox, Mirai) using character entropy,
n-gram transition likelihood, vowel-consonant ratios, and digit distributions.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class DGAClassificationResult:
    domain: str
    is_dga: bool
    dga_probability: float  # 0.0 (benign) to 1.0 (definitely DGA)
    shannon_entropy: float
    vowel_ratio: float
    digit_ratio: float
    max_consonant_streak: int
    matched_family_estimate: Optional[str] = None
    reasons: List[str] = field(default_factory=list)


# Frequent English bigrams for transition likelihood analysis
COMMON_BIGRAMS = {
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
    "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
    "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
    "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea"
}


class DGAClassifier:
    """Enterprise statistical and sequence classifier for DGA domain detection."""

    @classmethod
    def calculate_shannon_entropy(cls, text: str) -> float:
        """Calculate Shannon entropy in bits per character."""
        if not text:
            return 0.0
        counts = Counter(text)
        total = len(text)
        return -sum((cnt / total) * math.log2(cnt / total) for cnt in counts.values())

    @classmethod
    def extract_domain_label(cls, domain: str) -> str:
        """Extract the core second-level domain (SLD) label."""
        cleaned = domain.lower().strip().rstrip(".")
        parts = cleaned.split(".")
        if len(parts) >= 2:
            return parts[-2]
        return parts[0]

    @classmethod
    def classify_domain(cls, domain: str) -> DGAClassificationResult:
        """Evaluate a domain and return DGA probability and feature indicators."""
        label = cls.extract_domain_label(domain)
        label_len = len(label)

        if label_len <= 3:
            return DGAClassificationResult(
                domain=domain,
                is_dga=False,
                dga_probability=0.01,
                shannon_entropy=cls.calculate_shannon_entropy(label),
                vowel_ratio=0.5,
                digit_ratio=0.0,
                max_consonant_streak=1,
                matched_family_estimate=None,
                reasons=["Domain label too short to be algorithmic DGA"],
            )

        entropy = cls.calculate_shannon_entropy(label)
        vowels = sum(1 for c in label if c in "aeiou")
        digits = sum(1 for c in label if c.isdigit())
        consonants = sum(1 for c in label if c.isalpha() and c not in "aeiou")

        vowel_ratio = round(vowels / max(1, vowels + consonants), 3)
        digit_ratio = round(digits / label_len, 3)

        # Longest consecutive consonant streak
        consonant_streaks = re.findall(r"[bcdfghjklmnpqrstvwxyz]+", label)
        max_streak = max((len(s) for s in consonant_streaks), default=0)

        # Bigram frequency score
        bigrams = [label[i : i + 2] for i in range(len(label) - 1)]
        common_count = sum(1 for bg in bigrams if bg in COMMON_BIGRAMS)
        bigram_ratio = (common_count / max(1, len(bigrams)))

        reasons = []
        dga_score = 0.0

        # High entropy is strongly characteristic of pseudo-random generators
        if entropy > 3.6:
            dga_score += 0.40
            reasons.append(f"High Shannon entropy: {entropy:.2f} bits/char (threshold: 3.6)")
        elif entropy > 3.2:
            dga_score += 0.20

        # Unbalanced vowel ratio (very low or very high)
        if vowel_ratio < 0.20:
            dga_score += 0.25
            reasons.append(f"Abnormally low vowel ratio: {vowel_ratio * 100:.1f}%")
        elif vowel_ratio > 0.70:
            dga_score += 0.20
            reasons.append(f"Abnormally high vowel ratio: {vowel_ratio * 100:.1f}%")

        # Long streaks of consonants
        if max_streak >= 5:
            dga_score += 0.30
            reasons.append(f"Unpronounceable consonant streak of length {max_streak}")
        elif max_streak == 4:
            dga_score += 0.15

        # Mixed digit injection
        if 0.10 < digit_ratio < 0.80 and any(c.isalpha() for c in label):
            dga_score += 0.25
            reasons.append(f"Mixed alphanumeric character distribution (digits: {digit_ratio * 100:.1f}%)")

        # Low English bigram transition density
        if bigram_ratio < 0.15 and label_len >= 8:
            dga_score += 0.20
            reasons.append(f"Low natural language bigram transition rate: {bigram_ratio * 100:.1f}%")

        # Clamping
        prob = min(0.99, max(0.01, round(dga_score, 3)))
        is_dga = prob >= 0.50

        # Family heuristic estimation
        family = None
        if is_dga:
            if digits > 3 and entropy > 3.8:
                family = "Locky / Necurs Variant"
            elif max_streak >= 6:
                family = "Suppobox / Conficker Family"
            else:
                family = "Generic High-Entropy C2 DGA"

        return DGAClassificationResult(
            domain=domain,
            is_dga=is_dga,
            dga_probability=prob,
            shannon_entropy=round(entropy, 3),
            vowel_ratio=vowel_ratio,
            digit_ratio=digit_ratio,
            max_consonant_streak=max_streak,
            matched_family_estimate=family,
            reasons=reasons,
        )
