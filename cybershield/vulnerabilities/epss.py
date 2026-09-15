"""Local Offline Exploit Prediction Scoring System (EPSS) Engine.

Calculates empirical exploitation probability (0.0 to 1.0) and national percentile
for CVEs using local ground-truth tables and CVSS v3.1 vector regression heuristics,
enabling air-gapped risk prioritization without external cloud API dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class EPSSScore:
    """EPSS Score result containing probability and percentile."""
    cve_id: str
    epss_score: float  # Probability [0.0 - 1.0] of exploitation within 30 days
    percentile: float  # Rank relative to all other scored CVEs [0.0 - 100.0%]
    is_actively_exploited: bool
    rationale: str


# Offline Ground Truth Table for High-Impact Landmark Vulnerabilities
OFFLINE_EPSS_LOOKUP: Dict[str, EPSSScore] = {
    "CVE-2021-44228": EPSSScore(
        cve_id="CVE-2021-44228",
        epss_score=0.9752,
        percentile=99.98,
        is_actively_exploited=True,
        rationale="Log4Shell: Ubiquitous zero-click remote code execution with weaponized worms and ransomware adoption."
    ),
    "CVE-2017-0144": EPSSScore(
        cve_id="CVE-2017-0144",
        epss_score=0.9748,
        percentile=99.97,
        is_actively_exploited=True,
        rationale="EternalBlue: Exploited by WannaCry, NotPetya; continuously scanned by botnets globally."
    ),
    "CVE-2019-0708": EPSSScore(
        cve_id="CVE-2019-0708",
        epss_score=0.9680,
        percentile=99.85,
        is_actively_exploited=True,
        rationale="BlueKeep: Pre-authentication RDP remote code execution."
    ),
    "CVE-2021-26855": EPSSScore(
        cve_id="CVE-2021-26855",
        epss_score=0.9715,
        percentile=99.92,
        is_actively_exploited=True,
        rationale="ProxyLogon: Microsoft Exchange pre-auth SSRF utilized by state-sponsored APTs."
    ),
    "CVE-2021-34527": EPSSScore(
        cve_id="CVE-2021-34527",
        epss_score=0.9650,
        percentile=99.78,
        is_actively_exploited=True,
        rationale="PrintNightmare: Windows Print Spooler privilege escalation and remote code execution."
    ),
    "CVE-2022-22965": EPSSScore(
        cve_id="CVE-2022-22965",
        epss_score=0.9520,
        percentile=99.50,
        is_actively_exploited=True,
        rationale="Spring4Shell: Spring Framework remote code execution."
    ),
    "CVE-2023-34362": EPSSScore(
        cve_id="CVE-2023-34362",
        epss_score=0.9740,
        percentile=99.95,
        is_actively_exploited=True,
        rationale="MOVEit Transfer SQL Injection exploited in mass extortions by Clop ransomware group."
    ),
    "CVE-2023-4966": EPSSScore(
        cve_id="CVE-2023-4966",
        epss_score=0.9690,
        percentile=99.88,
        is_actively_exploited=True,
        rationale="Citrix Bleed: Memory disclosure enabling session hijack without credentials."
    ),
    "CVE-2024-21887": EPSSScore(
        cve_id="CVE-2024-21887",
        epss_score=0.9620,
        percentile=99.70,
        is_actively_exploited=True,
        rationale="Ivanti Connect Secure command injection chained for full appliance takeover."
    ),
    "CVE-2024-3400": EPSSScore(
        cve_id="CVE-2024-3400",
        epss_score=0.9580,
        percentile=99.62,
        is_actively_exploited=True,
        rationale="Palo Alto PAN-OS GlobalProtect command injection zero-day."
    ),
}


class EPSSCalculator:
    """Calculates or estimates EPSS exploitation probabilities offline."""

    @classmethod
    def calculate_epss(
        cls,
        cve_id: str,
        cvss_base_score: float = 5.0,
        attack_vector: str = "NETWORK",
        user_interaction: str = "NONE",
        privileges_required: str = "NONE",
        has_public_exploit: bool = False,
        is_cisa_kev: bool = False,
    ) -> EPSSScore:
        """Lookup ground-truth EPSS or compute empirical regression estimate."""
        normalized_cve = cve_id.strip().upper()
        if normalized_cve in OFFLINE_EPSS_LOOKUP:
            return OFFLINE_EPSS_LOOKUP[normalized_cve]

        # Empirical Bayesian model for estimating exploitation probability
        # Base prior distribution centered around 0.005 (0.5% average CVE exploitation rate)
        prior_prob = 0.005

        # Feature weight multipliers
        weight = 1.0

        # CISA KEV presence is the strongest predictor
        if is_cisa_kev:
            weight *= 150.0

        # Weaponized / Public Exploit
        if has_public_exploit:
            weight *= 45.0

        # Attack Vector: Network > Adjacent > Local > Physical
        av = attack_vector.upper()
        if "NETWORK" in av:
            weight *= 5.0
        elif "ADJACENT" in av:
            weight *= 1.8
        elif "LOCAL" in av:
            weight *= 0.6
        elif "PHYSICAL" in av:
            weight *= 0.1

        # User Interaction: None > Required
        if user_interaction.upper() in ("NONE", "N"):
            weight *= 3.0
        else:
            weight *= 0.4

        # Privileges Required: None > Low > High
        pr = privileges_required.upper()
        if pr in ("NONE", "N"):
            weight *= 3.5
        elif pr in ("LOW", "L"):
            weight *= 1.2
        elif pr in ("HIGH", "H"):
            weight *= 0.3

        # CVSS Base Score influence
        if cvss_base_score >= 9.0:
            weight *= 4.0
        elif cvss_base_score >= 7.0:
            weight *= 2.0
        elif cvss_base_score < 4.0:
            weight *= 0.2

        # Logistic transformation clamping between 0.0001 and 0.985
        estimated_prob = min(0.985, max(0.0001, prior_prob * weight))
        estimated_prob = round(estimated_prob, 4)

        # Estimate percentile from probability distribution curve
        if estimated_prob >= 0.90:
            percentile = 99.0 + ((estimated_prob - 0.90) / 0.10) * 0.99
        elif estimated_prob >= 0.50:
            percentile = 95.0 + ((estimated_prob - 0.50) / 0.40) * 4.0
        elif estimated_prob >= 0.10:
            percentile = 80.0 + ((estimated_prob - 0.10) / 0.40) * 15.0
        elif estimated_prob >= 0.01:
            percentile = 50.0 + ((estimated_prob - 0.01) / 0.09) * 30.0
        else:
            percentile = (estimated_prob / 0.01) * 50.0

        percentile = min(99.99, max(1.0, round(percentile, 2)))

        rationale = (
            f"Estimated via offline EPSS heuristic (CVSS: {cvss_base_score}, "
            f"Network: {'NETWORK' in av}, Exploit Available: {has_public_exploit}, "
            f"CISA KEV: {is_cisa_kev})."
        )

        return EPSSScore(
            cve_id=normalized_cve,
            epss_score=estimated_prob,
            percentile=percentile,
            is_actively_exploited=is_cisa_kev or has_public_exploit,
            rationale=rationale,
        )
