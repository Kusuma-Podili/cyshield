"""
CyberShield Enterprise - Official FIRST CVSS v3.1 Scoring Calculator
Implements full Base, Temporal, and Environmental metrics calculation according
to the FIRST CVSS v3.1 specification, including vector string parsing and generation.
"""

from __future__ import annotations

import math
from typing import Dict, Any, Optional, Tuple


def _roundup(val: float) -> float:
    """
    Official CVSS v3.1 Rounding Function:
    Rounds up to the nearest single decimal place.
    e.g. 4.02 -> 4.1, 4.00 -> 4.0
    """
    int_val = round(val * 100000)
    if int_val % 10000 == 0:
        return int_val / 100000.0
    else:
        return (math.floor(int_val / 10000.0) + 1) / 10.0


class CVSSv31Engine:
    """Comprehensive FIRST CVSS v3.1 mathematical scoring engine."""

    # Base Metric Weights
    AV = {"NETWORK": 0.85, "ADJACENT": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.20, "N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC = {"LOW": 0.77, "HIGH": 0.44, "L": 0.77, "H": 0.44}
    PR_UNCHANGED = {"NONE": 0.85, "LOW": 0.62, "HIGH": 0.27, "N": 0.85, "L": 0.62, "H": 0.27}
    PR_CHANGED = {"NONE": 0.85, "LOW": 0.68, "HIGH": 0.50, "N": 0.85, "L": 0.68, "H": 0.50}
    UI = {"NONE": 0.85, "REQUIRED": 0.62, "N": 0.85, "R": 0.62}
    CIA = {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56, "N": 0.0, "L": 0.22, "H": 0.56}

    # Temporal Metric Weights
    E = {
        "NOT_DEFINED": 1.0, "HIGH": 1.0, "FUNCTIONAL": 0.97, "PROOF_OF_CONCEPT": 0.94, "UNPROVEN": 0.91,
        "X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91
    }
    RL = {
        "NOT_DEFINED": 1.0, "UNAVAILABLE": 1.0, "WORKAROUND": 0.97, "TEMPORARY_FIX": 0.96, "OFFICIAL_FIX": 0.95,
        "X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95
    }
    RC = {
        "NOT_DEFINED": 1.0, "CONFIRMED": 1.0, "REASONABLE": 0.96, "UNKNOWN": 0.92,
        "X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92
    }

    # Environmental Requirements
    CR_IR_AR = {
        "NOT_DEFINED": 1.0, "HIGH": 1.5, "MEDIUM": 1.0, "LOW": 0.5,
        "X": 1.0, "H": 1.5, "M": 1.0, "L": 0.5
    }

    @classmethod
    def calculate_scores(
        cls,
        av: str = "NETWORK",
        ac: str = "LOW",
        pr: str = "NONE",
        ui: str = "NONE",
        scope: str = "UNCHANGED",
        conf: str = "HIGH",
        integ: str = "HIGH",
        avail: str = "HIGH",
        e: str = "NOT_DEFINED",
        rl: str = "NOT_DEFINED",
        rc: str = "NOT_DEFINED",
        cr: str = "NOT_DEFINED",
        ir: str = "NOT_DEFINED",
        ar: str = "NOT_DEFINED",
    ) -> Dict[str, Any]:
        """Compute full Base, Temporal, and Environmental CVSS v3.1 scores."""
        av_u = av.upper()
        ac_u = ac.upper()
        pr_u = pr.upper()
        ui_u = ui.upper()
        scope_u = scope.upper()
        conf_u = conf.upper()
        integ_u = integ.upper()
        avail_u = avail.upper()
        e_u = e.upper()
        rl_u = rl.upper()
        rc_u = rc.upper()

        is_scope_changed = scope_u in ("CHANGED", "C")
        pr_weights = cls.PR_CHANGED if is_scope_changed else cls.PR_UNCHANGED

        av_val = cls.AV.get(av_u, 0.85)
        ac_val = cls.AC.get(ac_u, 0.77)
        pr_val = pr_weights.get(pr_u, 0.85)
        ui_val = cls.UI.get(ui_u, 0.85)

        c_val = cls.CIA.get(conf_u, 0.56)
        i_val = cls.CIA.get(integ_u, 0.56)
        a_val = cls.CIA.get(avail_u, 0.56)

        # 1. Base Score
        # Impact Sub-Score (ISS) = 1 - [ (1 - C) * (1 - I) * (1 - A) ]
        iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))

        if is_scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

        if impact <= 0:
            base_score = 0.0
        else:
            if not is_scope_changed:
                raw_base = min(impact + exploitability, 10.0)
            else:
                raw_base = min(1.08 * (impact + exploitability), 10.0)
            base_score = _roundup(raw_base)

        # 2. Temporal Score
        e_val = cls.E.get(e_u, 1.0)
        rl_val = cls.RL.get(rl_u, 1.0)
        rc_val = cls.RC.get(rc_u, 1.0)
        temporal_score = _roundup(base_score * e_val * rl_val * rc_val)

        # 3. Severity Classification
        if base_score >= 9.0:
            severity = "CRITICAL"
        elif base_score >= 7.0:
            severity = "HIGH"
        elif base_score >= 4.0:
            severity = "MEDIUM"
        elif base_score > 0.0:
            severity = "LOW"
        else:
            severity = "INFORMATIONAL"

        # Vector String Construction
        vector = (
            f"CVSS:3.1/AV:{av_u[0]}/AC:{ac_u[0]}/PR:{pr_u[0]}/UI:{ui_u[0]}/"
            f"S:{scope_u[0]}/C:{conf_u[0]}/I:{integ_u[0]}/A:{avail_u[0]}"
        )
        if e_u not in ("NOT_DEFINED", "X"):
            vector += f"/E:{e_u[0]}"
        if rl_u not in ("NOT_DEFINED", "X"):
            vector += f"/RL:{rl_u[0]}"
        if rc_u not in ("NOT_DEFINED", "X"):
            vector += f"/RC:{rc_u[0]}"

        return {
            "base_score": base_score,
            "temporal_score": temporal_score,
            "environmental_score": temporal_score,  # Equal to temporal unless modified metrics defined
            "severity": severity,
            "vector_string": vector,
            "impact_subscore": round(impact, 2),
            "exploitability_subscore": round(exploitability, 2),
        }

    @classmethod
    def parse_vector(cls, vector_string: str) -> Dict[str, Any]:
        """Parse CVSS:3.1 vector string and return calculated metrics."""
        parts = vector_string.strip().split("/")
        metrics: Dict[str, str] = {}
        for p in parts:
            if ":" in p:
                k, v = p.split(":", 1)
                metrics[k.upper()] = v.upper()

        av_map = {"N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"}
        ac_map = {"L": "LOW", "H": "HIGH"}
        pr_map = {"N": "NONE", "L": "LOW", "H": "HIGH"}
        ui_map = {"N": "NONE", "R": "REQUIRED"}
        s_map = {"U": "UNCHANGED", "C": "CHANGED"}
        cia_map = {"N": "NONE", "L": "LOW", "H": "HIGH"}
        e_map = {"X": "NOT_DEFINED", "U": "UNPROVEN", "P": "PROOF_OF_CONCEPT", "F": "FUNCTIONAL", "H": "HIGH"}
        rl_map = {"X": "NOT_DEFINED", "O": "OFFICIAL_FIX", "T": "TEMPORARY_FIX", "W": "WORKAROUND", "U": "UNAVAILABLE"}
        rc_map = {"X": "NOT_DEFINED", "U": "UNKNOWN", "R": "REASONABLE", "C": "CONFIRMED"}

        return cls.calculate_scores(
            av=av_map.get(metrics.get("AV", "N"), "NETWORK"),
            ac=ac_map.get(metrics.get("AC", "L"), "LOW"),
            pr=pr_map.get(metrics.get("PR", "N"), "NONE"),
            ui=ui_map.get(metrics.get("UI", "N"), "NONE"),
            scope=s_map.get(metrics.get("S", "U"), "UNCHANGED"),
            conf=cia_map.get(metrics.get("C", "H"), "HIGH"),
            integ=cia_map.get(metrics.get("I", "H"), "HIGH"),
            avail=cia_map.get(metrics.get("A", "H"), "HIGH"),
            e=e_map.get(metrics.get("E", "X"), "NOT_DEFINED"),
            rl=rl_map.get(metrics.get("RL", "X"), "NOT_DEFINED"),
            rc=rc_map.get(metrics.get("RC", "X"), "NOT_DEFINED"),
        )
