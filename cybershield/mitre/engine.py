"""MITRE ATT&CK & D3FEND Enterprise Matrix Correlation & Heatmap Engine."""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from cybershield.engines.sigma_engine import sigma_engine
from cybershield.engines.yara_engine import yara_engine
from cybershield.mitre.d3fend import D3FEND_CATALOG
from cybershield.mitre.matrix_data import MITRE_TACTICS, TECHNIQUES_DATA
from cybershield.mitre.schemas import (
    D3FENDCountermeasure,
    MatrixCoverageReport,
    TacticHeatmapItem,
    TechniqueDetail,
)

logger = logging.getLogger("cybershield.mitre.engine")


class MitreMatrixEngine:
    """Master engine for MITRE ATT&CK enterprise coverage and D3FEND countermeasure planning."""

    def __init__(self) -> None:
        self._techniques: Dict[str, TechniqueDetail] = {t.id: t for t in TECHNIQUES_DATA}
        self._tactics: List[Dict[str, str]] = list(MITRE_TACTICS)

    def get_tactics(self) -> List[Dict[str, str]]:
        """List all 14 MITRE Enterprise tactics."""
        return list(self._tactics)

    def get_technique(self, technique_id: str) -> Optional[TechniqueDetail]:
        """Lookup technique by identifier e.g. T1059 or T1059.001."""
        tid = technique_id.strip().upper()
        if tid in self._techniques:
            return self._enrich_technique_coverage(self._techniques[tid])
        
        # Check sub-techniques
        for t in self._techniques.values():
            for sub in t.sub_techniques:
                if sub.id.upper() == tid:
                    return self._enrich_technique_coverage(t)
        return None

    def search_techniques(
        self,
        query: Optional[str] = None,
        tactic_id: Optional[str] = None,
        platform: Optional[str] = None,
    ) -> List[TechniqueDetail]:
        """Search techniques by keyword, tactic, or platform."""
        results: List[TechniqueDetail] = []
        q = (query or "").lower()

        for t in self._techniques.values():
            if tactic_id and t.tactic_id.upper() != tactic_id.upper():
                continue
            if platform and not any(p.lower() == platform.lower() for p in t.platforms):
                continue
            if q:
                matches_q = (
                    q in t.id.lower()
                    or q in t.name.lower()
                    or q in t.description.lower()
                    or any(q in sub.name.lower() or q in sub.id.lower() for sub in t.sub_techniques)
                )
                if not matches_q:
                    continue
            results.append(self._enrich_technique_coverage(t))

        return results

    def _get_active_technique_rule_counts(self) -> Dict[str, int]:
        """Count active Sigma and YARA rules targeting each technique."""
        counts: Dict[str, int] = {}

        # 1. Sigma rules
        for r in sigma_engine.get_loaded_rules():
            for tech in r.get("mitre_techniques", []):
                norm_tech = tech.strip().upper()
                # If subtechnique T1059.001, credit parent T1059 as well
                parent_tech = norm_tech.split(".")[0]
                counts[norm_tech] = counts.get(norm_tech, 0) + 1
                if parent_tech != norm_tech:
                    counts[parent_tech] = counts.get(parent_tech, 0) + 1

        # 2. YARA rules
        for r in yara_engine.get_loaded_rules():
            meta = r.get("meta", {})
            tech = meta.get("technique")
            if tech:
                norm_tech = tech.strip().upper()
                parent_tech = norm_tech.split(".")[0]
                counts[norm_tech] = counts.get(norm_tech, 0) + 1
                if parent_tech != norm_tech:
                    counts[parent_tech] = counts.get(parent_tech, 0) + 1

        return counts

    def _enrich_technique_coverage(self, tech: TechniqueDetail) -> TechniqueDetail:
        """Create a fresh copy of TechniqueDetail enriched with dynamic rule count."""
        rule_counts = self._get_active_technique_rule_counts()
        count = rule_counts.get(tech.id.upper(), 0)
        return TechniqueDetail(
            id=tech.id,
            name=tech.name,
            tactic=tech.tactic,
            tactic_id=tech.tactic_id,
            description=tech.description,
            platforms=tech.platforms,
            data_sources=tech.data_sources,
            detection_strategy=tech.detection_strategy,
            sub_techniques=tech.sub_techniques,
            d3fend_countermeasures=tech.d3fend_countermeasures,
            active_detection_rules_count=count,
            is_covered=count > 0,
        )

    def generate_coverage_report(self) -> MatrixCoverageReport:
        """Compute enterprise-wide MITRE ATT&CK coverage heatmap and D3FEND gap recommendations."""
        rule_counts = self._get_active_technique_rule_counts()

        tactic_heatmaps: List[TacticHeatmapItem] = []
        covered_total = 0
        all_techniques_list: List[TechniqueDetail] = []
        defensive_gaps: List[TechniqueDetail] = []

        # Tactic-level aggregation
        for tac in self._tactics:
            tac_id = tac["id"]
            tac_name = tac["name"]
            tac_techs = [t for t in self._techniques.values() if t.tactic_id == tac_id]
            total_t = len(tac_techs)

            covered_t = 0
            for t in tac_techs:
                cnt = rule_counts.get(t.id.upper(), 0)
                enriched = self._enrich_technique_coverage(t)
                all_techniques_list.append(enriched)
                if cnt > 0:
                    covered_t += 1
                else:
                    defensive_gaps.append(enriched)

            cov_pct = round((covered_t / total_t * 100.0), 1) if total_t > 0 else 0.0
            tactic_heatmaps.append(
                TacticHeatmapItem(
                    tactic_id=tac_id,
                    tactic_name=tac_name,
                    total_techniques=total_t,
                    covered_techniques=covered_t,
                    coverage_percentage=cov_pct,
                    active_alerts_count=0,
                    severity_distribution={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                )
            )
            covered_total += covered_t

        total_techniques = len(self._techniques)
        overall_pct = round((covered_total / total_techniques * 100.0), 1) if total_techniques > 0 else 0.0

        # Extract recommended D3FEND countermeasures for gaps
        recommended_d3fend: List[D3FENDCountermeasure] = []
        seen_d3 = set()
        for gap in defensive_gaps:
            for d in gap.d3fend_countermeasures:
                if d.d3fend_id not in seen_d3:
                    recommended_d3fend.append(d)
                    seen_d3.add(d.d3fend_id)

        return MatrixCoverageReport(
            overall_coverage_percentage=overall_pct,
            total_enterprise_techniques=total_techniques,
            covered_techniques=covered_total,
            blind_spots_count=len(defensive_gaps),
            tactic_heatmaps=tactic_heatmaps,
            top_defensive_gaps=defensive_gaps[:10],
            recommended_d3fend_countermeasures=recommended_d3fend,
        )


# Global singleton instance
mitre_engine = MitreMatrixEngine()
