"""Pydantic v2 Schemas for MITRE ATT&CK & D3FEND Enterprise Matrix."""

from __future__ import annotations

from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class D3FENDCountermeasure(BaseModel):
    d3fend_id: str
    name: str
    tactic: str  # Model, Harden, Detect, Isolate, Deceive, Evict
    description: str
    implementation_guidance: str


class SubTechnique(BaseModel):
    id: str
    name: str
    description: str
    platforms: List[str] = Field(default_factory=list)


class TechniqueDetail(BaseModel):
    id: str
    name: str
    tactic: str
    tactic_id: str
    description: str
    platforms: List[str] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)
    detection_strategy: str
    sub_techniques: List[SubTechnique] = Field(default_factory=list)
    d3fend_countermeasures: List[D3FENDCountermeasure] = Field(default_factory=list)
    active_detection_rules_count: int = 0
    is_covered: bool = False


class TacticHeatmapItem(BaseModel):
    tactic_id: str
    tactic_name: str
    total_techniques: int
    covered_techniques: int
    coverage_percentage: float
    active_alerts_count: int
    severity_distribution: Dict[str, int] = Field(default_factory=dict)


class MatrixCoverageReport(BaseModel):
    overall_coverage_percentage: float
    total_enterprise_techniques: int
    covered_techniques: int
    blind_spots_count: int
    tactic_heatmaps: List[TacticHeatmapItem]
    top_defensive_gaps: List[TechniqueDetail]
    recommended_d3fend_countermeasures: List[D3FENDCountermeasure]
