"""
╔══════════════════════════════════════════════════════════════════╗
║  ADFT — Modèles de données : Scoring & Analyse de sécurité     ║
║                                                                  ║
║  Ces modèles structurent les résultats de l'analyse de posture  ║
║  Active Directory : scores par catégorie et score global.       ║
╚══════════════════════════════════════════════════════════════════╝
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class SecurityScoreCategory:
    """Score d'une catégorie de sécurité observée."""

    name: str
    score: float = 100.0
    findings_count: int = 0
    weight: float = 0.25
    details: str = ""
    penalty_points: float = 0.0
    evidence_examples: List[str] = field(default_factory=list)
    operational_impact: str = ""
    exposure_level: str = "faible"
    evidence_confidence: float = 0.0
    observed_scope: str = ""
    top_driver: str = ""

    def apply_penalty(self, points: float, evidence: str | None = None) -> None:
        """Applique une pénalité et conserve quelques preuves lisibles."""
        pts = max(0.0, float(points))
        self.score = max(0.0, self.score - pts)
        if pts > 0:
            self.findings_count += 1
            self.penalty_points = round(self.penalty_points + pts, 1)
        if evidence:
            msg = str(evidence).strip()
            if msg and msg not in self.evidence_examples and len(self.evidence_examples) < 8:
                self.evidence_examples.append(msg)
        self._refresh_level()

    def finalize(self, evidence_confidence: float = 0.0, observed_scope: str = "") -> None:
        self.score = round(max(0.0, min(100.0, float(self.score))), 1)
        self.penalty_points = round(max(0.0, float(self.penalty_points)), 1)
        self.evidence_confidence = round(max(0.0, min(1.0, float(evidence_confidence))), 2)
        self.observed_scope = observed_scope
        self.top_driver = self.evidence_examples[0] if self.evidence_examples else ""
        self._refresh_level()

    def _refresh_level(self) -> None:
        if self.score <= 25:
            self.exposure_level = "critique"
        elif self.score <= 50:
            self.exposure_level = "élevé"
        elif self.score <= 75:
            self.exposure_level = "modéré"
        else:
            self.exposure_level = "faible"


@dataclass
class ADSecurityScore:
    """Score de sécurité global de l'environnement Active Directory."""

    global_score: float = 100.0
    categories: List[SecurityScoreCategory] = field(default_factory=list)
    risk_level: str = "faible"
    summary: str = ""
    evidence_confidence: float = 0.0
    confidence_label: str = "faible"
    observed_scope: str = ""
    severity_mix: str = ""
    score_drivers: List[str] = field(default_factory=list)
    calibration_version: str = "observed-v1"
    calibration_method: str = "heuristic_evidence_weighting"
    decision_thresholds: dict = field(default_factory=lambda: {"critical": "<=25", "high": "<=50", "medium": "<=75", "low": ">75"})
    calibration_notes: List[str] = field(default_factory=list)

    def compute_global_score(self) -> None:
        if not self.categories:
            self.global_score = 100.0
            self.risk_level = "faible"
            return

        total_weighted = sum(cat.score * cat.weight for cat in self.categories)
        total_weight = sum(cat.weight for cat in self.categories)
        self.global_score = round(total_weighted / total_weight, 1) if total_weight > 0 else 100.0
        self._determine_risk_level()

    def _determine_risk_level(self) -> None:
        if self.global_score <= 25:
            self.risk_level = "critique"
        elif self.global_score <= 50:
            self.risk_level = "élevé"
        elif self.global_score <= 75:
            self.risk_level = "modéré"
        else:
            self.risk_level = "faible"

    @property
    def total_findings(self) -> int:
        return sum(cat.findings_count for cat in self.categories)
