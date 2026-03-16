"""
╔══════════════════════════════════════════════════════════════════╗
║  ADFT — Modèles de données : Durcissement (Hardening)           ║
║                                                                  ║
║  Structure les recommandations de remédiation et les scripts    ║
║  de durcissement Active Directory.                               ║
╚══════════════════════════════════════════════════════════════════╝
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict


@dataclass
class HardeningFinding:
    """Constat de durcissement piloté par les preuves."""

    finding_id: str
    title: str
    category: str
    risk_explanation: str
    recommendation: str
    impact: str
    priority: str = "modéré"
    powershell_fix: Optional[str] = None
    references: List[str] = field(default_factory=list)

    # Nouveaux champs : recentrage preuves → action → validation
    evidence: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    validation_steps: List[str] = field(default_factory=list)
    rollback_steps: List[str] = field(default_factory=list)
    candidate_scope: str = "À confirmer par l'analyste"
    confidence: str = "medium"
    analyst_notes: str = ""

    @property
    def priority_rank(self) -> int:
        mapping = {"critique": 0, "élevé": 1, "modéré": 2, "faible": 3}
        return mapping.get(self.priority, 99)

    @property
    def has_candidate_script(self) -> bool:
        return bool(self.powershell_fix)


@dataclass
class HardeningReport:
    findings: List[HardeningFinding] = field(default_factory=list)
    summary: str = ""

    @property
    def total_issues(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.priority == "critique")

    @property
    def script_coverage(self) -> Dict[str, int]:
        available = sum(1 for f in self.findings if f.has_candidate_script)
        return {
            "with_script": available,
            "without_script": max(0, len(self.findings) - available),
            "coverage_percent": int(round((available / len(self.findings)) * 100)) if self.findings else 0,
        }

    def sorted_by_priority(self) -> List[HardeningFinding]:
        return sorted(self.findings, key=lambda f: (f.priority_rank, f.finding_id))

    def add_finding(self, finding: HardeningFinding) -> None:
        if any(existing.finding_id == finding.finding_id for existing in self.findings):
            return
        self.findings.append(finding)
