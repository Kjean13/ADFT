from adft.core.self_validation import SelfValidationEngine
"""
╔══════════════════════════════════════════════════════════════════╗
║  ADFT — Moteur de Reporting                                      ║
║                                                                  ║
║  Orchestre la génération de rapports dans tous les formats.     ║
║  Agrège les données de tous les modules pour produire un        ║
║  rapport d'investigation cohérent et complet.                   ║
╚══════════════════════════════════════════════════════════════════╝
"""

from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from adft.core.models import (
    DetectionAlert,
    InvestigationObject,
    AttackTimeline,
    ADSecurityScore,
    HardeningReport,
)
from adft.reporting.html_report import HTMLReportGenerator
from adft.reporting.json_report import JSONReportGenerator
from adft.reporting.csv_report import CSVReportGenerator


# ============================================================
#  Structure de données du rapport complet
# ============================================================

@dataclass
class InvestigationReport:
    """
    Contient toutes les données nécessaires à la génération du rapport.

    Ce dataclass est le contrat entre les modules d'analyse
    et le moteur de reporting. Chaque générateur de format
    puise dans cette structure.
    """
    # --- Métadonnées ---
    title: str = "Rapport d'Investigation ADFT v1.0"
    analyst: str = "ADFT v1.0"
    date: str = ""

    # --- Données d'investigation ---
    alerts: List[DetectionAlert] = field(default_factory=list)
    investigations: List[InvestigationObject] = field(default_factory=list)
    timeline: Optional[AttackTimeline] = None
    security_score: Optional[ADSecurityScore] = None
    hardening: Optional[HardeningReport] = None

    # --- Enrichissements (optionnels) ---
    attack_story: List[str] = field(default_factory=list)
    entity_graph: dict = field(default_factory=dict)
    case_explanation: dict = field(default_factory=dict)
    reconstruction: dict = field(default_factory=dict)
    data_quality: dict = field(default_factory=dict)
    integrity: dict = field(default_factory=dict)

    # --- Normalized events (serializable dicts) ---
    # Keep ONLY a small sample here (for debug/UI).
    # The full dataset must be written to an external JSONL file and referenced by `events_ref`.
    # This avoids gigantic JSON/HTML reports and prevents OOM kills.
    events: List[Dict[str, Any]] = field(default_factory=list)
    events_ref: Optional[str] = None
    events_truncated: bool = False

    # --- Statistiques ---
    total_events_processed: int = 0
    total_events_after_filter: int = 0
    log_sources: List[str] = field(default_factory=list)

    # ============================================================
    #  FIX #1 — Remplissage auto des METADATA si non renseignées
    # ============================================================

    def finalize_metadata(self) -> None:
        """
        Assure la cohérence des métadonnées du rapport.

        Problème corrigé :
          - total_events_processed = 0 alors qu'on a des alertes
          - total_events_after_filter = 0 alors qu'on a des alertes
          - log_sources = [] alors qu'on a un fichier source

        Cette méthode ne force rien si les champs sont déjà définis.
        """
        # Si tu as déjà mis les compteurs, on ne touche pas.
        if self.total_events_processed and self.total_events_after_filter and self.log_sources:
            return

        # 1) log_sources : déduire depuis alerts.events[*].source_log si dispo
        if not self.log_sources:
            sources = set()
            for a in self.alerts or []:
                for ev in getattr(a, "events", None) or []:
                    src = getattr(ev, "source_log", None)
                    if src:
                        sources.add(str(src))
            self.log_sources = sorted(sources)

        # 2) total_events_processed / after_filter :
        #    on ne peut pas deviner les 12 bruts ici si on n'a pas le contexte,
        #    mais on peut au moins mettre un chiffre cohérent basé sur les events
        #    réellement présents dans le rapport.
        if (self.total_events_processed or 0) <= 0:
            ev_ids = set()
            for a in self.alerts or []:
                for ev in getattr(a, "events", None) or []:
                    ev_id = getattr(ev, "id", None)
                    if ev_id:
                        ev_ids.add(ev_id)
                    else:
                        # fallback si pas d'id (moins robuste mais évite 0)
                        ev_ids.add((getattr(ev, "timestamp", None), getattr(ev, "event_id", None), getattr(ev, "user", None)))
            self.total_events_processed = len(ev_ids)

        if (self.total_events_after_filter or 0) <= 0:
            # Si tu ne stockes pas explicitement les filtered_events dans le report,
            # on considère "après filtre" = ce qui reste utilisé dans les alertes.
            self.total_events_after_filter = self.total_events_processed


class ReportingEngine:
    """
    Moteur central de génération de rapports.

    Usage :
        engine = ReportingEngine(output_dir="./reports")
        engine.generate(report_data, formats=["html", "json", "csv"])
    """

    def __init__(self, output_dir: str = "./reports") -> None:
        """
        Args :
            output_dir : Répertoire de sortie pour les rapports générés
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # --- Registre des générateurs de format ---
        self._generators = {
            "html": HTMLReportGenerator(),
            "json": JSONReportGenerator(),
            "csv": CSVReportGenerator(),
        }

    def generate(
        self,
        report: InvestigationReport,
        formats: Optional[List[str]] = None,
    ) -> List[Path]:
        """
        Génère le rapport dans les formats demandés.

        Args :
            report  : Données du rapport d'investigation
            formats : Liste des formats souhaités (défaut: tous)

        Returns :
            Liste des chemins vers les fichiers générés
        """
        if formats is None:
            formats = ["html", "json", "csv"]

        # Fix #1 : s'assure que les metadata ne sortent pas à 0/[] si on a de la matière
        report.finalize_metadata()

        # Self-validation (post-processing): fix/annotate report for SOC-grade consumption
        try:
            validator = SelfValidationEngine(report)
            validation = validator.run()
            # attach a SOC-friendly dict
            report.self_validation = {
                "applied": True,
                "integrity_score": getattr(validation, "integrity_score", None),
                "issues": [
                    {
                        "rule": i.rule,
                        "severity": i.severity,
                        "description": i.description,
                        "auto_fixed": i.auto_fixed,
                    }
                    for i in getattr(validation, "issues", []) or []
                ],
                "fixes": sorted({i.rule for i in getattr(validation, "issues", []) or []}),
            }
        except Exception:
            # never break reporting because of validation
            report.self_validation = {"applied": False}

        generated_files: List[Path] = []

        for fmt in formats:
            fmt = fmt.lower().strip()

            if fmt not in self._generators:
                print(f"  [Rapport] ⚠ Format inconnu : '{fmt}' — ignoré")
                continue

            generator = self._generators[fmt]
            output_path = self.output_dir / f"adft_report.{fmt}"

            try:
                generator.generate(report, output_path)
                generated_files.append(output_path)
                print(f"  [Rapport] ✓ {fmt.upper()} → {output_path}")
            except Exception as e:
                print(f"  [Rapport] ✗ Erreur génération {fmt.upper()} : {e}")

        return generated_files

# ============================================================
#  Helper SOC : pipeline → reporting (sans complexité)
# ============================================================

def generate_investigation_report(investigation_result: dict, output_dir: str, formats: list[str] | None = None) -> list[str]:
    """Génère HTML/JSON/CSV à partir du résultat pipeline.

    Attendu:
      investigation_result = {
        "report": InvestigationReport,
        "attack_story": [...],
        "graph": {...},
        "case_explanation": {...}
      }
    """
    base_report = investigation_result.get("report")
    if base_report is None:
        raise ValueError("investigation_result['report'] (InvestigationReport) requis")

    base_report.attack_story = investigation_result.get("attack_story", []) or []
    base_report.entity_graph = investigation_result.get("graph", {}) or {}
    base_report.case_explanation = investigation_result.get("case_explanation", {}) or {}

    engine = ReportingEngine(output_dir=output_dir)
    return engine.generate(base_report, formats=formats or ["html", "json", "csv"])

