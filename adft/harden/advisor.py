"""
╔══════════════════════════════════════════════════════════════════╗
║  ADFT — Conseiller en Remédiation                                ║
║                                                                  ║
║  Orchestre l'analyse de durcissement et la présentation          ║
║  des recommandations en mode --dry-run.                         ║
║                                                                  ║
║  RAPPEL CRITIQUE :                                               ║
║    - Suggestions de remédiation                                 ║
║    - Génération de scripts PowerShell                            ║
║    - JAMAIS de modification automatique de l'AD                 ║
╚══════════════════════════════════════════════════════════════════╝
"""

from typing import List
from adft.core.models import (
    DetectionAlert,
    InvestigationObject,
    HardeningReport,
)
from adft.harden.analyze import HardeningAnalyzer
from adft.harden.script_generator import PowerShellScriptGenerator


class RemediationAdvisor:
    """
    Point d'entrée principal du module de durcissement.

    Combine l'analyse de durcissement avec la génération de scripts
    pour fournir un plan de remédiation complet.

    Usage :
        advisor = RemediationAdvisor()
        report = advisor.advise(alerts, investigations)
        advisor.display_dry_run(report)
    """

    def __init__(self) -> None:
        self.analyzer = HardeningAnalyzer()
        self.script_generator = PowerShellScriptGenerator()

    def advise(
        self,
        alerts: List[DetectionAlert],
        investigations: List[InvestigationObject],
    ) -> HardeningReport:
        """
        Produit le rapport de durcissement complet avec scripts PowerShell.

        Args :
            alerts          : Alertes de détection
            investigations  : Objets d'investigation

        Returns :
            HardeningReport avec constats, recommandations et scripts
        """
        # --- Étape 1 : Analyser les faiblesses ---
        report = self.analyzer.analyze(alerts, investigations)

        # --- Étape 2 : Générer les scripts PowerShell ---
        self.script_generator.enrich_findings(report)
        coverage = report.script_coverage
        report.summary = (
            f"{report.total_issues} recommandation(s) pilotée(s) par preuves, "
            f"dont {report.critical_count} critique(s). "
            f"Scripts candidats disponibles pour {coverage['with_script']}/{report.total_issues} constats."
        )

        return report

    def display_dry_run(self, report: HardeningReport) -> None:
        """
        Affiche le rapport de durcissement en mode dry-run.

        Mode dry-run = visualisation des recommandations SANS
        aucune exécution ni modification. L'analyste décide
        quelles actions entreprendre.

        Args :
            report : Rapport de durcissement à afficher
        """
        print("\n" + "=" * 70)
        print("  🛡️  ADFT — Rapport de Durcissement (DRY-RUN)")
        print("  ⚠️  Aucune modification n'est appliquée automatiquement")
        print("=" * 70)

        if not report.findings:
            print("\n  ✅ Aucune recommandation de durcissement identifiée.\n")
            return

        print(f"\n  📊 {report.summary}\n")

        # --- Afficher chaque constat trié par priorité ---
        for i, finding in enumerate(report.sorted_by_priority(), 1):
            self._display_finding(i, finding)

        print("=" * 70)
        print("  ℹ️  Pour générer les scripts PowerShell :")
        print("      adft harden --export-scripts ./remediation/")
        print("=" * 70 + "\n")

    @staticmethod
    def _display_finding(index: int, finding) -> None:
        """Affiche un constat de durcissement formaté."""
        # --- Icône par priorité ---
        icons = {
            "critique": "🔴", "élevé": "🟠",
            "modéré": "🟡", "faible": "🟢",
        }
        icon = icons.get(finding.priority, "⚪")

        print(f"  ┌─ [{finding.finding_id}] {icon} {finding.title}")
        print(f"  │  Priorité  : {finding.priority.upper()}")
        print(f"  │  Catégorie : {finding.category}")
        print(f"  │")
        print(f"  │  Risque :")
        for line in finding.risk_explanation.split("\n"):
            print(f"  │    {line}")
        print(f"  │")
        print(f"  │  Remédiation :")
        for line in finding.recommendation.split("\n"):
            print(f"  │    {line}")
        print(f"  │")
        print(f"  │  Impact : {finding.impact}")

        if finding.powershell_fix:
            print(f"  │")
            print(f"  │  Script PowerShell disponible ✓")

        print(f"  └{'─' * 60}")
        print()