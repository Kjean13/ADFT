"""
╔══════════════════════════════════════════════════════════════════╗
║  ADFT — Module de Reporting                                      ║
║                                                                  ║
║  Génère des rapports d'investigation prêts pour le SOC.         ║
║                                                                  ║
║  Formats supportés :                                             ║
║    • HTML  — Rapport visuel complet avec timeline                ║
║    • JSON  — Données structurées pour intégration                ║
║    • CSV   — Export tabulaire des findings                        ║
╚══════════════════════════════════════════════════════════════════╝
"""

from adft.reporting.engine import ReportingEngine

__all__ = ["ReportingEngine"]