"""
╔══════════════════════════════════════════════════════════════════╗
║  ADFT — Tests du module de Reporting                             ║
╚══════════════════════════════════════════════════════════════════╝
"""

import unittest
import tempfile
import json
from pathlib import Path
from datetime import datetime

from adft.core.models import DetectionAlert, AttackTimeline, TimelineEntry
from adft.reporting.engine import ReportingEngine, InvestigationReport
from adft.reporting.json_report import JSONReportGenerator
from adft.reporting.csv_report import CSVReportGenerator


class TestReportingEngine(unittest.TestCase):
    """Tests du moteur de reporting."""

    def setUp(self) -> None:
        self.now = datetime.now()
        self.temp_dir = tempfile.mkdtemp()
        self.engine = ReportingEngine(output_dir=self.temp_dir)

    def _make_sample_report(self) -> InvestigationReport:
        """Crée un rapport de test avec des données minimalistes."""
        alerts = [
            DetectionAlert(
                rule_id="TEST-001", rule_name="Test Kerberoasting",
                severity="high", mitre_tactic="TA0006",
                mitre_technique="T1558.003", description="Test alert",
                timestamp=self.now, user="attacker",
                source_host="WKS01", target_host="DC01",
            ),
        ]

        return InvestigationReport(
            alerts=alerts,
            total_events_processed=100,
            total_events_after_filter=42,
        )

    def test_generation_html(self) -> None:
        """Le rapport HTML doit être généré correctement."""
        report = self._make_sample_report()
        files = self.engine.generate(report, formats=["html"])

        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].exists())
        content = files[0].read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("ADFT", content)

    def test_generation_json(self) -> None:
        """Le rapport JSON doit être du JSON valide."""
        report = self._make_sample_report()
        files = self.engine.generate(report, formats=["json"])

        self.assertEqual(len(files), 1)
        content = files[0].read_text(encoding="utf-8")
        data = json.loads(content)  # Doit être du JSON valide
        self.assertIn("metadata", data)
        self.assertIn("alerts", data)

    def test_generation_csv(self) -> None:
        """Le rapport CSV doit contenir les en-têtes."""
        report = self._make_sample_report()
        files = self.engine.generate(report, formats=["csv"])

        self.assertEqual(len(files), 1)
        content = files[0].read_text(encoding="utf-8-sig")
        self.assertIn("rule_id", content)
        self.assertIn("severity", content)

    def test_generation_multi_format(self) -> None:
        """La génération multi-format doit créer tous les fichiers."""
        report = self._make_sample_report()
        files = self.engine.generate(report, formats=["html", "json", "csv"])
        self.assertEqual(len(files), 3)


if __name__ == "__main__":
    unittest.main()