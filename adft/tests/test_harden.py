"""
╔══════════════════════════════════════════════════════════════════╗
║  ADFT — Tests du module de Durcissement                          ║
╚══════════════════════════════════════════════════════════════════╝
"""

import json
import unittest
from datetime import datetime
from tempfile import TemporaryDirectory

from adft.core.models import DetectionAlert, InvestigationObject, HardeningFinding
from adft.harden.analyzer import HardeningAnalyzer
from adft.harden.script_generator import PowerShellScriptGenerator


class TestHardeningAnalyzer(unittest.TestCase):
    """Tests de l'analyseur de durcissement."""

    def setUp(self) -> None:
        self.analyzer = HardeningAnalyzer()
        self.now = datetime.now()

    def test_detection_kerberoasting(self) -> None:
        """Le Kerberoasting doit générer un constat HARD-001."""
        alerts = [
            DetectionAlert(
                rule_id="DET-001", rule_name="Kerberoasting",
                severity="critical", mitre_tactic="TA0006",
                mitre_technique="T1558.003", description="Kerberoasting détecté",
                timestamp=self.now, user="attacker",
            ),
        ]

        report = self.analyzer.analyze(alerts, [])
        finding_ids = [f.finding_id for f in report.findings]
        self.assertIn("HARD-001", finding_ids)

    def test_detection_escalade_privileges(self) -> None:
        """L'escalade de privilèges doit générer un constat HARD-010."""
        alerts = [
            DetectionAlert(
                rule_id="DET-010", rule_name="Privilege Escalation",
                severity="high", mitre_tactic="TA0004",
                mitre_technique="T1068", description="Escalade détectée",
                timestamp=self.now, user="attacker",
            ),
        ]

        report = self.analyzer.analyze(alerts, [])
        finding_ids = [f.finding_id for f in report.findings]
        self.assertIn("HARD-010", finding_ids)

    def test_tri_par_priorite(self) -> None:
        """Les constats doivent être triés par priorité décroissante."""
        alerts = [
            DetectionAlert(
                rule_id="DET-001", rule_name="Kerberoasting",
                severity="critical", mitre_tactic="TA0006",
                mitre_technique="T1558.003", description="Test",
                timestamp=self.now, user="attacker",
            ),
        ]

        report = self.analyzer.analyze(alerts, [])
        sorted_findings = report.sorted_by_priority()

        if len(sorted_findings) >= 2:
            self.assertLessEqual(
                sorted_findings[0].priority_rank,
                sorted_findings[1].priority_rank,
            )

    def test_hygiene_toujours_presente(self) -> None:
        """Les recommandations d'hygiène doivent toujours être présentes."""
        report = self.analyzer.analyze([], [])
        finding_ids = [f.finding_id for f in report.findings]
        self.assertIn("HARD-040", finding_ids)



    def test_matching_on_mitre_technique_name(self) -> None:
        """Le hardening doit matcher les noms de technique, pas seulement les IDs MITRE."""
        alerts = [
            DetectionAlert(
                rule_id="KERB-001", rule_name="Kerberoasting détecté",
                severity="critical", mitre_tactic="Credential Access",
                mitre_technique="Kerberoasting", description="Kerberoasting détecté",
                timestamp=self.now, user="svc_sql",
            ),
        ]
        report = self.analyzer.analyze(alerts, [])
        finding = next(f for f in report.findings if f.finding_id == "HARD-001")
        self.assertTrue(finding.evidence)
        self.assertTrue(finding.validation_steps)

class TestPowerShellScriptGenerator(unittest.TestCase):
    """Tests du générateur de scripts PowerShell."""

    def setUp(self) -> None:
        self.generator = PowerShellScriptGenerator()

    def test_generation_script_kerberoasting(self) -> None:
        """Un script doit être généré pour HARD-001."""
        finding = HardeningFinding(
            finding_id="HARD-001", title="Kerberoasting",
            category="authentication", risk_explanation="Test",
            recommendation="Test", impact="Test", priority="critique",
        )

        script = self.generator._generate_script(finding)
        self.assertIsNotNone(script)
        self.assertIn("SPN", script)
        self.assertIn("AVERTISSEMENT", script)

    def test_entete_securite_present(self) -> None:
        """Chaque script doit contenir l'en-tête de sécurité."""
        finding = HardeningFinding(
            finding_id="HARD-001", title="Test",
            category="test", risk_explanation="Test",
            recommendation="Test", impact="Test", priority="critique",
        )

        script = self.generator._generate_script(finding)
        self.assertIn("AVERTISSEMENT", script)
        self.assertIn("ADFT", script)

    def test_pas_de_script_pour_finding_inconnu(self) -> None:
        """Aucun script ne doit être généré pour un finding sans template."""
        finding = HardeningFinding(
            finding_id="HARD-999", title="Inconnu",
            category="test", risk_explanation="Test",
            recommendation="Test", impact="Test", priority="faible",
        )

        script = self.generator._generate_script(finding)
        self.assertIsNone(script)


if __name__ == "__main__":
    unittest.main()

class TestPowerShellScriptExport(unittest.TestCase):
    def setUp(self) -> None:
        self.generator = PowerShellScriptGenerator()

    def test_script_contains_metadata_block(self) -> None:
        finding = HardeningFinding(
            finding_id="HARD-001", title="Kerberoasting",
            category="authentication", risk_explanation="Test",
            recommendation="Test", impact="Test", priority="critique",
            evidence=["evt1"], validation_steps=["vérifier AES"],
            candidate_scope="Compte service", confidence="high",
        )
        script = self.generator._generate_script(finding)
        self.assertIn("Preuves observées", script)
        self.assertIn("vérifier AES", script)
        self.assertIn("Compte service", script)

    def test_export_creates_manifest(self) -> None:
        finding = HardeningFinding(
            finding_id="HARD-001", title="Kerberoasting",
            category="authentication", risk_explanation="Test",
            recommendation="Test", impact="Test", priority="critique",
            validation_steps=["contrôle post-action"],
        )
        report = type('Dummy', (), {
            'findings': [finding],
            'sorted_by_priority': lambda self: self.findings,
            'summary': 'ok',
            'script_coverage': {'with_script': 1, 'without_script': 0, 'coverage_percent': 100},
        })()
        self.generator.enrich_findings(report)
        with TemporaryDirectory() as tmp:
            self.generator.export_scripts(report, tmp)
            from pathlib import Path
            manifest = json.loads((Path(tmp) / 'manifest.json').read_text(encoding='utf-8'))
            self.assertEqual(manifest['coverage']['with_script'], 1)
            self.assertEqual(manifest['scripts'][0]['finding_id'], 'HARD-001')
