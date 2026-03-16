"""
╔══════════════════════════════════════════════════════════════════╗
║  ADFT — Tests du module d'Analyse & Scoring                     ║
╚══════════════════════════════════════════════════════════════════╝
"""

import unittest
from datetime import datetime

from adft.core.models import NormalizedEvent, DetectionAlert, InvestigationObject
from adft.analysis.noise_filter import NoiseFilter
from adft.analysis.risk_scorer import RiskScorer
from adft.analysis.ad_security_score import ADSecurityScoreCalculator


class TestNoiseFilter(unittest.TestCase):
    """Tests du filtrage du bruit."""

    def setUp(self) -> None:
        """Prépare les données de test."""
        self.filter = NoiseFilter()
        self.now = datetime.now()

    def test_filtre_comptes_machine(self) -> None:
        """Les comptes machine (suffixe $) doivent être filtrés."""
        events = [
            NormalizedEvent(
                timestamp=self.now, event_id=4624, user="DC01$",
                source_host="DC01", target_host="DC01",
                action="logon_success", severity="info",
            ),
            NormalizedEvent(
                timestamp=self.now, event_id=4624, user="j.martin",
                source_host="WKS01", target_host="DC01",
                action="logon_success", severity="info",
            ),
        ]

        result = self.filter.filter_events(events)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].user, "j.martin")

    def test_filtre_comptes_systeme(self) -> None:
        """Les comptes système (SYSTEM, LOCAL SERVICE...) doivent être filtrés."""
        events = [
            NormalizedEvent(
                timestamp=self.now, event_id=4624, user="SYSTEM",
                source_host="DC01", target_host="DC01",
                action="logon_success", severity="info",
            ),
        ]

        result = self.filter.filter_events(events)
        self.assertEqual(len(result), 0)

    def test_filtre_event_ids_faible_valeur(self) -> None:
        """Les Event IDs sans valeur forensique doivent être filtrés."""
        events = [
            NormalizedEvent(
                timestamp=self.now, event_id=4616, user="j.martin",
                source_host="WKS01", target_host="WKS01",
                action="time_change", severity="info",
            ),
        ]

        result = self.filter.filter_events(events)
        self.assertEqual(len(result), 0)

    def test_conservation_evenements_pertinents(self) -> None:
        """Les événements pertinents ne doivent PAS être filtrés."""
        events = [
            NormalizedEvent(
                timestamp=self.now, event_id=4625, user="attacker",
                source_host="EXT01", target_host="DC01",
                action="logon_failed", severity="medium",
            ),
        ]

        result = self.filter.filter_events(events)
        self.assertEqual(len(result), 1)


class TestRiskScorer(unittest.TestCase):
    """Tests du scoring de risque."""

    def setUp(self) -> None:
        self.scorer = RiskScorer()
        self.now = datetime.now()

    def test_score_alerte_critique(self) -> None:
        """Une alerte critique avec technique d'escalade doit avoir un score élevé."""
        alert = DetectionAlert(
            rule_id="TEST-001", rule_name="Test",
            severity="critical", mitre_tactic="TA0004",
            mitre_technique="T1068", description="Test",
            timestamp=self.now, user="admin",
        )

        score = self.scorer.score_alert(alert)
        self.assertGreaterEqual(score, 60.0)

    def test_score_alerte_info(self) -> None:
        """Une alerte info doit avoir un score faible."""
        alert = DetectionAlert(
            rule_id="TEST-002", rule_name="Test",
            severity="info", mitre_tactic="TA0007",
            mitre_technique="T1087", description="Test",
            timestamp=self.now, user="user",
        )

        score = self.scorer.score_alert(alert)
        self.assertLess(score, 20.0)

    def test_score_investigation_volume(self) -> None:
        """Plus d'alertes corrélées = score plus élevé."""
        alerts = [
            DetectionAlert(
                rule_id=f"TEST-{i}", rule_name="Test",
                severity="high", mitre_tactic="TA0004",
                mitre_technique="T1068", description="Test",
                timestamp=self.now, user="admin",
            )
            for i in range(5)
        ]

        inv = InvestigationObject(identity="admin", alerts=alerts)
        score = self.scorer.score_investigation(inv)
        self.assertGreater(score, 70.0)

    def test_risk_level_labels(self) -> None:
        """Les labels de risque doivent correspondre aux seuils."""
        self.assertEqual(self.scorer.risk_level_from_score(90), "critique")
        self.assertEqual(self.scorer.risk_level_from_score(70), "élevé")
        self.assertEqual(self.scorer.risk_level_from_score(50), "modéré")
        self.assertEqual(self.scorer.risk_level_from_score(10), "info")


class TestADSecurityScore(unittest.TestCase):
    """Tests du score de sécurité AD."""

    def setUp(self) -> None:
        self.calculator = ADSecurityScoreCalculator()
        self.now = datetime.now()

    def test_score_parfait_sans_alertes(self) -> None:
        """Sans alertes, le score doit être 100/100."""
        score = self.calculator.calculate([], [])
        self.assertEqual(score.global_score, 100.0)
        self.assertEqual(score.risk_level, "faible")


    def test_score_expose_preuves_et_confiance(self) -> None:
        alerts = [
            DetectionAlert(
                rule_id="AUTH-001", rule_name="Kerberoasting",
                severity="critical", mitre_tactic="TA0006",
                mitre_technique="T1558", description="Kerberoasting against admin",
                timestamp=self.now, user="admin.svc", source_host="WKS01", target_host="DC01",
            ),
            DetectionAlert(
                rule_id="LM-001", rule_name="Suspicious RDP",
                severity="high", mitre_tactic="TA0008",
                mitre_technique="T1021", description="Remote movement",
                timestamp=self.now, user="admin.svc", source_host="WKS01", target_host="SRV02",
            ),
        ]

        score = self.calculator.calculate(alerts, [])
        self.assertGreater(score.evidence_confidence, 0)
        self.assertIn("alertes", score.observed_scope)
        self.assertTrue(any(cat.evidence_examples for cat in score.categories))

    def test_score_degradé_avec_alertes_critiques(self) -> None:
        """Des alertes critiques doivent dégrader significativement le score."""
        alerts = [
            DetectionAlert(
                rule_id="TEST-001", rule_name="Kerberoasting",
                severity="critical", mitre_tactic="TA0006",
                mitre_technique="T1558", description="Kerberoasting",
                timestamp=self.now, user="attacker",
            )
            for _ in range(5)
        ]

        score = self.calculator.calculate(alerts, [])
        self.assertLess(score.global_score, 50.0)


if __name__ == "__main__":
    unittest.main()