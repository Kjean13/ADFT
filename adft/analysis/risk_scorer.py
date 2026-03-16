"""adft.analysis.risk_scorer

Deterministic risk scoring (0–100) used to prioritize alerts/investigations.

Design goals:
- simple, stable, explainable
- no external dependencies
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, List


class RiskScorer:
    """Score alerts/investigations on a 0–100 scale (deterministic)."""

    # Base mapping: MITRE tactic -> points
    _TACTIC_BASE: Dict[str, float] = {
        "TA0001": 15.0,  # Initial Access
        "TA0002": 10.0,  # Execution
        "TA0003": 10.0,  # Persistence
        "TA0004": 20.0,  # Privilege Escalation
        "TA0005": 15.0,  # Defense Evasion
        "TA0006": 20.0,  # Credential Access
        "TA0007": 10.0,  # Discovery
        "TA0008": 15.0,  # Lateral Movement
        "TA0009": 10.0,  # Collection
        "TA0010": 10.0,  # Exfiltration
        "TA0040": 30.0,  # Impact
        "UNKNOWN": 5.0,
    }

    # Human label -> tactic ID
    _TACTIC_ALIASES: Dict[str, str] = {
        "INITIAL ACCESS": "TA0001",
        "EXECUTION": "TA0002",
        "PERSISTENCE": "TA0003",
        "PRIVILEGE ESCALATION": "TA0004",
        "DEFENSE EVASION": "TA0005",
        "CREDENTIAL ACCESS": "TA0006",
        "DISCOVERY": "TA0007",
        "LATERAL MOVEMENT": "TA0008",
        "COLLECTION": "TA0009",
        "EXFILTRATION": "TA0010",
        "IMPACT": "TA0040",
    }

    # Technique boosts (additive)
    _TECH_BOOSTS: Dict[str, float] = {
        "T1558.001": 40.0,  # Golden Ticket
        "T1490": 20.0,      # Inhibit System Recovery
        "T1068": 25.0,      # Exploitation for Privilege Escalation (generic)
    }

    # Deterministic bonus by severity (in points)
    _SEV_BONUS: Dict[str, float] = {
        "info": 0.0,
        "low": 5.0,
        "medium": 15.0,
        "high": 30.0,
        "critical": 50.0,
    }

    def _normalize_tactic(self, tactic: str | None) -> str:
        if not tactic:
            return "UNKNOWN"
        t = str(tactic).strip().upper()
        if t in self._TACTIC_BASE:
            return t
        return self._TACTIC_ALIASES.get(t, "UNKNOWN")

    def score_alert(self, alert: Any) -> float:
        """Score a single alert (DetectionAlert or dict-like)."""
        sev_raw = str(getattr(alert, "severity", "") or "").strip().lower()
        sev = sev_raw if sev_raw in self._SEV_BONUS else "medium"

        mitre_tactic = self._normalize_tactic(getattr(alert, "mitre_tactic", None))
        base = float(self._TACTIC_BASE.get(mitre_tactic, self._TACTIC_BASE["UNKNOWN"]))

        mitre_id = str(getattr(alert, "mitre_id", "") or "").strip()
        rule_id = str(getattr(alert, "rule_id", "") or "").strip().upper()

        boost = 0.0
        if mitre_id in self._TECH_BOOSTS:
            boost += self._TECH_BOOSTS[mitre_id]

        # Rule-specific strong signals
        if rule_id in {"KERB-003", "KERB-001", "KERB-002"}:
            boost += 20.0

        score = base + boost + float(self._SEV_BONUS.get(sev, 15.0))
        return float(max(0.0, min(100.0, round(score, 1))))

    def risk_level_from_score(self, score: float) -> str:
        if score >= 80:
            return "critique"
        if score >= 60:
            return "élevé"
        if score >= 35:
            return "modéré"
        if score >= 20:
            return "faible"
        return "info"

    def score_investigation(self, inv: Any) -> float:
        """Score a single InvestigationObject (deterministic)."""
        alerts = getattr(inv, "alerts", []) or []
        if not alerts:
            return 0.0

        worst = max(self.score_alert(a) for a in alerts)
        volume_bonus = min(20.0, 2.5 * max(0, len(alerts) - 1))
        return float(max(0.0, min(100.0, round(worst + volume_bonus, 1))))

    def score_all_investigations(self, investigations: List[Any]) -> List[Any]:
        """Annotate investigations with a `risk_score` field when possible."""
        for inv in investigations or []:
            try:
                score = self.score_investigation(inv)
                if hasattr(inv, "risk_score"):
                    setattr(inv, "risk_score", score)
                else:
                    # best effort for dict-like objects
                    if isinstance(inv, dict):
                        inv["risk_score"] = score
            except Exception:
                continue
        return investigations

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tactic_base": dict(self._TACTIC_BASE),
            "severity_bonus": dict(self._SEV_BONUS),
            "tech_boosts": dict(self._TECH_BOOSTS),
        }
