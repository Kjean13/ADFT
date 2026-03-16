"""False Positive Engine — filtrage et tuning des détections ADFT.

Architecture :
  - Whitelist par rule_id / user / host / IP (exact match et wildcard)
  - Suppression par regex sur la description
  - Fenêtres de maintenance (inhibition temporaire)
  - Ajustement de confiance (boost / penalty) par rule_id ou pattern
  - Stats de filtrage pour audit et tuning

Usage:
    engine = FalsePositiveEngine.from_config_file("fp_config.json")
    filtered = engine.filter(detections)
    print(engine.stats)
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from adft.core.models.events import Detection, Severity


# ---------------------------------------------------------------------------
# Configuration structures
# ---------------------------------------------------------------------------

@dataclass
class WhitelistEntry:
    """Entrée de whitelist atomique."""
    rule_id: str = ""          # ex: "LM-4624-SMB" — vide = toutes les règles
    user: str = ""             # Wildcard supporté: "svc_*", "*backup*"
    host: str = ""             # Wildcard supporté
    ip: str = ""               # Wildcard supporté
    comment: str = ""

    def matches(self, detection: Detection) -> bool:
        # Filtre par rule_id
        if self.rule_id and not self._wc_match(self.rule_id, detection.rule_id):
            return False

        entities = [str(e).lower() for e in (detection.entities or [])]
        entity_str = " ".join(entities)

        # Filtre par user
        if self.user:
            if not any(self._wc_match(self.user, e) for e in entities):
                return False

        # Filtre par host
        if self.host:
            if not any(self._wc_match(self.host, e) for e in entities):
                return False

        # Filtre par IP
        if self.ip:
            if not any(self._wc_match(self.ip, e) for e in entities):
                return False

        return True

    @staticmethod
    def _wc_match(pattern: str, value: str) -> bool:
        return fnmatch.fnmatchcase(value.lower(), pattern.lower())


@dataclass
class SuppressionRule:
    """Suppression par regex sur la description ou la règle."""
    pattern: str               # Regex appliqué sur detection.description
    rule_id: str = ""          # Optionnel : limiter à une règle
    flags: int = re.IGNORECASE
    comment: str = ""
    _compiled: Optional[re.Pattern] = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._compiled = re.compile(self.pattern, self.flags)

    def matches(self, detection: Detection) -> bool:
        if self.rule_id and detection.rule_id != self.rule_id:
            return False
        target = detection.description or ""
        return bool(self._compiled.search(target))  # type: ignore[union-attr]


@dataclass
class MaintenanceWindow:
    """Fenêtre de maintenance : inhibition de détections pendant une plage horaire."""
    start_utc: datetime
    end_utc: datetime
    rule_ids: list[str] = field(default_factory=list)   # vide = toutes les règles
    hosts: list[str] = field(default_factory=list)       # vide = tous les hôtes
    comment: str = ""

    def is_active(self, at: Optional[datetime] = None) -> bool:
        now = at or datetime.now(tz=timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        return self.start_utc <= now <= self.end_utc

    def suppresses(self, detection: Detection, at: Optional[datetime] = None) -> bool:
        if not self.is_active(at):
            return False
        if self.rule_ids and detection.rule_id not in self.rule_ids:
            return False
        if self.hosts:
            ent_lower = [str(e).lower() for e in (detection.entities or [])]
            if not any(h.lower() in ent_lower for h in self.hosts):
                return False
        return True


@dataclass
class ConfidenceTuning:
    """Ajustement de confiance (multiplicateur) pour une règle ou un pattern."""
    rule_id: str = ""       # Vide = s'applique à toutes les règles
    multiplier: float = 1.0 # ex: 0.5 pour réduire de 50%, 1.2 pour booster
    min_confidence: float = 0.0
    max_confidence: float = 1.0
    comment: str = ""

    def apply(self, detection: Detection) -> float:
        if self.rule_id and detection.rule_id != self.rule_id:
            return detection.confidence
        new_conf = detection.confidence * self.multiplier
        return max(self.min_confidence, min(self.max_confidence, new_conf))


# ---------------------------------------------------------------------------
# Main Engine
# ---------------------------------------------------------------------------

class FalsePositiveEngine:
    """Moteur de filtrage et de tuning des faux positifs ADFT.

    Chaîne de traitement (dans l'ordre) :
      1. Fenêtres de maintenance   → suppression totale si active
      2. Whitelist (exact/wildcard) → suppression totale si match
      3. Règles de suppression regex → suppression totale si match
      4. Tuning de confiance       → ajustement du score (ne supprime pas)
      5. Seuil de confiance minimal → suppression si confiance < min_confidence
    """

    DEFAULT_MIN_CONFIDENCE = 0.3

    def __init__(
        self,
        whitelist: list[WhitelistEntry] | None = None,
        suppression_rules: list[SuppressionRule] | None = None,
        maintenance_windows: list[MaintenanceWindow] | None = None,
        confidence_tunings: list[ConfidenceTuning] | None = None,
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    ) -> None:
        self.whitelist: list[WhitelistEntry] = whitelist or []
        self.suppression_rules: list[SuppressionRule] = suppression_rules or []
        self.maintenance_windows: list[MaintenanceWindow] = maintenance_windows or []
        self.confidence_tunings: list[ConfidenceTuning] = confidence_tunings or []
        self.min_confidence = min_confidence

        # Stats internes
        self._stats: dict[str, int] = {
            "total_in": 0,
            "suppressed_maintenance": 0,
            "suppressed_whitelist": 0,
            "suppressed_regex": 0,
            "suppressed_confidence": 0,
            "passed": 0,
        }
        self._suppressed_rules: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def filter(
        self,
        detections: list[Detection],
        at: Optional[datetime] = None,
    ) -> list[Detection]:
        """Filtre une liste de détections, retourne celles qui passent."""
        out: list[Detection] = []
        at = at or datetime.now(tz=timezone.utc)

        for det in detections:
            self._stats["total_in"] += 1
            reason = self._should_suppress(det, at)
            if reason:
                self._stats[f"suppressed_{reason}"] += 1
                self._suppressed_rules[det.rule_id] = (
                    self._suppressed_rules.get(det.rule_id, 0) + 1
                )
                continue

            # Appliquer les tunings de confiance
            tuned = self._apply_confidence_tuning(det)
            if tuned.confidence < self.min_confidence:
                self._stats["suppressed_confidence"] += 1
                self._suppressed_rules[det.rule_id] = (
                    self._suppressed_rules.get(det.rule_id, 0) + 1
                )
                continue

            out.append(tuned)
            self._stats["passed"] += 1

        return out

    def reset_stats(self) -> None:
        """Remet les statistiques de filtrage à zéro."""
        for k in self._stats:
            self._stats[k] = 0
        self._suppressed_rules.clear()

    @property
    def stats(self) -> dict[str, Any]:
        """Snapshot des statistiques de filtrage."""
        suppression_rate = 0.0
        total = self._stats.get("total_in", 0)
        if total > 0:
            suppression_rate = round(
                (total - self._stats.get("passed", 0)) / total * 100, 1
            )
        return {
            **self._stats,
            "suppression_rate_pct": suppression_rate,
            "suppressed_by_rule": dict(sorted(
                self._suppressed_rules.items(), key=lambda x: x[1], reverse=True
            )),
        }

    # ------------------------------------------------------------------
    # Configuration loading
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "FalsePositiveEngine":
        """Instancier depuis un dictionnaire de configuration."""
        whitelist = [
            WhitelistEntry(**{k: v for k, v in e.items() if k in WhitelistEntry.__dataclass_fields__})
            for e in config.get("whitelist", [])
        ]
        suppression_rules = []
        for e in config.get("suppression_rules", []):
            s = SuppressionRule(
                pattern=e["pattern"],
                rule_id=e.get("rule_id", ""),
                comment=e.get("comment", ""),
            )
            suppression_rules.append(s)

        maintenance_windows = []
        for e in config.get("maintenance_windows", []):
            mw = MaintenanceWindow(
                start_utc=datetime.fromisoformat(e["start_utc"]).replace(tzinfo=timezone.utc),
                end_utc=datetime.fromisoformat(e["end_utc"]).replace(tzinfo=timezone.utc),
                rule_ids=e.get("rule_ids", []),
                hosts=e.get("hosts", []),
                comment=e.get("comment", ""),
            )
            maintenance_windows.append(mw)

        confidence_tunings = [
            ConfidenceTuning(**{k: v for k, v in e.items() if k in ConfidenceTuning.__dataclass_fields__})
            for e in config.get("confidence_tunings", [])
        ]

        return cls(
            whitelist=whitelist,
            suppression_rules=suppression_rules,
            maintenance_windows=maintenance_windows,
            confidence_tunings=confidence_tunings,
            min_confidence=config.get("min_confidence", cls.DEFAULT_MIN_CONFIDENCE),
        )

    @classmethod
    def from_config_file(cls, path: str | Path) -> "FalsePositiveEngine":
        """Charger depuis un fichier JSON."""
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Fichier de configuration FP introuvable: {config_path}")
        with config_path.open("r", encoding="utf-8") as f:
            config = json.load(f)
        return cls.from_config(config)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _should_suppress(
        self, detection: Detection, at: datetime
    ) -> Optional[str]:
        """Retourne la raison de suppression ou None si la détection passe."""
        # 1. Fenêtres de maintenance
        for mw in self.maintenance_windows:
            if mw.suppresses(detection, at):
                return "maintenance"

        # 2. Whitelist
        for entry in self.whitelist:
            if entry.matches(detection):
                return "whitelist"

        # 3. Regex de suppression
        for rule in self.suppression_rules:
            if rule.matches(detection):
                return "regex"

        return None

    def _apply_confidence_tuning(self, detection: Detection) -> Detection:
        """Retourne une nouvelle détection avec la confiance ajustée."""
        new_confidence = detection.confidence
        for tuning in self.confidence_tunings:
            new_confidence = tuning.apply(
                type("_D", (), {"rule_id": detection.rule_id, "confidence": new_confidence})()
            )

        if new_confidence == detection.confidence:
            return detection

        # Créer une copie avec la confiance ajustée (Detection est un dataclass)
        import dataclasses
        return dataclasses.replace(detection, confidence=round(new_confidence, 4))
