
from __future__ import annotations

from adft.core.models.events import Detection, NormalizedEvent
from adft.core.quality import QualityCollector
from adft.detection.rules.base_rule import BaseRule
from adft.detection.rulepacks import RulePackV1


class DetectionEngine:
    """Moteur de détection avec traçabilité des règles défaillantes."""

    def __init__(self, rulepack: RulePackV1 | None = None) -> None:
        self._rules: list[BaseRule] = []
        self._stats: dict[str, int] = {
            "rules_executed": 0,
            "rules_failed": 0,
            "detections_total": 0,
        }
        self._quality = QualityCollector("detection")
        self.rulepack = rulepack or RulePackV1()
        self._register_rulepack(self.rulepack)

    def _register_rulepack(self, pack: RulePackV1) -> None:
        try:
            pack.validate()
        except Exception as exc:
            self._quality.warn(
                "rulepack_validation_failed",
                "Validation non bloquante du rulepack en échec.",
                error=str(exc),
            )
        self._rules = []
        for r in pack.build():
            self.register_rule(r)

    def register_rule(self, rule: BaseRule) -> None:
        self._rules.append(rule)

    def run(self, events: list[NormalizedEvent]) -> list[Detection]:
        all_detections: list[Detection] = []

        for rule in self._rules:
            try:
                detections = rule.evaluate(events)
                all_detections.extend(detections)
                self._stats["rules_executed"] += 1
                self._stats["detections_total"] += len(detections)
            except Exception as exc:
                self._stats["rules_failed"] += 1
                self._quality.error(
                    "rule_execution_failed",
                    "Une règle a échoué pendant l'analyse.",
                    rule_id=getattr(rule, "rule_id", rule.__class__.__name__),
                    rule_name=getattr(rule, "rule_name", rule.__class__.__name__),
                    error=str(exc),
                )

        all_detections.sort(key=lambda d: d.timestamp)
        return all_detections

    def list_rules(self) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        for r in self._rules:
            out.append(
                {
                    "rule_id": getattr(r, "rule_id", ""),
                    "name": getattr(r, "name", getattr(r, "rule_name", "")),
                    "severity": str(getattr(r, "severity", "")),
                    "mitre_tactic": getattr(r, "mitre_tactic", ""),
                    "mitre_technique": getattr(r, "mitre_technique", ""),
                    "mitre_id": getattr(r, "mitre_id", ""),
                }
            )
        return out

    @property
    def rules(self) -> list[str]:
        return [
            f"{getattr(r, 'rule_id', '')}: {getattr(r, 'name', getattr(r, 'rule_name', ''))}".strip()
            for r in self._rules
        ]

    @property
    def quality_report(self) -> dict[str, object]:
        snap = self._quality.snapshot()
        snap["stats"] = {**self._stats, **(snap.get("stats") or {})}
        return snap

    @property
    def stats(self) -> dict[str, int]:
        data = dict(self._stats)
        data.update(self._quality.snapshot().get("stats", {}))
        return data
