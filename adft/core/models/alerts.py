"""
ADFT — Modèle DetectionAlert

Certains modules (analysis/reporting/harden) manipulent des "alertes"
enrichies (ex: score de risque) plutôt que les détections brutes.

Ce modèle est compatible avec la Detection (events.py) mais :
- severity est stockée en chaîne (ex: "high") pour simplifier scoring/filtrage
- risk_score est optionnel et calculé après coup
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import hashlib
from typing import Any, List, Optional


@dataclass
class DetectionAlert:
    rule_id: str
    rule_name: str
    description: str
    severity: str
    mitre_tactic: str
    mitre_technique: str
    timestamp: datetime | str

    # Optionnels (compat tests + enrichissement)
    user: Optional[str] = None
    source_host: Optional[str] = None
    target_host: Optional[str] = None
    source_ip: Optional[str] = None
    entities: List[str] = field(default_factory=list)
    confidence: float = 0.5

    # Identifiants (compat tests)
    id: Optional[str] = None
    mitre_id: Optional[str] = None

    # Enrichissements
    risk_score: float = 0.0
    risk_level: str = ""

    # Événements déclencheurs (optionnel pour les exports)
    events: Optional[List[Any]] = None

    def __post_init__(self) -> None:
        ts = self.timestamp if isinstance(self.timestamp, str) else self.timestamp.isoformat()

        if not self.id:
            base = "|".join([
                self.rule_id or "",
                ts or "",
                self.description or "",
                self.user or "",
                self.source_host or "",
                self.target_host or "",
                self.source_ip or "",
            ])
            self.id = hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]

        if not self.mitre_id:
            self.mitre_id = self.mitre_technique


    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "mitre_id": self.mitre_id,
            "timestamp": self.timestamp if isinstance(self.timestamp, str) else self.timestamp.isoformat(),
            "user": self.user,
            "source_host": self.source_host,
            "target_host": self.target_host,
            "source_ip": self.source_ip,
            "entities": self.entities,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
        }
