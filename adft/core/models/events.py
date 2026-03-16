from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Optional


# ==========================================================
# ENUMS
# ==========================================================

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackPhase(str, Enum):
    UNKNOWN = "unknown"
    INITIAL_ACCESS = "initial_access"
    RECONNAISSANCE = "reconnaissance"
    CREDENTIAL_ACCESS = "credential_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    DOMAIN_DOMINANCE = "domain_dominance"


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ==========================================================
# NORMALIZED EVENT
# ==========================================================

@dataclass
class NormalizedEvent:
    timestamp: datetime
    event_id: int
    user: str
    source_host: str
    target_host: str
    action: str
    severity: Severity

    raw_event: dict[str, Any] = field(default_factory=dict)
    source_log: str = "unit-test"
    domain: str = ""

    logon_type: Optional[int] = None
    ticket_encryption: Optional[str] = None
    ticket_options: Optional[str] = None
    service_name: Optional[str] = None
    target_user: Optional[str] = None
    group_name: Optional[str] = None
    process_name: Optional[str] = None
    ip_address: Optional[str] = None
    status: Optional[str] = None
    sub_status: Optional[str] = None

    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        data["severity"] = self.severity.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NormalizedEvent":
        d = dict(data)
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        d["severity"] = Severity(d["severity"])
        return cls(**d)


# ==========================================================
# DETECTION
# ==========================================================

@dataclass
class Detection:
    id: str
    rule_id: str
    rule_name: str
    description: str
    severity: Severity
    mitre_tactic: str
    mitre_technique: str
    mitre_id: str
    events: list[NormalizedEvent]
    timestamp: datetime
    entities: list[str]
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity.value,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "mitre_id": self.mitre_id,
            "timestamp": self.timestamp.isoformat(),
            "entities": self.entities,
            "confidence": self.confidence,
            "event_count": len(self.events),
        }


# ==========================================================
# INVESTIGATION OBJECT
# ==========================================================

@dataclass
class InvestigationObject:
    """Objet d'investigation corrélé.

    Compat :
    - accepte `identity=` (ancien nom)
    - accepte `alerts=` (liste d'alertes / detections legacy)
    - accepte `detection_ids=` (utilisé par explain / export)
    """

    # Champs principaux
    id: str = ""
    title: str = "Investigation"
    start_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    end_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    summary: str = ""

    # Compat legacy
    identity: str = ""

    # Modèle actuel
    primary_entity: str = ""
    related_entities: list[str] = field(default_factory=list)
    attack_phase: AttackPhase = field(default_factory=lambda: AttackPhase.UNKNOWN)
    severity: Severity = Severity.INFO

    # ✅ Accepté en entrée (JSON/outils de restitution)
    detection_ids: list[str] = field(default_factory=list)

    # Runtime
    detections: list[Detection] = field(default_factory=list)

    # Legacy/tests
    alerts: list[Any] = field(default_factory=list)

    # Scoring
    risk_score: float = 0.0

    def __post_init__(self) -> None:
        # 1) Normaliser primary_entity / identity
        if not self.primary_entity and self.identity:
            self.primary_entity = self.identity
        if not self.identity and self.primary_entity:
            self.identity = self.primary_entity

        # 2) Normaliser alerts/detections
        if self.detections and not self.alerts:
            self.alerts = self.detections

        # 3) detection_ids depuis detections si besoin
        if self.detections and not self.detection_ids:
            self.detection_ids = [d.id for d in self.detections if getattr(d, "id", None)]

        # 4) detection_ids depuis alerts si possible
        if self.alerts and not self.detection_ids:
            ids: list[str] = []
            for a in self.alerts:
                _id = getattr(a, "id", None)
                if isinstance(_id, str) and _id:
                    ids.append(_id)
            if ids:
                self.detection_ids = ids

        # 5) ID déterministe fallback
        if not self.id:
            base = (
                f"{self.primary_entity}|"
                f"{self.start_time.isoformat()}|{self.end_time.isoformat()}|"
                f"{len(self.alerts) if self.alerts else 0}"
            )
            self.id = hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        det_ids = [d.id for d in self.detections] if self.detections else (self.detection_ids or [])
        return {
            "id": self.id,
            "title": self.title,
            "detection_ids": det_ids,
            "primary_entity": self.primary_entity,
            "related_entities": self.related_entities,
            "attack_phase": self.attack_phase.value,
            "severity": self.severity.value,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "summary": self.summary,
            "risk_score": self.risk_score,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "InvestigationObject":
        d = dict(data)

        # dates
        if isinstance(d.get("start_time"), str):
            d["start_time"] = datetime.fromisoformat(d["start_time"])
        if isinstance(d.get("end_time"), str):
            d["end_time"] = datetime.fromisoformat(d["end_time"])

        # enums
        if isinstance(d.get("attack_phase"), str):
            d["attack_phase"] = AttackPhase(d["attack_phase"])
        if isinstance(d.get("severity"), str):
            d["severity"] = Severity(d["severity"])

        # sécurité types
        if d.get("related_entities") is None:
            d["related_entities"] = []
        if d.get("detection_ids") is None:
            d["detection_ids"] = []
        if d.get("alerts") is None:
            d["alerts"] = []
        if d.get("detections") is None:
            d["detections"] = []

        # ⚠️ detections : si jamais tu reload un export avec detections partiels
        # on ne tente pas de reconstruire Detection ici (souvent absent dans JSON export),
        # on garde vide et on s’appuie sur detection_ids.
        if isinstance(d.get("detections"), list) and d["detections"]:
            # si c'est déjà des objets Detection, ok ; sinon on drop pour éviter crash
            if not all(isinstance(x, Detection) for x in d["detections"]):
                d["detections"] = []

        return cls(**d)


# ==========================================================
# TIMELINE ENTRY
# ==========================================================

@dataclass
class TimelineEntry:
    timestamp: datetime
    phase: AttackPhase
    title: str
    description: str
    severity: Severity
    entities: list[str]
    mitre_ids: list[str]
    detection_ids: list[str]
    rule_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "phase": self.phase.value,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "entities": self.entities,
            "mitre_ids": self.mitre_ids,
            "detection_ids": self.detection_ids,
            "rule_id": self.rule_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TimelineEntry":
        d = dict(data)
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        d["phase"] = AttackPhase(d["phase"])
        d["severity"] = Severity(d["severity"])
        d.setdefault("entities", [])
        d.setdefault("mitre_ids", [])
        d.setdefault("detection_ids", [])
        d.setdefault("rule_id", None)
        return cls(**d)


# ==========================================================
# SECURITY SCORE
# ==========================================================

@dataclass
class SecurityScore:
    global_score: float
    authentication_exposure: float
    privilege_risks: float
    suspicious_behavior: float
    ad_hygiene: float
    findings_summary: dict[str, int]
    critical_findings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ==========================================================
# HARDENING
# ==========================================================

@dataclass
class HardeningRecommendation:
    id: str
    finding: str
    risk_explanation: str
    recommended_remediation: str
    impact_estimation: str
    priority: Priority
    category: str
    powershell_script: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["priority"] = self.priority.value
        return data


# ==========================================================
# INVESTIGATION CONTEXT
# ==========================================================

@dataclass
class InvestigationContext:
    investigation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    log_sources: list[str] = field(default_factory=list)
    total_events_parsed: int = 0

    normalized_events: list[NormalizedEvent] = field(default_factory=list)
    detections: list[Detection] = field(default_factory=list)
    investigations: list[InvestigationObject] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)

    security_score: Optional[SecurityScore] = None
    hardening_recommendations: list[HardeningRecommendation] = field(default_factory=list)