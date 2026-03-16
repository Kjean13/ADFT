
from __future__ import annotations

import hashlib
import ipaddress
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Dict, Iterable, List, Set

from adft.core.models.events import (
    AttackPhase,
    Detection,
    InvestigationObject,
    Severity,
)
from adft.core.quality import QualityCollector

MITRE_TO_PHASE: dict[str, AttackPhase] = {
    "Credential Access": AttackPhase.CREDENTIAL_ACCESS,
    "Privilege Escalation": AttackPhase.PRIVILEGE_ESCALATION,
    "Lateral Movement": AttackPhase.LATERAL_MOVEMENT,
    "Persistence": AttackPhase.PERSISTENCE,
    "Defense Evasion": AttackPhase.DEFENSE_EVASION,
    "Initial Access": AttackPhase.INITIAL_ACCESS,
    "Reconnaissance": AttackPhase.RECONNAISSANCE,
}


@dataclass
class _InvestigationSeed:
    primary_entity: str
    detections: List[Detection]
    users: Set[str]
    hosts: Set[str]
    ips: Set[str]


class CorrelationEngine:
    """Corrélation en deux passes avec fenêtre temporelle effective."""

    CORRELATION_WINDOW = timedelta(hours=24)
    ADJACENT_MERGE_WINDOW = timedelta(minutes=30)

    def __init__(self) -> None:
        self._quality = QualityCollector("correlation")
        self._stats: dict[str, int] = {
            "entity_groups": 0,
            "initial_clusters": 0,
            "merged_clusters": 0,
            "investigations": 0,
        }

    @staticmethod
    def _stable_investigation_id(primary_entity: str, detections: Iterable[Detection]) -> str:
        detections = list(detections)
        if not detections:
            payload = primary_entity or ""
        else:
            ordered = sorted(detections, key=lambda d: d.timestamp)
            start = ordered[0].timestamp.isoformat()
            end = ordered[-1].timestamp.isoformat()
            rule_ids = ",".join([d.rule_id for d in ordered if getattr(d, "rule_id", None)])
            payload = "|".join([primary_entity or "", start, end, rule_ids])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def correlate(self, detections: list[Detection]) -> list[InvestigationObject]:
        if not detections:
            return []

        entity_groups = self._group_by_entity(detections)
        self._stats["entity_groups"] = len(entity_groups)

        seeds: list[_InvestigationSeed] = []
        for entity, entity_detections in entity_groups.items():
            entity_detections.sort(key=lambda d: d.timestamp)
            for cluster in self._split_by_time_window(entity_detections):
                seeds.append(self._build_seed(entity, cluster))
        self._stats["initial_clusters"] = len(seeds)

        merged_seeds = self._second_pass_merge(seeds)
        self._stats["investigations"] = len(merged_seeds)

        investigations = [self._seed_to_investigation(seed) for seed in merged_seeds]

        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        investigations.sort(
            key=lambda i: (severity_order.get(i.severity, 5), i.start_time)
        )
        return investigations

    def _group_by_entity(self, detections: list[Detection]) -> dict[str, list[Detection]]:
        groups: defaultdict[str, list[Detection]] = defaultdict(list)
        for detection in detections:
            primary = ""
            for entity in detection.entities:
                if entity and not entity.endswith("$"):
                    primary = entity
                    break
            if not primary:
                primary = "unknown"
            groups[primary].append(detection)
        return dict(groups)

    def _split_by_time_window(self, detections: list[Detection]) -> list[list[Detection]]:
        if not detections:
            return []
        clusters: list[list[Detection]] = [[detections[0]]]
        for detection in detections[1:]:
            current = clusters[-1]
            if detection.timestamp - current[-1].timestamp <= self.CORRELATION_WINDOW:
                current.append(detection)
            else:
                clusters.append([detection])
        return clusters

    def _build_seed(self, entity: str, detections: list[Detection]) -> _InvestigationSeed:
        users: set[str] = set()
        hosts: set[str] = set()
        ips: set[str] = set()
        for detection in detections:
            for value in detection.entities or []:
                kind = self._classify_entity(value)
                if kind == "ip":
                    ips.add(value)
                elif kind == "host":
                    hosts.add(value)
                elif kind == "user":
                    users.add(value)
            for event in detection.events or []:
                for value in (
                    getattr(event, "user", None),
                    getattr(event, "source_host", None),
                    getattr(event, "target_host", None),
                    getattr(event, "ip_address", None),
                ):
                    if not value:
                        continue
                    kind = self._classify_entity(str(value))
                    if kind == "ip":
                        ips.add(str(value))
                    elif kind == "host":
                        hosts.add(str(value))
                    else:
                        users.add(str(value))
        return _InvestigationSeed(entity, detections, users, hosts, ips)

    def _second_pass_merge(self, seeds: list[_InvestigationSeed]) -> list[_InvestigationSeed]:
        merged: list[_InvestigationSeed] = []
        used = [False] * len(seeds)
        for idx, seed in enumerate(seeds):
            if used[idx]:
                continue
            current = seed
            changed = True
            used[idx] = True
            while changed:
                changed = False
                for jdx, other in enumerate(seeds):
                    if used[jdx]:
                        continue
                    if self._should_merge(current, other):
                        current = self._merge_seeds(current, other)
                        used[jdx] = True
                        self._stats["merged_clusters"] += 1
                        changed = True
            merged.append(current)
        return merged

    def _should_merge(self, left: _InvestigationSeed, right: _InvestigationSeed) -> bool:
        left_start, left_end = left.detections[0].timestamp, left.detections[-1].timestamp
        right_start, right_end = right.detections[0].timestamp, right.detections[-1].timestamp
        gap = max(left_start, right_start) - min(left_end, right_end)
        if gap > self.CORRELATION_WINDOW:
            return False

        shared_hosts = left.hosts & right.hosts
        shared_ips = left.ips & right.ips
        shared_users = left.users & right.users
        if shared_hosts or shared_ips:
            return True
        if shared_users and gap <= self.ADJACENT_MERGE_WINDOW:
            return True
        if gap <= self.ADJACENT_MERGE_WINDOW and ((left.hosts and right.ips) or (left.ips and right.hosts)):
            return True
        return False

    def _merge_seeds(self, left: _InvestigationSeed, right: _InvestigationSeed) -> _InvestigationSeed:
        detections = sorted([*left.detections, *right.detections], key=lambda d: d.timestamp)
        return _InvestigationSeed(
            primary_entity=left.primary_entity if left.primary_entity != "unknown" else right.primary_entity,
            detections=detections,
            users=set(left.users) | set(right.users),
            hosts=set(left.hosts) | set(right.hosts),
            ips=set(left.ips) | set(right.ips),
        )

    @staticmethod
    def _classify_entity(value: str) -> str:
        item = (value or "").strip()
        if not item:
            return "other"
        try:
            ipaddress.ip_address(item)
            return "ip"
        except ValueError:
            pass
        lower = item.lower()
        if any(token in lower for token in ("dc", "srv", "server", "ws", "wk", "host", ".local", ".corp")):
            return "host"
        if item.endswith("$"):
            return "host"
        if "\\" in item or "@" in item:
            return "user"
        if item.isupper() and any(ch.isdigit() for ch in item):
            return "host"
        return "user"

    @staticmethod
    def _determine_phase(detections: list[Detection]) -> AttackPhase:
        phase_priority = [
            AttackPhase.DOMAIN_DOMINANCE,
            AttackPhase.DEFENSE_EVASION,
            AttackPhase.PERSISTENCE,
            AttackPhase.LATERAL_MOVEMENT,
            AttackPhase.PRIVILEGE_ESCALATION,
            AttackPhase.CREDENTIAL_ACCESS,
            AttackPhase.RECONNAISSANCE,
            AttackPhase.INITIAL_ACCESS,
        ]
        detected_phases = set()
        for detection in detections:
            phase = MITRE_TO_PHASE.get(detection.mitre_tactic)
            if phase:
                detected_phases.add(phase)
        for phase in phase_priority:
            if phase in detected_phases:
                return phase
        return AttackPhase.INITIAL_ACCESS

    @staticmethod
    def _max_severity(detections: list[Detection]) -> Severity:
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return min(
            (d.severity for d in detections),
            key=lambda s: severity_order.get(s, 5),
        )

    @staticmethod
    def _collect_related_entities(detections: list[Detection], primary: str) -> list[str]:
        related: set[str] = set()
        for detection in detections:
            for entity in detection.entities:
                if entity and entity != primary:
                    related.add(entity)
        return sorted(related)[:20]

    @staticmethod
    def _generate_summary(entity: str, detections: list[Detection], phase: AttackPhase) -> str:
        techniques = sorted(set(d.mitre_technique for d in detections if d.mitre_technique))
        duration = detections[-1].timestamp - detections[0].timestamp
        if duration.total_seconds() < 60:
            duration_str = "moins d'une minute"
        elif duration.total_seconds() < 3600:
            duration_str = f"{int(duration.total_seconds() / 60)} minutes"
        else:
            duration_str = f"{int(duration.total_seconds() / 3600)} heures"
        techniques_str = ", ".join(techniques[:6]) if techniques else "inconnues"
        return (
            f"Activité corrélée autour de '{entity}' sur {duration_str}. "
            f"Phase dominante: {phase.value}. Techniques observées: {techniques_str}."
        )

    def _seed_to_investigation(self, seed: _InvestigationSeed) -> InvestigationObject:
        detections = sorted(seed.detections, key=lambda d: d.timestamp)
        phase = self._determine_phase(detections)
        severity = self._max_severity(detections)
        primary = seed.primary_entity or next(iter(seed.users or seed.hosts or seed.ips or {"unknown"}))
        return InvestigationObject(
            id=self._stable_investigation_id(primary, detections),
            title=f"Investigation — {primary}",
            detections=detections,
            primary_entity=primary,
            related_entities=self._collect_related_entities(detections, primary),
            attack_phase=phase,
            severity=severity,
            start_time=detections[0].timestamp,
            end_time=detections[-1].timestamp,
            summary=self._generate_summary(primary, detections, phase),
        )

    @property
    def stats(self) -> dict[str, int]:
        data = dict(self._stats)
        data.update(self._quality.snapshot().get("stats", {}))
        return data

    @property
    def quality_report(self) -> dict[str, Dict[str, object]]:
        snap = self._quality.snapshot()
        snap["stats"] = {**self._stats, **(snap.get("stats") or {})}
        return snap
