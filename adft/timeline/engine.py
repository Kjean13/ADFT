"""
=========================================================
Moteur de Timeline ------- MODULE LE PLUS IMPORTANT
=========================================================

Ce module reconstruit la NARRATIVE CHRONOLOGIQUE de l'attaque.

Priorité : CLARTÉ > complexité.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from adft.core.models.events import (
    AttackPhase,
    Detection,
    InvestigationObject,
    Severity,
    TimelineEntry,
)

# ═══════════════════════════════════════════════════════
#  Descriptions des phases pour la narrative
# ═══════════════════════════════════════════════════════

PHASE_DESCRIPTIONS: dict[AttackPhase, str] = {
    AttackPhase.INITIAL_ACCESS: (
        "L'attaquant obtient un premier accès au réseau (phishing, creds volés, service exposé)."
    ),
    AttackPhase.RECONNAISSANCE: (
        "L'attaquant énumère l'environnement AD (users, groupes, machines, GPO, trusts)."
    ),
    AttackPhase.CREDENTIAL_ACCESS: (
        "Vol/tentative de vol d'identifiants (Kerberoasting, AS-REP roasting, dump LSASS, etc.)."
    ),
    AttackPhase.PRIVILEGE_ESCALATION: (
        "Élévation de privilèges (passage admin/local -> admin domaine, droits sensibles, etc.)."
    ),
    AttackPhase.LATERAL_MOVEMENT: (
        "Déplacement latéral entre machines (RDP, PsExec, WMI, WinRM, Pass-the-Hash)."
    ),
    AttackPhase.PERSISTENCE: (
        "Mécanismes de persistance (compte, service, tâche planifiée, clé run, WMI, etc.)."
    ),
    AttackPhase.DEFENSE_EVASION: (
        "Masquage/évasion (effacement logs, désactivation audit, timestomp, contournements)."
    ),
    AttackPhase.DOMAIN_DOMINANCE: (
        "Contrôle du domaine (DCSync/DCShadow, Golden Ticket, altération objets AD à grande échelle)."
    ),
}


class TimelineEngine:
    """
    Moteur de reconstruction de timeline d'attaque.

    Transforme investigations + détections en séquence chronologique lisible
    (phases -> titres -> descriptions).
    """

    # Mapping MITRE tactic (string) -> AttackPhase
    _TACTIC_MAP: dict[str, AttackPhase] = {
        "initial access": AttackPhase.INITIAL_ACCESS,
        "reconnaissance": AttackPhase.RECONNAISSANCE,
        "discovery": AttackPhase.RECONNAISSANCE,
        "credential access": AttackPhase.CREDENTIAL_ACCESS,
        "privilege escalation": AttackPhase.PRIVILEGE_ESCALATION,
        "lateral movement": AttackPhase.LATERAL_MOVEMENT,
        "persistence": AttackPhase.PERSISTENCE,
        "defense evasion": AttackPhase.DEFENSE_EVASION,
        "command and control": AttackPhase.LATERAL_MOVEMENT,  # fallback pratique
        "exfiltration": AttackPhase.DOMAIN_DOMINANCE,         # fallback (selon ton modèle)
        "impact": AttackPhase.DOMAIN_DOMINANCE,               # fallback
    }

    def build(
        self,
        investigations: list[InvestigationObject],
        detections: list[Detection],
    ) -> list[TimelineEntry]:
        """
        Construit la timeline d'attaque.

        1) Entrées depuis les investigations (si disponibles)
        2) Sinon, entrées depuis les détections brutes
        3) Déduplication
        4) Tri chrono
        """
        if not investigations and not detections:
            return []

        entries: list[TimelineEntry] = []

        # 1) depuis investigations (corrélations)
        for inv in investigations or []:
            for det in getattr(inv, "detections", []) or []:
                entries.append(self._detection_to_entry(det, inv))

        # 2) fallback : détections directes
        if not entries and detections:
            for det in detections:
                entries.append(self._detection_to_standalone_entry(det))

        # 3) dédup
        entries = self._deduplicate(entries)

        # 4) tri chrono (narrative)
        entries.sort(key=lambda e: e.timestamp or datetime.min)

        return entries

    # ─────────────────────────────────────────────────────
    #  Conversions Detection -> TimelineEntry
    # ─────────────────────────────────────────────────────

    def _detection_to_entry(
        self,
        detection: Detection,
        investigation: InvestigationObject,
    ) -> TimelineEntry:
        phase = self._tactic_to_phase(getattr(detection, "mitre_tactic", None))
        title = self._build_title(detection, phase)
        description = self._build_description(detection, phase)

        return TimelineEntry(
            timestamp=getattr(detection, "timestamp", None),
            phase=phase,
            title=title,
            description=description,
            severity=getattr(detection, "severity", Severity.MEDIUM),
            entities=self._entities_dict(detection),  # ✅ SAFE dict
            mitre_ids=[getattr(detection, "mitre_id", None)] if getattr(detection, "mitre_id", None) else [],
            detection_ids=[getattr(detection, "id", None)] if getattr(detection, "id", None) else [],
            rule_id=getattr(detection, "rule_id", None),
        )

    def _detection_to_standalone_entry(self, detection: Detection) -> TimelineEntry:
        phase = self._tactic_to_phase(getattr(detection, "mitre_tactic", None))
        title = self._build_title(detection, phase)
        description = self._build_description(detection, phase)

        return TimelineEntry(
            timestamp=getattr(detection, "timestamp", None),
            phase=phase,
            title=title,
            description=description,
            severity=getattr(detection, "severity", Severity.MEDIUM),
            entities=self._entities_dict(detection),  # ✅ SAFE dict
            mitre_ids=[getattr(detection, "mitre_id", None)] if getattr(detection, "mitre_id", None) else [],
            detection_ids=[getattr(detection, "id", None)] if getattr(detection, "id", None) else [],
            rule_id=getattr(detection, "rule_id", None),
        )

    # ─────────────────────────────────────────────────────
    #  Phase mapping
    # ─────────────────────────────────────────────────────

    def _tactic_to_phase(self, tactic: Optional[str]) -> AttackPhase:
        """
        Map une tactique MITRE (string) vers une AttackPhase ADFT.
        Fallback : RECONNAISSANCE si inconnu/absent.
        """
        if not tactic:
            return AttackPhase.RECONNAISSANCE

        t = str(tactic).strip().lower()
        return self._TACTIC_MAP.get(t, AttackPhase.RECONNAISSANCE)

    # ─────────────────────────────────────────────────────
    #  Narrative builders
    # ─────────────────────────────────────────────────────

    def _build_title(self, detection: Detection, phase: AttackPhase) -> str:
        """
        Titre court, lisible en 1 ligne.
        """
        mitre = getattr(detection, "mitre_id", None)
        name = getattr(detection, "name", None) or getattr(detection, "rule_name", None) or "Activity"
        if mitre:
            return f"[{phase.name}] {name} ({mitre})"
        return f"[{phase.name}] {name}"

    def _build_description(self, detection: Detection, phase: AttackPhase) -> str:
        """
        Description courte + détails (actor/src/dst) si dispo.
        """
        ent = self._entities_dict(detection)  # ✅ jamais une liste ici
        actor = self._pick_actor(ent)
        src = self._pick_src(ent)
        dst = self._pick_dst(ent)
        details = self._pick_details(detection, ent)

        base = PHASE_DESCRIPTIONS.get(phase, "Activité détectée dans le cadre de l'investigation.")
        parts: list[str] = [base]

        line = []
        if actor:
            line.append(f"actor={actor}")
        if src:
            line.append(f"src={src}")
        if dst:
            line.append(f"dst={dst}")
        if line:
            parts.append("Contexte: " + ", ".join(line))

        if details:
            parts.append(f"Détails: {details}")

        return " | ".join(parts)

    # ─────────────────────────────────────────────────────
    #  Entities normalization (FIX du 'list has no get')
    # ─────────────────────────────────────────────────────

    def _entities_dict(self, detection: Detection) -> dict:
        """
        Normalise detection.entities en dict.
        - dict => ok
        - list[dict] => merge
        - list[str]/autres => ignore
        - None => {}
        """
        ent = getattr(detection, "entities", None)

        if isinstance(ent, dict):
            return ent

        if isinstance(ent, list):
            merged: dict = {}
            for item in ent:
                if isinstance(item, dict):
                    merged.update(item)
            return merged

        return {}

    # ─────────────────────────────────────────────────────
    #  Pick helpers (no crash)
    # ─────────────────────────────────────────────────────

    def _pick_actor(self, ent: dict) -> Optional[str]:
        for k in ("user", "username", "account", "subject_user", "src_user", "actor"):
            v = ent.get(k)
            if v:
                return str(v)
        return None

    def _pick_src(self, ent: dict) -> Optional[str]:
        for k in ("src_ip", "source_ip", "ip", "client_ip", "workstation", "src_host", "source_host"):
            v = ent.get(k)
            if v:
                return str(v)
        return None

    def _pick_dst(self, ent: dict) -> Optional[str]:
        for k in ("dst_ip", "dest_ip", "destination_ip", "target_ip", "target_host", "dst_host", "computer"):
            v = ent.get(k)
            if v:
                return str(v)
        return None

    def _pick_details(self, detection: Detection, ent: dict) -> Optional[str]:
        # détail prioritaire : message/summary/commandline
        for attr in ("summary", "message", "detail", "details", "command_line", "cmdline"):
            v = getattr(detection, attr, None)
            if v:
                return str(v)

        for k in ("process", "image", "parent_image", "service", "share", "object", "event_id"):
            v = ent.get(k)
            if v:
                return f"{k}={v}"

        return None

    # ─────────────────────────────────────────────────────
    #  Deduplication
    # ─────────────────────────────────────────────────────

    def _deduplicate(self, entries: list[TimelineEntry]) -> list[TimelineEntry]:
        """
        Dédup simple : même phase + même titre + timestamps proches (<= 30s).
        """
        if not entries:
            return entries

        entries_sorted = sorted(entries, key=lambda e: e.timestamp or datetime.min)

        out: list[TimelineEntry] = []
        window = timedelta(seconds=30)

        for e in entries_sorted:
            if not out:
                out.append(e)
                continue

            last = out[-1]

            if not e.timestamp or not last.timestamp:
                out.append(e)
                continue

            same_signature = (e.phase == last.phase) and (e.title == last.title)
            close = abs(e.timestamp - last.timestamp) <= window

            if same_signature and close:
                last.detection_ids = list(dict.fromkeys((last.detection_ids or []) + (e.detection_ids or [])))
                last.mitre_ids = list(dict.fromkeys((last.mitre_ids or []) + (e.mitre_ids or [])))

                merged = {}
                merged.update(last.entities or {})
                merged.update(e.entities or {})
                last.entities = merged

                last.severity = self._max_severity(last.severity, e.severity)
                continue

            out.append(e)

        return out

    def _max_severity(self, a: Severity, b: Severity) -> Severity:
        """
        Compare robuste (si Severity est Enum/str/int selon ton modèle).
        """
        try:
            return a if a >= b else b
        except Exception:
            order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            sa = order.get(str(a).upper(), 2)
            sb = order.get(str(b).upper(), 2)
            return a if sa >= sb else b