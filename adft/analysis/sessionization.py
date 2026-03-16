"""Sessionization Engine — corrélation comportementale par sessions glissantes.

Fenêtres : 4h max, gap de 45min pour couper une session.

Patterns détectés :
  SEQ-001 : Brute force → succès (échecs 4625 suivis de 4624 pour le même user/IP)
  SEQ-002 : Lateral movement multi-hôtes (4624 type 3 sur N hôtes depuis même IP)
  SEQ-003 : Credential access → escalade (4769/4662 suivi de 4672/4728 par même user)
  SEQ-004 : Activité nocturne (logon + actions critiques entre 22h et 5h UTC)
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from adft.core.models.events import NormalizedEvent, Severity


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SESSION_MAX_DURATION = timedelta(hours=4)
SESSION_GAP_THRESHOLD = timedelta(minutes=45)

NIGHT_START_HOUR = 22   # UTC
NIGHT_END_HOUR = 5      # UTC

LATERAL_HOST_THRESHOLD = 3      # Min hôtes distincts pour SEQ-002
BRUTE_FORCE_MIN_FAILS = 5       # Min échecs avant le succès pour SEQ-001
CRED_ESCALATION_WINDOW = timedelta(minutes=30)  # Fenêtre SEQ-003


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Session:
    """Représente une session d'activité d'un utilisateur/IP."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    user: str = ""
    ip: str = ""
    host: str = ""
    events: list[NormalizedEvent] = field(default_factory=list)
    start: Optional[datetime] = None
    end: Optional[datetime] = None

    def add(self, ev: NormalizedEvent) -> None:
        self.events.append(ev)
        ts = ev.timestamp
        if self.start is None or ts < self.start:
            self.start = ts
        if self.end is None or ts > self.end:
            self.end = ts

    @property
    def duration(self) -> timedelta:
        if self.start and self.end:
            return self.end - self.start
        return timedelta(0)

    @property
    def is_nocturnal(self) -> bool:
        """True si la majorité des événements tombent en période nocturne UTC."""
        nocturnal = sum(
            1 for e in self.events
            if _is_night_hour(e.timestamp.hour if e.timestamp.tzinfo else e.timestamp.replace(tzinfo=timezone.utc).hour)
        )
        return nocturnal >= max(1, len(self.events) // 2)


@dataclass
class SessionPattern:
    """Résultat d'un pattern comportemental détecté dans une session."""
    pattern_id: str         # SEQ-001 … SEQ-004
    pattern_name: str
    description: str
    severity: Severity
    session: Session
    evidence_events: list[NormalizedEvent] = field(default_factory=list)
    confidence: float = 0.75
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _is_night_hour(hour: int) -> bool:
    return hour >= NIGHT_START_HOUR or hour < NIGHT_END_HOUR


def _get_logon_type(ev: NormalizedEvent) -> int:
    lt = getattr(ev, "logon_type", None)
    if lt is None:
        lt = (ev.raw_event or {}).get("LogonType") or (ev.raw_event or {}).get("logon_type")
    try:
        return int(str(lt or "0").strip())
    except ValueError:
        return 0


# ---------------------------------------------------------------------------
# Sessionizer
# ---------------------------------------------------------------------------

class SessionEngine:
    """Moteur de sessionisation et de détection de patterns comportementaux."""

    def __init__(
        self,
        max_duration: timedelta = SESSION_MAX_DURATION,
        gap_threshold: timedelta = SESSION_GAP_THRESHOLD,
    ) -> None:
        self.max_duration = max_duration
        self.gap_threshold = gap_threshold
        self._sessions: list[Session] = []
        self._patterns: list[SessionPattern] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process(self, events: list[NormalizedEvent]) -> list[SessionPattern]:
        """Sessionize les événements et retourne les patterns détectés."""
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        self._sessions = self._build_sessions(sorted_events)
        self._patterns = []
        for session in self._sessions:
            self._patterns.extend(self._detect_patterns(session))
        return self._patterns

    @property
    def sessions(self) -> list[Session]:
        return list(self._sessions)

    @property
    def patterns(self) -> list[SessionPattern]:
        return list(self._patterns)

    @property
    def stats(self) -> dict[str, Any]:
        by_pattern: dict[str, int] = defaultdict(int)
        for p in self._patterns:
            by_pattern[p.pattern_id] += 1
        return {
            "sessions": len(self._sessions),
            "patterns_detected": len(self._patterns),
            "by_pattern": dict(by_pattern),
        }

    # ------------------------------------------------------------------
    # Session building (fenêtre glissante)
    # ------------------------------------------------------------------

    def _build_sessions(self, events: list[NormalizedEvent]) -> list[Session]:
        """Découpe les événements en sessions par (user, IP) avec gap et max_duration."""
        # Grouper par (user, ip)
        buckets: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
        for ev in events:
            user = ev.user or "?"
            ip = ev.ip_address or ev.source_host or "?"
            buckets[(user, ip)].append(ev)

        sessions: list[Session] = []
        for (user, ip), evs in buckets.items():
            sorted_evs = sorted(evs, key=lambda e: e.timestamp)
            current: Optional[Session] = None

            for ev in sorted_evs:
                if current is None:
                    current = Session(user=user, ip=ip)
                    current.add(ev)
                    continue

                gap = ev.timestamp - current.end  # type: ignore[operator]
                duration_if_added = ev.timestamp - current.start  # type: ignore[operator]

                # Couper si gap > seuil OU durée max atteinte
                if gap > self.gap_threshold or duration_if_added > self.max_duration:
                    sessions.append(current)
                    current = Session(user=user, ip=ip)

                current.add(ev)

            if current:
                sessions.append(current)

        return sessions

    # ------------------------------------------------------------------
    # Pattern detection
    # ------------------------------------------------------------------

    def _detect_patterns(self, session: Session) -> list[SessionPattern]:
        patterns: list[SessionPattern] = []
        p = self._check_seq001_brute_then_success(session)
        if p:
            patterns.append(p)
        p = self._check_seq002_lateral_multi_host(session)
        if p:
            patterns.append(p)
        p = self._check_seq003_cred_then_escalation(session)
        if p:
            patterns.append(p)
        p = self._check_seq004_nocturnal(session)
        if p:
            patterns.append(p)
        return patterns

    def _check_seq001_brute_then_success(self, session: Session) -> Optional[SessionPattern]:
        """SEQ-001 : Brute force (4625 x N) suivi d'un succès (4624)."""
        fails = [e for e in session.events if e.event_id == 4625]
        successes = [e for e in session.events if e.event_id == 4624]

        if len(fails) < BRUTE_FORCE_MIN_FAILS or not successes:
            return None

        # Vérifier qu'un succès suit les échecs
        last_fail = max(fails, key=lambda e: e.timestamp)
        success_after = [s for s in successes if s.timestamp > last_fail.timestamp]

        if not success_after:
            return None

        evidence = fails[-20:] + success_after[:5]
        return SessionPattern(
            pattern_id="SEQ-001",
            pattern_name="Brute Force → Succès",
            description=(
                f"Brute force détecté : {len(fails)} échec(s) (4625) suivi(s) "
                f"de {len(success_after)} succès (4624) pour «{session.user}» "
                f"depuis {session.ip}."
            ),
            severity=Severity.CRITICAL,
            session=session,
            evidence_events=sorted(evidence, key=lambda e: e.timestamp),
            confidence=0.88,
            metadata={"fails": len(fails), "successes": len(success_after)},
        )

    def _check_seq002_lateral_multi_host(self, session: Session) -> Optional[SessionPattern]:
        """SEQ-002 : Logon réseau (4624 type 3) sur plusieurs hôtes distincts."""
        lateral_evs = [
            e for e in session.events
            if e.event_id == 4624 and _get_logon_type(e) == 3
        ]

        hosts = {e.target_host for e in lateral_evs if e.target_host}

        if len(hosts) < LATERAL_HOST_THRESHOLD:
            return None

        return SessionPattern(
            pattern_id="SEQ-002",
            pattern_name="Lateral Movement — Multi-hôtes",
            description=(
                f"Mouvement latéral possible : «{session.user}» ({session.ip}) "
                f"a effectué des logons réseau (4624 type 3) sur {len(hosts)} "
                f"hôtes: {', '.join(sorted(hosts)[:6])}."
            ),
            severity=Severity.HIGH,
            session=session,
            evidence_events=sorted(lateral_evs, key=lambda e: e.timestamp)[:50],
            confidence=0.80,
            metadata={"hosts": sorted(hosts), "host_count": len(hosts)},
        )

    def _check_seq003_cred_then_escalation(self, session: Session) -> Optional[SessionPattern]:
        """SEQ-003 : Accès aux credentials (4769/4662) suivi d'escalade (4672/4728)."""
        cred_evs = [e for e in session.events if e.event_id in (4769, 4662, 4771)]
        esc_evs = [e for e in session.events if e.event_id in (4672, 4728, 4732, 4756)]

        if not cred_evs or not esc_evs:
            return None

        # Vérifier séquence temporelle dans la fenêtre
        for cred_ev in cred_evs:
            related_esc = [
                e for e in esc_evs
                if timedelta(0) <= (e.timestamp - cred_ev.timestamp) <= CRED_ESCALATION_WINDOW
            ]
            if related_esc:
                evidence = [cred_ev] + related_esc[:5]
                return SessionPattern(
                    pattern_id="SEQ-003",
                    pattern_name="Credential Access → Escalade Privilèges",
                    description=(
                        f"Séquence détectée : accès credentials (ID {cred_ev.event_id}) "
                        f"suivi d'escalade (ID {related_esc[0].event_id}) en "
                        f"{(related_esc[0].timestamp - cred_ev.timestamp).seconds}s "
                        f"par «{session.user}»."
                    ),
                    severity=Severity.CRITICAL,
                    session=session,
                    evidence_events=sorted(evidence, key=lambda e: e.timestamp),
                    confidence=0.82,
                    metadata={
                        "cred_event_id": cred_ev.event_id,
                        "esc_event_ids": [e.event_id for e in related_esc[:5]],
                    },
                )
        return None

    def _check_seq004_nocturnal(self, session: Session) -> Optional[SessionPattern]:
        """SEQ-004 : Activité critique de nuit (22h-5h UTC)."""
        critical_events = [
            e for e in session.events
            if e.event_id in (4728, 4732, 4756, 1102, 4720, 4662, 4769, 4672, 7045)
        ]

        if not critical_events:
            return None

        nocturnal = [
            e for e in critical_events
            if _is_night_hour(
                e.timestamp.hour if e.timestamp.tzinfo else
                e.timestamp.replace(tzinfo=timezone.utc).hour
            )
        ]

        if len(nocturnal) < 2:
            return None

        event_ids = sorted({e.event_id for e in nocturnal})
        return SessionPattern(
            pattern_id="SEQ-004",
            pattern_name="Activité Nocturne Suspecte",
            description=(
                f"Activité critique détectée hors heures de travail (22h-5h UTC) "
                f"par «{session.user}» : {len(nocturnal)} événement(s) "
                f"(IDs {event_ids}) depuis {session.ip}."
            ),
            severity=Severity.HIGH,
            session=session,
            evidence_events=sorted(nocturnal, key=lambda e: e.timestamp)[:50],
            confidence=0.70,
            metadata={"event_ids": event_ids, "nocturnal_count": len(nocturnal)},
        )
