"""adft.analysis.noise_filter

Deterministic noise reduction utilities.

- `filter_events` : minimal pre-tri for NormalizedEvent (unit tests / hygiene)
- `filter_alerts` : deduplication/bucketing for DetectionAlert (SOC usage)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Tuple, Set, Any

from adft.core.models.alerts import DetectionAlert


class NoiseFilter:
    """Rule-based noise filter / deduplicator."""

    # Rules known to be bursty in AD labs; widen bucket window
    _WIDE_BUCKET_RULES: Set[str] = {"PRIV-002", "ADMIN-001"}
    _DEFAULT_BUCKET_MINUTES = 1
    _WIDE_BUCKET_MINUTES = 30

    # Low-value Windows events for DFIR in this context (can be extended)
    _LOW_VALUE_EVENT_IDS: Set[int] = {4616}  # system time change (too noisy by default)
    _SYSTEM_USERS: Set[str] = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}

    def filter_events(self, events):  # type: ignore[no-untyped-def]
        """Filtre des événements normalisés (pré-tri).

        Règles stables :
        - Exclut comptes machine (suffixe '$')
        - Exclut comptes système courants
        - Exclut EventIDs à faible valeur (par défaut: 4616)
        """
        if not events:
            return events

        kept = []
        for ev in events:
            user = str(getattr(ev, "user", "") or "")
            eid = int(getattr(ev, "event_id", 0) or 0)

            if user.endswith("$"):
                continue
            if user.upper() in self._SYSTEM_USERS:
                continue
            if eid in self._LOW_VALUE_EVENT_IDS:
                continue

            kept.append(ev)

        return kept

    def filter_alerts(self, alerts: List[DetectionAlert]) -> List[DetectionAlert]:
        """Déduplique et réduit le bruit sur les alertes."""
        if not alerts:
            return alerts

        # Sort by time so we keep earliest representative per bucket
        def _ts(a: DetectionAlert) -> str:
            return getattr(a, "timestamp", "") or ""

        alerts_sorted = sorted(alerts, key=_ts)

        seen: Dict[Tuple[str, str, str, str], DetectionAlert] = {}
        kept: List[DetectionAlert] = []

        for a in alerts_sorted:
            key = self._dedup_key(a)
            if key in seen:
                continue
            seen[key] = a
            kept.append(a)

        return kept

    def _dedup_key(self, a: DetectionAlert) -> Tuple[str, str, str, str]:
        ts_bucket = self._ts_bucket(getattr(a, "timestamp", ""), getattr(a, "rule_id", ""))
        rid = (getattr(a, "rule_id", "") or "").strip()
        user = (getattr(a, "user", "") or "").strip()
        host = (getattr(a, "target_host", "") or getattr(a, "host", "") or "").strip()
        return (rid, user, host, ts_bucket)

    def _ts_bucket(self, ts: str, rule_id: str | None = None) -> str:
        """Return bucket string; widen for some rule_ids."""
        if not ts:
            return ""

        minutes = self._DEFAULT_BUCKET_MINUTES
        rid = (rule_id or "").strip().upper()
        if rid in self._WIDE_BUCKET_RULES:
            minutes = self._WIDE_BUCKET_MINUTES

        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        except Exception:
            return ts[:16]

        bucket_min = (dt.minute // minutes) * minutes
        dt_bucket = dt.replace(minute=bucket_min, second=0, microsecond=0)
        return dt_bucket.isoformat(timespec="minutes")
