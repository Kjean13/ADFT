"""
ADFT — Modèles Timeline

AttackTimeline agrège des TimelineEntry et fournit des bornes temporelles.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, List, Optional

from adft.core.models.events import TimelineEntry


@dataclass
class AttackTimeline:
    entries: List[TimelineEntry] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    def __post_init__(self) -> None:
        if self.entries:
            times = []
            for e in self.entries:
                ts = getattr(e, "timestamp", None)
                if ts is not None:
                    times.append(ts)
            if times and self.start_time is None:
                self.start_time = min(times)
            if times and self.end_time is None:
                self.end_time = max(times)

    @property
    def summary(self) -> dict[str, Any]:
        """
        Résumé compact utilisé par le reporting (JSON/HTML).
        Permet d'éviter l'erreur: AttackTimeline has no attribute 'summary'.
        """
        return {
            "available": bool(self.entries),
            "entries_count": len(self.entries),
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": bool(self.entries),
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "entries": [e.to_dict() if hasattr(e, "to_dict") else e for e in self.entries],
        }
