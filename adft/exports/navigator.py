from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List


def build_attack_navigator_layer(alerts: List[Dict[str, Any]] | None = None, name: str = "ADFT Observed Exposure") -> Dict[str, Any]:
    alerts = list(alerts or [])
    counter = Counter()
    tactics: dict[str, set[str]] = {}
    for a in alerts:
        mid = (a.get("mitre_id") or "").strip()
        if not mid:
            continue
        counter[mid] += 1
        tac = (a.get("mitre_tactic") or "").strip()
        if tac:
            tactics.setdefault(mid, set()).add(tac)

    max_count = max(counter.values()) if counter else 1
    techniques = []
    for mid, count in sorted(counter.items()):
        score = int(round((count / max_count) * 100)) if max_count else count
        techniques.append({
            "techniqueID": mid,
            "score": score,
            "comment": f"Observed {count} time(s) in ADFT detections",
            "metadata": [
                {"name": "count", "value": str(count)},
                {"name": "tactics", "value": ", ".join(sorted(tactics.get(mid, set())) or ["unknown"])}
            ],
        })

    return {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Observed techniques extracted from ADFT correlated detections.",
        "filters": {"platforms": ["Windows"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "average", "showID": False, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#1f2937", "#2563eb", "#ef4444"], "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": "Observed lightly", "color": "#2563eb"},
            {"label": "Observed heavily", "color": "#ef4444"},
        ],
    }
