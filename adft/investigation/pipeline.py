from __future__ import annotations

from typing import Any, Dict, List

from adft.explain.deterministic import build_case_explanation
from adft.graph.entity_graph import build_entity_graph
from adft.investigation.attack_story import build_attack_story
from adft.reconstruction import build_compromise_reconstruction


def run_investigation_pipeline(
    *,
    events: List[Dict[str, Any]],
    detections: List[Any],
    timeline: Any,
    alerts: List[Dict[str, Any]] | None = None,
    investigations: List[Dict[str, Any]] | None = None,
    security_score: Dict[str, Any] | None = None,
    hardening: Dict[str, Any] | None = None,
    model: str | None = None,
    enable_ai: bool = False,
) -> Dict[str, Any]:
    """Pipeline recentré et déterministe.

    Le cœur métier reste :
    attack story + entity graph + explication multi-niveaux fondée sur les preuves.
    Aucun enrichissement externe n'est requis dans la version purifiée.
    """
    _ = detections, model, enable_ai
    attack_story = build_attack_story(events)
    graph = build_entity_graph(events)
    timeline_dict = timeline.to_dict() if hasattr(timeline, "to_dict") else (timeline or {})

    reconstruction = build_compromise_reconstruction(
        alerts=alerts or [],
        investigations=investigations or [],
        timeline=timeline_dict if isinstance(timeline_dict, dict) else {},
        entity_graph=graph,
        attack_story=attack_story,
    )

    case_explanation = build_case_explanation(
        alerts=alerts or [],
        investigations=investigations or [],
        timeline=timeline_dict if isinstance(timeline_dict, dict) else {},
        security_score=security_score or {},
        hardening=hardening or {},
    )

    return {
        "attack_story": attack_story,
        "graph": graph,
        "case_explanation": case_explanation,
        "reconstruction": reconstruction,
        # alias conservé pour compat rapport/UI existants
    }
