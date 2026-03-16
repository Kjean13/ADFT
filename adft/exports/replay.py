from __future__ import annotations

from typing import Any, Dict, List


def build_replay_payload(
    *,
    alerts: List[Dict[str, Any]] | None = None,
    timeline: Dict[str, Any] | None = None,
    investigations: List[Dict[str, Any]] | None = None,
    entity_graph: Dict[str, Any] | None = None,
    reconstruction: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    alerts = list(alerts or [])
    timeline = dict(timeline or {})
    investigations = list(investigations or [])
    entity_graph = dict(entity_graph or {})
    reconstruction = dict(reconstruction or {})

    entries = list(timeline.get("entries") or [])
    replay_steps: List[Dict[str, Any]] = []
    for idx, entry in enumerate(entries, 1):
        replay_steps.append({
            "step": idx,
            "timestamp": entry.get("timestamp"),
            "phase": entry.get("phase"),
            "title": entry.get("title") or entry.get("rule_id") or f"step-{idx}",
            "description": entry.get("description"),
            "detection_ids": entry.get("detection_ids") or [],
            "entities": entry.get("entities") or [],
        })

    return {
        "summary": {
            "alerts": len(alerts),
            "investigations": len(investigations),
            "steps": len(replay_steps),
            "graph_nodes": len(entity_graph.get("nodes") or []),
            "graph_edges": len(entity_graph.get("edges") or []),
        },
        "steps": replay_steps,
        "investigations": investigations,
        "entity_graph": entity_graph,
        "reconstruction": reconstruction,
    }
