from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Dict, List, Set, Tuple


PRIVILEGED_TOKENS = ("admin", "administrator", "krbtgt", "domain admins", "enterprise admins", "svc_")


def _norm(s: Any) -> str:
    return str(s).strip() if s is not None else ""


def _is_dc_like(value: str) -> bool:
    s = _norm(value).lower()
    return s.startswith("dc") or s in {"domaincontroller", "domain-controller"}


def _is_privileged(value: str) -> bool:
    s = _norm(value).lower()
    return any(tok in s for tok in PRIVILEGED_TOKENS)


def _build_value_type(graph: Dict[str, Any]) -> Dict[str, str]:
    value_type: Dict[str, str] = {}
    for n in graph.get("nodes") or []:
        if not isinstance(n, dict):
            continue
        v = _norm(n.get("value"))
        t = _norm(n.get("type")).lower()
        if v and v not in value_type:
            value_type[v] = t
    return value_type


def build_attack_paths(
    graph: Dict[str, Any],
    *,
    max_depth: int = 5,
    include_single_hop: bool = True,
) -> List[List[str]]:
    """Build attack paths from an ADFT entity_graph."""
    if not isinstance(graph, dict):
        return []

    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    if not nodes or not edges:
        return []

    value_type = _build_value_type(graph)
    adj: Dict[str, List[str]] = defaultdict(list)
    for e in edges:
        if not isinstance(e, dict):
            continue
        a = _norm(e.get("from") or e.get("source") or e.get("src"))
        b = _norm(e.get("to") or e.get("target") or e.get("dst"))
        if a and b:
            adj[a].append(b)
    if not adj:
        return []

    crown_targets = {v for v, t in value_type.items() if (t == "host" and _is_dc_like(v)) or (t in {"account", "user"} and _is_privileged(v))}

    def is_source(v: str) -> bool:
        t = value_type.get(v, "")
        return t in {"ip", "account", "user", "host"}

    def is_target(v: str) -> bool:
        if crown_targets:
            return v in crown_targets
        return value_type.get(v, "") == "host"

    sources = [v for v in value_type.keys() if is_source(v)] or list(adj.keys())
    targets = {v for v in value_type.keys() if is_target(v)}

    paths: List[List[str]] = []
    seen_paths: Set[Tuple[str, ...]] = set()
    for source in sources:
        if source not in adj:
            continue
        q = deque([(source, [source])])
        while q:
            cur, path = q.popleft()
            if len(path) > max_depth:
                continue
            if cur in targets:
                if include_single_hop or len(path) >= 2:
                    tp = tuple(path)
                    if tp not in seen_paths:
                        seen_paths.add(tp)
                        paths.append(path)
            for nxt in adj.get(cur, []):
                if not nxt or nxt in path:
                    continue
                q.append((nxt, path + [nxt]))

    if not include_single_hop:
        paths = [p for p in paths if len(p) >= 2]
    paths.sort(key=lambda p: (-len(p), " → ".join(p).lower()))
    return paths


def analyze_attack_paths(graph: Dict[str, Any], *, max_depth: int = 6, limit: int = 8) -> List[Dict[str, Any]]:
    """Annotate attack paths so the UI/CLI can prioritize the useful ones."""
    value_type = _build_value_type(graph)
    paths = build_attack_paths(graph, max_depth=max_depth, include_single_hop=True)
    annotated: List[Dict[str, Any]] = []
    seen = set()
    for path in paths:
        if not path:
            continue
        source = path[0]
        target = path[-1]
        source_type = value_type.get(source, "")
        target_type = value_type.get(target, "")
        reasons: List[str] = []
        score = 0
        if source_type == "ip":
            reasons.append("origine réseau visible")
            score += 2
        if _is_dc_like(target):
            reasons.append("cible AD sensible")
            score += 4
        if _is_privileged(target) or any(_is_privileged(node) for node in path):
            reasons.append("identité privilégiée impliquée")
            score += 3
        if len(path) >= 4:
            reasons.append("chaîne multi-sauts")
            score += 2
        if any(value_type.get(node, "") == "host" for node in path[1:-1]):
            reasons.append("pivot intermédiaire observé")
            score += 1
        risk = "low"
        if score >= 7:
            risk = "high"
        elif score >= 4:
            risk = "medium"
        entry = {
            "path": path,
            "summary": " → ".join(path),
            "length": len(path),
            "source": source,
            "source_type": source_type,
            "target": target,
            "target_type": target_type,
            "risk_score": score,
            "risk_level": risk,
            "reasons": reasons or ["relation orientée observée"],
        }
        key = (entry["summary"], entry["risk_level"], entry["risk_score"])
        if key not in seen:
            seen.add(key)
            annotated.append(entry)
    annotated.sort(key=lambda item: (-int(item["risk_score"]), -int(item["length"]), item["summary"].lower()))
    return annotated[:limit]
