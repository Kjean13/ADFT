from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, List, Tuple

# ==========================================================
# Entity Graph (deterministic, analyst-friendly)
# - Used for: report enrichment, campaign/story context, graph UI
# ==========================================================

AUTH_EVENT_IDS = {4624, 4625, 4648, 4768, 4769, 4771, 4776}
PRIVILEGED_TOKENS = ("admin", "administrator", "krbtgt", "domain admins", "enterprise admins", "svc_")


def _get(d: Dict[str, Any], *keys, default=None):
    """Smart getter supporting dotted keys."""

    def get_dotted(obj: Any, key: str):
        if not isinstance(obj, dict):
            return None
        if "." not in key:
            return obj.get(key)
        cur: Any = obj
        for part in key.split("."):
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        return cur

    for k in keys:
        v = get_dotted(d, k)
        if v not in (None, "", []):
            return v
    return default


def _get_event_id(e: Dict[str, Any]) -> int | None:
    v = _get(e, "event_id", "EventID", "event.code", "eventid", default=None)
    if v is None:
        return None
    try:
        return int(v)
    except Exception:
        return None


def _sanitize_id(prefix: str, value: str) -> str:
    """Return a Mermaid-safe node id."""
    s = (value or "").strip()
    s = s.replace("\\", "_").replace("/", "_").replace("-", "_").replace(".", "_").replace(":", "_")
    s = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in s)
    if not s:
        s = "unknown"
    if not s[0].isalpha():
        s = f"v_{s}"
    return f"{prefix}_{s}"


def _is_dc_like(host: str) -> bool:
    s = (host or "").strip().lower()
    return s in {"dc", "dc1", "dc2", "dc3", "domaincontroller", "domain-controller"} or s.startswith("dc")


def _is_privileged_account(user: str) -> bool:
    s = (user or "").strip().lower()
    return any(tok in s for tok in PRIVILEGED_TOKENS)


def _node_role(node_type: str, value: str) -> str:
    if node_type == "host" and _is_dc_like(value):
        return "domain_controller"
    if node_type == "account" and _is_privileged_account(value):
        return "privileged_account"
    if node_type == "ip":
        return "network_origin"
    if node_type == "host":
        return "endpoint"
    if node_type == "account":
        return "identity"
    return "entity"


def _criticality(node_type: str, value: str) -> str:
    role = _node_role(node_type, value)
    if role in {"domain_controller", "privileged_account"}:
        return "high"
    if role in {"endpoint", "network_origin"}:
        return "medium"
    return "low"


def _edge_rel_priority(rel: str) -> int:
    order = {
        "logged_on_as": 4,
        "accessed": 3,
        "connected_to": 2,
        "seen_on": 1,
    }
    return order.get(str(rel or ""), 0)


def build_entity_graph(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a deterministic entity graph from raw events."""
    node_counter: Counter[Tuple[str, str]] = Counter()
    edge_counter: Counter[Tuple[str, str, str]] = Counter()
    user_to_hosts: Dict[str, set[str]] = defaultdict(set)

    def add_node(node_type: str, value: str):
        text = str(value or "").strip()
        if text:
            node_counter[(node_type, text)] += 1

    def add_edge(source: str, rel: str, target: str):
        source = str(source or "").strip()
        target = str(target or "").strip()
        rel = str(rel or "").strip()
        if source and target and rel and source != target:
            edge_counter[(source, rel, target)] += 1

    for e in events or []:
        user = _get(e, "user", "username", "TargetUserName", "SubjectUserName", "AccountName", "account")
        src_host = _get(
            e,
            "source_host", "src_host", "src", "WorkstationName", "Workstation", "ClientName", "ClientComputerName",
            "ComputerName", "Computer", "host", "hostname",
        )
        tgt_host = _get(
            e,
            "target_host", "dest_host", "dst_host", "dest", "TargetServerName", "ComputerName", "Computer", "host", "hostname",
        )
        src_ip = _get(
            e,
            "ip_address", "source_ip", "src_ip", "source.ip", "client.ip", "winlog.event_data.IpAddress",
            "winlog.event_data.ClientAddress", "IpAddress", "ClientAddress",
        )
        eid = _get_event_id(e)

        if eid in AUTH_EVENT_IDS:
            ws = _get(
                e,
                "WorkstationName", "Workstation", "ClientName", "ClientComputerName",
                "winlog.event_data.WorkstationName", "winlog.event_data.Workstation",
                "winlog.event_data.ClientName", "winlog.event_data.ClientComputerName", "winlog.event_data.SourceWorkstation",
            )
            if ws:
                src_host = ws

        if eid in AUTH_EVENT_IDS and user and src_host:
            sh = str(src_host)
            if not _is_dc_like(sh):
                user_to_hosts[str(user)].add(sh)

        add_node("account", str(user) if user else "")
        add_node("host", str(src_host) if src_host else "")
        add_node("host", str(tgt_host) if tgt_host else "")
        add_node("ip", str(src_ip) if src_ip else "")

        if eid in AUTH_EVENT_IDS:
            if src_ip:
                to_host = str(src_host) if src_host else ""
                if to_host and _is_dc_like(to_host) and user:
                    cand = sorted(user_to_hosts.get(str(user), set()))
                    if cand:
                        to_host = cand[0]
                if to_host:
                    add_edge(str(src_ip), "seen_on", to_host)
            if src_host and user:
                add_edge(str(src_host), "logged_on_as", str(user))
            if user and tgt_host:
                add_edge(str(user), "accessed", str(tgt_host))
            if src_host and tgt_host and str(src_host) != str(tgt_host):
                add_edge(str(src_host), "connected_to", str(tgt_host))
        else:
            if user and tgt_host:
                add_edge(str(user), "accessed", str(tgt_host))
            if src_host and tgt_host and str(src_host) != str(tgt_host):
                add_edge(str(src_host), "connected_to", str(tgt_host))

    nodes: List[Dict[str, Any]] = []
    for (node_type, value), count in sorted(node_counter.items(), key=lambda item: (item[0][0], item[0][1].lower())):
        nodes.append({
            "type": node_type,
            "value": value,
            "count": count,
            "role": _node_role(node_type, value),
            "criticality": _criticality(node_type, value),
        })

    edges: List[Dict[str, Any]] = []
    for (source, rel, target), count in sorted(edge_counter.items(), key=lambda item: (-item[1], -_edge_rel_priority(item[0][1]), item[0][0].lower(), item[0][2].lower())):
        edges.append({"from": source, "rel": rel, "to": target, "count": count})

    graph = {"nodes": nodes, "edges": edges}
    graph["summary"] = {
        "nodes": len(nodes),
        "edges": len(edges),
        "accounts": sum(1 for n in nodes if n.get("type") == "account"),
        "hosts": sum(1 for n in nodes if n.get("type") == "host"),
        "ips": sum(1 for n in nodes if n.get("type") == "ip"),
        "domain_controllers": sum(1 for n in nodes if n.get("role") == "domain_controller"),
        "privileged_accounts": sum(1 for n in nodes if n.get("role") == "privileged_account"),
    }
    graph["analysis"] = analyze_graph(graph)
    graph["mermaid"] = to_mermaid(graph)
    return graph


def analyze_graph(graph: Dict[str, Any]) -> Dict[str, Any]:
    """Return analyst-friendly graph insights without changing the core graph."""
    nodes = list(graph.get("nodes") or [])
    edges = list(graph.get("edges") or [])
    if not nodes:
        return {
            "hot_nodes": [],
            "crown_jewels": [],
            "pivot_candidates": [],
            "paths": [],
            "attack_surface": "limited",
            "summary": "Graphe trop limité pour dériver des relations d’attaque utiles.",
        }

    inbound: Counter[str] = Counter()
    outbound: Counter[str] = Counter()
    rel_mix: Counter[str] = Counter()
    node_index = {str(n.get("value") or ""): n for n in nodes if n.get("value")}
    for edge in edges:
        src = str(edge.get("from") or "")
        dst = str(edge.get("to") or "")
        weight = int(edge.get("count") or 1)
        if src:
            outbound[src] += weight
        if dst:
            inbound[dst] += weight
        rel = str(edge.get("rel") or "")
        if rel:
            rel_mix[rel] += weight

    hot_nodes: List[Dict[str, Any]] = []
    pivot_candidates: List[Dict[str, Any]] = []
    crown_jewels: List[Dict[str, Any]] = []
    for value, node in node_index.items():
        node["inbound_degree"] = inbound.get(value, 0)
        node["outbound_degree"] = outbound.get(value, 0)
        node["degree"] = node["inbound_degree"] + node["outbound_degree"]
        record = {
            "value": value,
            "type": node.get("type"),
            "role": node.get("role"),
            "criticality": node.get("criticality"),
            "degree": node.get("degree"),
            "inbound_degree": node.get("inbound_degree", 0),
            "outbound_degree": node.get("outbound_degree", 0),
            "count": node.get("count", 1),
        }
        hot_nodes.append(record)
        if node.get("role") in {"domain_controller", "privileged_account"}:
            crown_jewels.append(record)
        if node["outbound_degree"] >= 1 and node.get("role") in {"network_origin", "endpoint", "identity", "privileged_account"}:
            pivot_candidates.append(record)

    hot_nodes.sort(key=lambda item: (-int(item["degree"]), -int(item["count"]), str(item["value"]).lower()))
    pivot_candidates.sort(key=lambda item: (-int(item["outbound_degree"]), -int(item["degree"]), str(item["value"]).lower()))
    crown_jewels.sort(key=lambda item: (-int(item["degree"]), str(item["value"]).lower()))

    from adft.graph.attack_path import analyze_attack_paths
    paths = analyze_attack_paths(graph, max_depth=6, limit=8)

    attack_surface = "limited"
    if crown_jewels or len(paths) >= 2:
        attack_surface = "high_value_paths_observed"
    elif len(hot_nodes) >= 4 and rel_mix.get("connected_to", 0):
        attack_surface = "multi_entity_observed"

    summary_parts = []
    if pivot_candidates:
        summary_parts.append("pivot(s) probable(s): " + ", ".join(p["value"] for p in pivot_candidates[:3]))
    if crown_jewels:
        summary_parts.append("actifs sensibles: " + ", ".join(c["value"] for c in crown_jewels[:3]))
    if paths:
        summary_parts.append("chemin(s) prioritaire(s): " + " ; ".join(p["summary"] for p in paths[:2]))
    summary = "; ".join(summary_parts) + ("." if summary_parts else "Graphe construit, mais sans relation d’attaque saillante.")

    return {
        "hot_nodes": hot_nodes[:8],
        "pivot_candidates": pivot_candidates[:6],
        "crown_jewels": crown_jewels[:6],
        "paths": paths,
        "attack_surface": attack_surface,
        "edge_mix": dict(rel_mix),
        "summary": summary,
    }


def to_mermaid(graph: Dict[str, Any]) -> str:
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []

    types_by_value: Dict[str, set[str]] = {}
    for n in nodes:
        v = n.get("value")
        t = n.get("type")
        if v and t:
            types_by_value.setdefault(v, set()).add(t)

    def ntype(v: str) -> str:
        ts = types_by_value.get(v, set())
        if "ip" in ts:
            return "ip"
        if "account" in ts:
            return "account"
        if "host" in ts:
            return "host"
        return "node"

    def label(v: str) -> str:
        t = ntype(v)
        if t == "ip":
            return f"IP: {v}"
        if t == "account":
            return f"Account: {v}"
        if t == "host":
            return f"Host: {v}"
        return v

    id_by_value: Dict[str, str] = {}
    for n in nodes:
        v = n.get("value") or ""
        t = n.get("type") or "node"
        prefix = "ip" if t == "ip" else "acct" if t == "account" else "host" if t == "host" else "node"
        if v and v not in id_by_value:
            id_by_value[v] = _sanitize_id(prefix, v)

    lines: List[str] = ["flowchart LR"]
    for v in sorted(id_by_value.keys(), key=lambda x: (ntype(x), x.lower())):
        nid = id_by_value[v]
        lab = label(v).replace('"', "'")
        t = ntype(v)
        if t == "account":
            shape = f"{nid}([{lab}])"
        elif t == "host":
            shape = f"{nid}[{lab}]"
        elif t == "ip":
            shape = f"{nid}(({lab}))"
        else:
            shape = f"{nid}[{lab}]"
        lines.append(f"  {shape}")

    for ed in sorted(edges, key=lambda e: (e.get("rel", ""), e.get("from", ""), e.get("to", ""))):
        f = ed.get("from") or ""
        t = ed.get("to") or ""
        rel = ed.get("rel") or "rel"
        count = int(ed.get("count") or 1)
        if not f or not t or f == t:
            continue
        fid = id_by_value.get(f) or _sanitize_id("node", f)
        tid = id_by_value.get(t) or _sanitize_id("node", t)
        rel_txt = rel.replace("_", " ")
        if count > 1:
            rel_txt += f" ×{count}"
        lines.append(f"  {fid} -->|{rel_txt}| {tid}")

    lines.append("  %% classes")
    lines.append("  classDef ip fill:#1f2937,stroke:#38bdf8,stroke-width:1px,color:#e5e7eb;")
    lines.append("  classDef host fill:#111827,stroke:#a78bfa,stroke-width:1px,color:#e5e7eb;")
    lines.append("  classDef account fill:#0b1220,stroke:#34d399,stroke-width:1px,color:#e5e7eb;")
    lines.append("  classDef crown fill:#2a1108,stroke:#f59e0b,stroke-width:2px,color:#fde68a;")
    for n in nodes:
        v = n.get("value")
        nid = id_by_value.get(v or "")
        if not nid:
            continue
        t = ntype(v)
        if t == "ip":
            lines.append(f"  class {nid} ip;")
        elif t == "host":
            lines.append(f"  class {nid} host;")
        elif t == "account":
            lines.append(f"  class {nid} account;")
        if n.get("role") in {"domain_controller", "privileged_account"}:
            lines.append(f"  class {nid} crown;")

    return "\n".join(lines)


def enrich_alerts_with_entities(alerts: List[Any], graph: Dict[str, Any]) -> List[Any]:
    """Enrich DetectionAlert-like objects with user/source_host/target_host/source_ip."""
    if not alerts:
        return alerts or []

    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []

    types_by_value: Dict[str, set[str]] = {}
    for n in nodes:
        v = n.get("value")
        t = n.get("type")
        if v and t:
            types_by_value.setdefault(v, set()).add(t)

    def pick(entities: List[str], wanted: str) -> str | None:
        for val in entities or []:
            if wanted in types_by_value.get(val, set()):
                return val
        return None

    def infer_hosts(entities: List[str]) -> tuple[str | None, str | None]:
        hosts = [v for v in (entities or []) if "host" in types_by_value.get(v, set())]
        if len(hosts) < 2:
            return (None, hosts[0] if hosts else None)
        hostset = set(hosts)
        for ed in edges:
            if ed.get("rel") != "connected_to":
                continue
            f = ed.get("from")
            t = ed.get("to")
            if f in hostset and t in hostset:
                return (f, t)
        hosts_sorted = sorted(hosts)
        return (hosts_sorted[0], hosts_sorted[-1])

    for a in alerts:
        ents = list(getattr(a, "entities", []) or [])
        evs = getattr(a, "events", None) or []
        if isinstance(evs, list) and evs:
            for ev in evs:
                if not isinstance(ev, dict):
                    continue
                if getattr(a, "user", None) in (None, ""):
                    u = _get(ev, "user")
                    if u:
                        setattr(a, "user", u)
                        if u not in ents:
                            ents.append(u)
                if getattr(a, "source_ip", None) in (None, ""):
                    ip2 = _get(ev, "source_ip", "src_ip")
                    if ip2:
                        setattr(a, "source_ip", ip2)
                        if ip2 not in ents:
                            ents.append(ip2)
                sh = _get(ev, "source_host")
                th = _get(ev, "target_host")
                if sh and sh not in ents:
                    ents.append(sh)
                if th and th not in ents:
                    ents.append(th)

        user = pick(ents, "account")
        if user:
            setattr(a, "user", user)
        ip = pick(ents, "ip")
        if ip:
            setattr(a, "source_ip", ip)

        src_h, tgt_h = infer_hosts(ents)
        if (not tgt_h) and getattr(a, "user", None):
            u = getattr(a, "user", None)
            for ed in edges:
                if ed.get("rel") == "accessed" and ed.get("from") == u:
                    tgt_h = ed.get("to")
                    break
        if (not src_h) and tgt_h:
            for ed in edges:
                if ed.get("rel") == "connected_to" and ed.get("to") == tgt_h:
                    src_h = ed.get("from")
                    break
        if src_h:
            setattr(a, "source_host", src_h)
        if tgt_h:
            setattr(a, "target_host", tgt_h)

    return alerts
