from __future__ import annotations

from typing import Any, Dict

from adft.explain import format_case_explanation
from adft.graph.attack_path import analyze_attack_paths


def _safe_get_str(d: dict[str, Any], *keys: str) -> str:
    for k in keys:
        v = d.get(k)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return ""


def render_summary_text(state: Dict[str, Any]) -> str:
    stats = state.get("stats", {}) or {}
    score = state.get("security_score", {}) or {}
    dq = state.get("data_quality", {}) or {}
    dq_summary = dq.get("summary", {}) or {}
    lines = [
        "ADFT Investigation Summary",
        "──────────────────────────",
        f"Events analyzed : {stats.get('raw_events', 0)}",
        f"Detections      : {stats.get('detections', 0)}",
        f"Alerts          : {stats.get('alerts', 0)}",
        f"Investigations  : {stats.get('investigations', 0)}",
        f"Timeline        : {stats.get('timeline_entries', 0)}",
        f"AD Score        : {score.get('global_score', score.get('score', 'N/A'))}",
        f"Risk level      : {score.get('risk_level', score.get('level', 'UNKNOWN'))}",
        f"Data warnings   : {dq_summary.get('warnings', 0)} | dropped={dq_summary.get('dropped_events', 0)} | rules_failed={dq_summary.get('rules_failed', 0)}",
        "",
    ]
    return "\n".join(lines)


def render_alerts_text(state: Dict[str, Any], full: bool = False) -> str:
    alerts = state.get("alerts", []) or []
    if not alerts:
        return "[ADFT] Aucune alerte disponible."
    lines = ["ADFT Alerts", "───────────"]
    for a in alerts:
        ts = _safe_get_str(a, "timestamp") or "N/A"
        lines.append(f"- {ts}")
        lines.append(f"  rule    : {_safe_get_str(a, 'rule_name', 'rule_id')}")
        lines.append(f"  tactic  : {_safe_get_str(a, 'mitre_tactic') or 'UNKNOWN'}")
        lines.append(f"  severity: {_safe_get_str(a, 'severity')} | risk: {a.get('risk_score', 'N/A')} ({_safe_get_str(a, 'risk_level')})")
        if full:
            lines.append(f"  desc    : {_safe_get_str(a, 'description')}")
            ents = a.get("entities") or []
            if isinstance(ents, list) and ents:
                lines.append(f"  entities: {', '.join(map(str, ents[:8]))}")
    lines.append("")
    return "\n".join(lines)


def render_score_text(state: Dict[str, Any]) -> str:
    score = state.get("security_score", {}) or {}
    if not score:
        return "[ADFT] Aucun score disponible."
    lines = [
        "ADFT AD Exposure Score",
        "──────────────────────",
        f"Score global : {score.get('global_score', 'N/A')}/100",
        f"Risque       : {score.get('risk_level', 'N/A')}",
        f"Confiance    : {score.get('evidence_confidence', 'N/A')}",
    ]
    scope = score.get('observed_scope')
    if scope:
        lines.append(f"Périmètre    : {scope}")
    if score.get('summary'):
        lines.append(f"Résumé       : {score.get('summary')}")
    lines.append("")
    lines.append("Catégories")
    for cat in score.get('categories', []) or []:
        lines.append(f"- {cat.get('name')}: {cat.get('score')}/100 | findings={cat.get('findings_count')} | pénalité={cat.get('penalty_points', 0)}")
        examples = cat.get('evidence_examples') or []
        for example in examples[:3]:
            lines.append(f"    · {example}")
        impact = cat.get('operational_impact')
        if impact:
            lines.append(f"    impact: {impact}")
    lines.append("")
    return "\n".join(lines)


def render_hardening_text(state: Dict[str, Any]) -> str:
    hard = state.get("hardening", {}) or {}
    findings = hard.get("findings", []) or []
    coverage = hard.get("script_coverage") or {}
    lines = ["ADFT Hardening", "──────────────", hard.get("summary") or "Aucun rapport de hardening disponible."]
    if coverage:
        lines.append(
            f"Couverture scripts : {coverage.get('with_script', 0)}/{len(findings)} ({coverage.get('coverage_percent', 0)}%)"
        )
    lines.append("")
    for finding in findings:
        lines.append(f"- {finding.get('finding_id')} | {finding.get('priority')} | {finding.get('title')}")
        evidence = finding.get('evidence') or []
        for item in evidence[:2]:
            lines.append(f"    preuve: {item}")
        validations = finding.get('validation_steps') or []
        if validations:
            lines.append(f"    validation: {validations[0]}")
    lines.append("")
    return "\n".join(lines)


def render_attack_chain_text(state: Dict[str, Any]) -> str:
    alerts = state.get("alerts", []) or []
    buckets: dict[str, list[str]] = {}
    for a in alerts:
        tactic = (_safe_get_str(a, "mitre_tactic") or "UNKNOWN").replace(" ", "_").upper()
        label = (_safe_get_str(a, "mitre_id") + " " + _safe_get_str(a, "mitre_technique")).strip() or _safe_get_str(a, "rule_name")
        if label:
            buckets.setdefault(tactic, []).append(label)
    lines = ["ADFT Attack Chain", "─────────────────"]
    for tactic, labels in buckets.items():
        lines.append("")
        lines.append(tactic)
        for label in sorted(set(labels)):
            lines.append(f"  → {label}")
    lines.append("")
    return "\n".join(lines)


def render_attack_path_text(state: Dict[str, Any]) -> str:
    graph = state.get("entity_graph", {}) or {}
    analysis = (graph.get("analysis") or {}) if isinstance(graph, dict) else {}
    paths = analysis.get("paths") or analyze_attack_paths(graph, max_depth=6, limit=12)
    if not paths:
        return "[ADFT] Aucun attack path détecté."
    lines = ["ADFT Attack Paths", "─────────────────"]
    surface = analysis.get("attack_surface")
    if surface:
        lines.append(f"Surface        : {surface}")
    if analysis.get("summary"):
        lines.append(f"Résumé         : {analysis.get('summary')}")
    for item in paths[:12]:
        if isinstance(item, list):
            lines.append("  " + " → ".join(item))
            continue
        lines.append(f"  [{item.get('risk_level', 'low')}] {item.get('summary')}")
        reasons = item.get('reasons') or []
        if reasons:
            lines.append("      ↳ " + ", ".join(reasons[:3]))
    lines.append("")
    return "\n".join(lines)


def render_story_text(state: Dict[str, Any], full: bool = False) -> str:
    attack_story = state.get("attack_story", []) or []
    timeline = (state.get("timeline") or {}).get("entries", []) or []
    lines = ["ADFT Incident Narrative", "────────────────────────"]
    if full and timeline:
        for e in timeline:
            lines.append(f"{e.get('timestamp', 'N/A')} [{e.get('phase', 'unknown')}] {e.get('description', '')}")
    else:
        for step in attack_story[:20]:
            lines.append(f"- {step}")
    lines.append("")
    return "\n".join(lines)


def render_reconstruct_text(state: Dict[str, Any], full: bool = False) -> str:
    reconstruction = state.get("reconstruction", {}) or {}
    if not reconstruction:
        return "[ADFT] Aucune reconstruction disponible."
    lines = ["ADFT Compromise Reconstruction", "────────────────────────────", reconstruction.get("summary") or "Résumé indisponible."]
    if reconstruction.get("patient_zero_account") or reconstruction.get("patient_zero_host"):
        lines.append(
            f"Pivot initial : {reconstruction.get('patient_zero_account') or 'N/A'} @ {reconstruction.get('patient_zero_host') or 'N/A'}"
        )
    if reconstruction.get("scope"):
        lines.append(f"Périmètre     : {reconstruction.get('scope')}")
    if reconstruction.get("confidence_label"):
        lines.append(f"Confiance     : {reconstruction.get('confidence')} ({reconstruction.get('confidence_label')})")
    if reconstruction.get("domain_controllers"):
        lines.append("Actifs AD      : " + ", ".join(reconstruction.get("domain_controllers")[:4]))
    if reconstruction.get("path_candidates"):
        lines.append("Chemins        :")
        for path in reconstruction.get("path_candidates")[:4]:
            lines.append(f"  → {path.get('summary')}")
    if full:
        lines.append("Observations   :")
        for item in reconstruction.get("key_observations", [])[:6]:
            lines.append(f"  - {item}")
    lines.append("")
    return "\n".join(lines)


def render_explain_text(state: Dict[str, Any], level: str = "analyst") -> str:
    explanation = state.get("case_explanation") or {}
    return format_case_explanation(explanation, level)
