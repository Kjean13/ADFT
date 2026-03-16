from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, List


def _top(items: Iterable[str], limit: int = 5) -> List[str]:
    c = Counter([str(x).strip() for x in items if str(x).strip()])
    return [name for name, _ in c.most_common(limit)]


def _get_score(security_score: Dict[str, Any]) -> tuple[str, str]:
    if not isinstance(security_score, dict):
        return ("N/A", "unknown")
    score = security_score.get("global_score")
    if score is None:
        score = security_score.get("score")
    level = security_score.get("risk_level") or security_score.get("level") or "unknown"
    return (str(score) if score is not None else "N/A", str(level))


def _summarize_evidence(alerts: List[Dict[str, Any]], investigations: List[Dict[str, Any]], timeline: Dict[str, Any]) -> Dict[str, Any]:
    tactics = _top([a.get("mitre_tactic") or "" for a in alerts], 6)
    techniques = _top([
        f"{(a.get('mitre_id') or '').strip()} {(a.get('mitre_technique') or '').strip()}".strip()
        for a in alerts
    ], 8)
    accounts = _top([
        a.get("user") or a.get("account") or i.get("primary_entity") or i.get("identity") or ""
        for a in alerts for i in [{}]
    ] + [
        i.get("primary_entity") or i.get("identity") or "" for i in investigations
    ], 6)
    hosts = _top([
        a.get("target_host") or a.get("host") or a.get("source_host") or "" for a in alerts
    ], 6)
    entries = list((timeline or {}).get("entries") or [])
    phases = _top([e.get("phase") or "" for e in entries], 8)
    return {
        "tactics": tactics,
        "techniques": techniques,
        "accounts": accounts,
        "hosts": hosts,
        "phases": phases,
        "timeline_entries": len(entries),
        "alerts": len(alerts),
        "investigations": len(investigations),
    }


def build_case_explanation(
    *,
    alerts: List[Dict[str, Any]] | None = None,
    investigations: List[Dict[str, Any]] | None = None,
    timeline: Dict[str, Any] | None = None,
    security_score: Dict[str, Any] | None = None,
    hardening: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    alerts = list(alerts or [])
    investigations = list(investigations or [])
    timeline = dict(timeline or {})
    security_score = dict(security_score or {})
    hardening = dict(hardening or {})

    evidence = _summarize_evidence(alerts, investigations, timeline)
    score, level = _get_score(security_score)
    critical_findings = int(hardening.get("critical_count") or 0)
    total_findings = int(hardening.get("total_issues") or 0)

    summary_parts = [
        f"{evidence['alerts']} alerte(s) corrélée(s) en {evidence['investigations']} investigation(s)",
        f"{evidence['timeline_entries']} entrée(s) de timeline",
        f"score AD observé {score} ({level})",
    ]
    if evidence["tactics"]:
        summary_parts.append("tactiques dominantes : " + ", ".join(evidence["tactics"][:3]))
    summary = "; ".join(summary_parts) + "."

    manager = (
        f"Les preuves observées indiquent une compromission ou tentative de compromission touchant "
        f"{', '.join(evidence['hosts'][:3]) if evidence['hosts'] else 'des actifs Windows/AD'}. "
        f"Le niveau de risque observé est {level} avec un score de {score}. "
        f"{critical_findings} mesure(s) de durcissement critique(s) et {total_findings} constat(s) au total requièrent une validation analyste."
    )

    ir = (
        f"La corrélation relie {evidence['alerts']} alertes à {evidence['investigations']} investigation(s). "
        f"Phases visibles : {', '.join(evidence['phases'][:4]) if evidence['phases'] else 'non déterminées'}. "
        f"Comptes saillants : {', '.join(evidence['accounts'][:4]) if evidence['accounts'] else 'non identifiés'}."
    )

    analyst = (
        f"Tactiques MITRE dominantes : {', '.join(evidence['tactics'][:5]) if evidence['tactics'] else 'aucune'}. "
        f"Techniques observées : {', '.join(evidence['techniques'][:5]) if evidence['techniques'] else 'aucune'}. "
        f"Hôtes clés : {', '.join(evidence['hosts'][:5]) if evidence['hosts'] else 'aucun'}.")

    pedagogic = (
        "ADFT a d'abord normalisé les traces Windows/AD, puis détecté des signaux, les a corrélés, "
        "a reconstruit une chronologie et a calculé un score d'exposition basé sur les preuves réellement observées."
    )

    next_steps: List[str] = []
    if critical_findings:
        next_steps.append("Traiter en priorité les constats de durcissement critiques en mode dry-run.")
    if evidence["hosts"]:
        next_steps.append("Valider les hôtes les plus exposés et confirmer leur rôle métier avant remédiation.")
    if evidence["accounts"]:
        next_steps.append("Contrôler les comptes sensibles observés dans la corrélation et vérifier leurs privilèges effectifs.")
    next_steps.append("Rejouer la timeline et confirmer les phases d'attaque avant toute action corrective large.")

    gaps: List[str] = []
    if not evidence["phases"]:
        gaps.append("La timeline n'a pas permis d'identifier clairement les phases d'attaque.")
    if not evidence["accounts"]:
        gaps.append("Aucun compte saillant n'a pu être extrait des traces corrélées.")
    if not total_findings:
        gaps.append("Aucun finding de durcissement n'a été généré à partir des preuves actuelles.")

    mitre = []
    for a in alerts:
        mid = (a.get("mitre_id") or "").strip()
        tech = (a.get("mitre_technique") or "").strip()
        tac = (a.get("mitre_tactic") or "").strip()
        if mid or tech:
            mitre.append({"id": mid, "technique": tech or mid, "tactic": tac})
    dedup = []
    seen = set()
    for item in mitre:
        key = (item.get("id"), item.get("technique"), item.get("tactic"))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(item)

    return {
        "summary": summary,
        "confidence": "deterministic",
        "levels": {
            "manager": manager,
            "ir": ir,
            "analyst": analyst,
            "pedagogic": pedagogic,
        },
        "operational_impact": manager,
        "evidence": evidence,
        "gaps": gaps,
        "next_steps": next_steps[:6],
        "mitre": dedup[:30],
    }


def format_case_explanation(explanation: Dict[str, Any], level: str = "analyst") -> str:
    level = (level or "analyst").lower()
    levels = explanation.get("levels") or {}
    text = levels.get(level) or levels.get("analyst") or explanation.get("summary") or "Aucune explication disponible."
    impact = explanation.get("operational_impact")
    steps = list(explanation.get("next_steps") or [])
    gaps = list(explanation.get("gaps") or [])

    lines = [text]
    if impact and impact != text:
        lines.append("")
        lines.append("Impact opérationnel :")
        lines.append(f"- {impact}")
    if steps:
        lines.append("")
        lines.append("Actions prioritaires :")
        lines.extend([f"- {s}" for s in steps[:5]])
    if gaps:
        lines.append("")
        lines.append("Limites observées :")
        lines.extend([f"- {g}" for g in gaps[:4]])
    return "\n".join(lines)
