"""
╔══════════════════════════════════════════════════════════════════╗
║  ADFT — Générateur de Rapport JSON                               ║
║                                                                  ║
║  Produit un rapport JSON structuré pour :                        ║
║    • Intégration avec d'autres outils (SIEM, ticketing)         ║
║    • Traitement programmatique des résultats                     ║
║    • Archivage structuré des investigations                      ║
╚══════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, TYPE_CHECKING

from adft import RELEASE_LABEL, __version__

if TYPE_CHECKING:
    from adft.reporting.engine import InvestigationReport


class JSONReportGenerator:
    """
    Génère un rapport JSON structuré et sérialisable.
    """

    # ================================================================
    # Helpers sérialisation safe (datetime | str | None)
    # ================================================================
    @staticmethod
    def _safe_iso(ts) -> Any:
        """
        Retourne:
          - None si ts is None
          - ts (str) si déjà string
          - ts.isoformat() si datetime
          - str(ts) sinon
        """
        if ts is None:
            return None
        if isinstance(ts, str):
            return ts
        if isinstance(ts, datetime):
            return ts.isoformat()
        return str(ts)

    def generate(self, report: InvestigationReport, output_path: Path) -> None:
        data = self._serialize_report(report)
        output_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )

    def _serialize_report(self, report: InvestigationReport) -> Dict[str, Any]:
        return {
            "metadata": {
                "title": report.title,
                "analyst": report.analyst,
                "date": report.date or datetime.now().isoformat(),
                "generator": "ADFT Core — Active Directory Forensic Toolkit",
                "release": RELEASE_LABEL,
                "package_version": __version__,
                "total_events_processed": report.total_events_processed,
                "total_events_after_filter": report.total_events_after_filter,
                "log_sources": report.log_sources,
                "events_ref": getattr(report, "events_ref", None),
                "events_truncated": bool(getattr(report, "events_truncated", False)),
                "integrity": getattr(report, "integrity", {}),
            },
            # Events sample for debug/UI (full dataset is in metadata.events_ref JSONL)
            "events": getattr(report, "events", []) or [],
            "security_score": self._serialize_score(report),
            "alerts": self._serialize_alerts(report),
            "investigations": self._serialize_investigations(report),
            "timeline": self._serialize_timeline(report),
            "hardening": self._serialize_hardening(report),
            "attack_story": report.attack_story,
            "entity_graph": report.entity_graph,
            "case_explanation": getattr(report, "case_explanation", {}),
            "reconstruction": getattr(report, "reconstruction", {}) or {},
            "ransomware_analysis": getattr(report, "ransomware_analysis", {}),
            "multi_host": getattr(report, "multi_host", {}),
            "self_validation": getattr(report, "self_validation", None),
            "data_quality": getattr(report, "data_quality", {}),
            "integrity": getattr(report, "integrity", {}),
            "mitre_mapping": self._build_mitre_mapping(report),
        }

    def _serialize_score(self, report: InvestigationReport) -> Dict[str, Any]:
        if not report.security_score:
            return {"available": False}

        score = report.security_score
        return {
            "available": True,
            "global_score": getattr(score, "global_score", None),
            "risk_level": getattr(score, "risk_level", None),
            "total_findings": getattr(score, "total_findings", None),
            "summary": getattr(score, "summary", None),
            "evidence_confidence": getattr(score, "evidence_confidence", None),
            "confidence_label": getattr(score, "confidence_label", None),
            "observed_scope": getattr(score, "observed_scope", None),
            "severity_mix": getattr(score, "severity_mix", None),
            "score_drivers": getattr(score, "score_drivers", None),
            "calibration_version": getattr(score, "calibration_version", None),
            "calibration_method": getattr(score, "calibration_method", None),
            "decision_thresholds": getattr(score, "decision_thresholds", None),
            "calibration_notes": getattr(score, "calibration_notes", None),
            "categories": [
                {
                    "name": getattr(cat, "name", None),
                    "score": getattr(cat, "score", None),
                    "findings_count": getattr(cat, "findings_count", None),
                    "weight": getattr(cat, "weight", None),
                    "details": getattr(cat, "details", None),
                    "penalty_points": getattr(cat, "penalty_points", None),
                    "evidence_examples": getattr(cat, "evidence_examples", None),
                    "operational_impact": getattr(cat, "operational_impact", None),
                    "exposure_level": getattr(cat, "exposure_level", None),
                    "evidence_confidence": getattr(cat, "evidence_confidence", None),
                    "observed_scope": getattr(cat, "observed_scope", None),
                    "top_driver": getattr(cat, "top_driver", None),
                }
                for cat in getattr(score, "categories", []) or []
            ],
        }

    def _serialize_alerts(self, report: InvestigationReport) -> List[Dict[str, Any]]:
        return [
            {
                "rule_id": getattr(alert, "rule_id", None),
                "rule_name": getattr(alert, "rule_name", None),
                "severity": getattr(alert, "severity", None),
                "mitre_tactic": getattr(alert, "mitre_tactic", None),
                "mitre_technique": getattr(alert, "mitre_technique", None),
                "description": getattr(alert, "description", None),
                "timestamp": self._safe_iso(getattr(alert, "timestamp", None)),
                "user": getattr(alert, "user", None),
                "source_host": getattr(alert, "source_host", None),
                "target_host": getattr(alert, "target_host", None),
                "risk_score": getattr(alert, "risk_score", None),
                "risk_level": getattr(alert, "risk_level", None),
                "entities": getattr(alert, "entities", None),
                "event_count": len(getattr(alert, "events", []) or []),
            }
            for alert in (report.alerts or [])
        ]

    def _serialize_investigations(self, report: InvestigationReport) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for inv in (report.investigations or []):
            alerts = getattr(inv, "alerts", None) or getattr(inv, "detections", None) or []
            events = getattr(inv, "events", None) or []
            out.append(
                {
                    "id": getattr(inv, "id", None),
                    "title": getattr(inv, "title", None),
                    "identity": getattr(inv, "identity", None) or getattr(inv, "id", None),
                    "primary_entity": getattr(inv, "primary_entity", None),
                    "related_entities": getattr(inv, "related_entities", None),
                    "attack_phase": getattr(getattr(inv, "attack_phase", None), "value", getattr(inv, "attack_phase", None)),
                    "severity": getattr(getattr(inv, "severity", None), "value", getattr(inv, "severity", None)),
                    "start_time": self._safe_iso(getattr(inv, "start_time", None)),
                    "end_time": self._safe_iso(getattr(inv, "end_time", None)),
                    "risk_score": getattr(inv, "risk_score", 0.0),
                    "alert_count": len(alerts),
                    "event_count": len(events),
                    "summary": getattr(inv, "summary", None),
                    "alert_rule_ids": [getattr(a, "rule_id", None) for a in alerts],
                }
            )
        return out

    def _serialize_timeline(self, report: InvestigationReport) -> Dict[str, Any]:
        if not report.timeline:
            return {"available": False, "entries": []}

        tl = report.timeline
        return {
            "available": True,
            "start_time": self._safe_iso(getattr(tl, "start_time", None)),
            "end_time": self._safe_iso(getattr(tl, "end_time", None)),
            "summary": getattr(tl, "summary", None),
            "entries": [
                {
                    "timestamp": self._safe_iso(getattr(e, "timestamp", None)),
                    "phase": getattr(getattr(e, "phase", None), "value", getattr(e, "phase", None)),
                    "title": getattr(e, "title", None),
                    "description": getattr(e, "description", None),
                    "severity": getattr(getattr(e, "severity", None), "value", getattr(e, "severity", None)),
                    "entities": getattr(e, "entities", None),
                    "mitre_ids": getattr(e, "mitre_ids", None),
                    "detection_ids": getattr(e, "detection_ids", None),
                    "rule_id": getattr(e, "rule_id", None),
                }
                for e in (getattr(tl, "entries", None) or [])
            ],
        }

    def _serialize_hardening(self, report: InvestigationReport) -> Dict[str, Any]:
        if not report.hardening:
            return {"available": False, "findings": []}

        h = report.hardening
        findings = []
        for f in h.sorted_by_priority():
            findings.append(
                {
                    "finding_id": getattr(f, "finding_id", None),
                    "title": getattr(f, "title", None),
                    "category": getattr(f, "category", None),
                    "priority": getattr(f, "priority", None),
                    "risk_explanation": getattr(f, "risk_explanation", None),
                    "recommendation": getattr(f, "recommendation", None),
                    "impact": getattr(f, "impact", None),
                    "has_powershell_fix": getattr(f, "powershell_fix", None) is not None,
                    "powershell_fix": getattr(f, "powershell_fix", None),
                    "evidence": getattr(f, "evidence", None),
                    "prerequisites": getattr(f, "prerequisites", None),
                    "validation_steps": getattr(f, "validation_steps", None),
                    "rollback_steps": getattr(f, "rollback_steps", None),
                    "candidate_scope": getattr(f, "candidate_scope", None),
                    "confidence": getattr(f, "confidence", None),
                }
            )

        return {
            "available": True,
            "summary": getattr(h, "summary", ""),
            "total_issues": getattr(h, "total_issues", None),
            "critical_count": getattr(h, "critical_count", None),
            "script_coverage": getattr(h, "script_coverage", {}),
            "findings": findings,
        }

    @staticmethod
    def _build_mitre_mapping(report: InvestigationReport) -> List[Dict[str, Any]]:
        mapping: Dict[str, Dict[str, Any]] = {}

        for alert in (report.alerts or []):
            key = getattr(alert, "mitre_technique", None) or "unknown"
            if key not in mapping:
                mapping[key] = {
                    "technique": key,
                    "tactic": getattr(alert, "mitre_tactic", None),
                    "count": 0,
                    "rules": set(),
                }
            mapping[key]["count"] += 1
            rn = getattr(alert, "rule_name", None)
            if rn:
                mapping[key]["rules"].add(rn)
        # Merge MITRE techniques from structured case explanation (si disponibles)
        try:
            ai = getattr(report, "case_explanation", None) or {}
            ai_mitre = ai.get("mitre") if isinstance(ai, dict) else None
            if isinstance(ai_mitre, list):
                for item in ai_mitre:
                    if not isinstance(item, dict):
                        continue
                    tech = item.get("technique") or item.get("name") or item.get("technique_name")
                    mid = item.get("id") or item.get("mitre_id")
                    tactic = item.get("tactic") or item.get("mitre_tactic")
                    key = tech or mid or "unknown"
                    if key not in mapping:
                        mapping[key] = {
                            "technique": key,
                            "tactic": tactic,
                            "count": 0,
                            "rules": set(),
                        }
                    # count=0 pour distinguer "explanation-inferred" vs "rule-hit"
                    mapping[key]["rules"].add("EXPLANATION")
        except Exception:
            pass

        return [{**v, "rules": list(v["rules"])} for v in mapping.values()]