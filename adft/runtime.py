from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any, Callable, Dict, List

from adft.analysis.ad_security_score import ADSecurityScoreCalculator
from adft.analysis.noise_filter import NoiseFilter
from adft.analysis.risk_scorer import RiskScorer
from adft.correlation.engine import CorrelationEngine
from adft.core.ingestion.canonical import CanonicalJsonlConverter
from adft.core.ingestion.loader import LogLoader
from adft.core.models.alerts import DetectionAlert
from adft.core.models.events import Detection
from adft.core.models.timeline import AttackTimeline
from adft.core.normalization.normalizer import EventNormalizer
from adft.detection.engine import DetectionEngine
from adft.exports import build_attack_navigator_layer, build_replay_payload
from adft.graph.entity_graph import build_entity_graph, enrich_alerts_with_entities
from adft.harden.advisor import RemediationAdvisor
from adft.investigation.pipeline import run_investigation_pipeline
from adft.reporting.engine import InvestigationReport, ReportingEngine
from adft.reporting.integrity import write_integrity_manifest
from adft.timeline.engine import TimelineEngine

LAST_RUN_FILE = ".adft_last_run.json"
ProgressCallback = Callable[[str, str], None]


def state_path(output_dir: str | Path) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    return out / LAST_RUN_FILE


def save_last_run(output_dir: str | Path, payload: dict[str, Any]) -> None:
    state_path(output_dir).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def load_last_run(output_dir: str | Path) -> dict[str, Any]:
    path = state_path(output_dir)
    if not path.exists():
        raise FileNotFoundError(
            f"Aucune investigation trouvée dans {path.parent}. Lance d'abord: adft investigate <logs> -o {path.parent}"
        )
    return json.loads(path.read_text(encoding="utf-8"))


def _serialize_report_obj(obj: Any) -> Any:
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    return obj


def _event_to_dict(e: Any) -> Dict[str, Any]:
    if hasattr(e, "to_dict"):
        try:
            return e.to_dict()  # type: ignore[attr-defined]
        except Exception:
            pass
    if hasattr(e, "__dict__"):
        return dict(e.__dict__)  # type: ignore[arg-type]
    if isinstance(e, dict):
        return e
    return {"value": str(e)}


def detection_to_alert(d: Detection) -> DetectionAlert:
    severity = getattr(d.severity, "value", str(d.severity))
    ts = d.timestamp.isoformat() if hasattr(d.timestamp, "isoformat") else str(d.timestamp)
    return DetectionAlert(
        id=d.id,
        rule_id=d.rule_id,
        rule_name=d.rule_name,
        description=d.description,
        severity=severity,
        mitre_tactic=d.mitre_tactic,
        mitre_technique=d.mitre_technique,
        mitre_id=d.mitre_id,
        timestamp=ts,
        entities=list(d.entities or []),
        confidence=float(d.confidence),
        events=[e.to_dict() if hasattr(e, "to_dict") else e for e in (d.events or [])],
    )


def serialize_hardening_report(report: Any) -> Dict[str, Any]:
    if report is None:
        return {}
    findings = []
    for f in getattr(report, "findings", []) or []:
        findings.append({
            "finding_id": getattr(f, "finding_id", None),
            "title": getattr(f, "title", None),
            "category": getattr(f, "category", None),
            "priority": getattr(f, "priority", None),
            "risk_explanation": getattr(f, "risk_explanation", None),
            "recommendation": getattr(f, "recommendation", None),
            "impact": getattr(f, "impact", None),
            "powershell_fix": getattr(f, "powershell_fix", None),
            "references": getattr(f, "references", None),
            "evidence": getattr(f, "evidence", None),
            "prerequisites": getattr(f, "prerequisites", None),
            "validation_steps": getattr(f, "validation_steps", None),
            "rollback_steps": getattr(f, "rollback_steps", None),
            "candidate_scope": getattr(f, "candidate_scope", None),
            "confidence": getattr(f, "confidence", None),
            "analyst_notes": getattr(f, "analyst_notes", None),
        })
    return {
        "summary": getattr(report, "summary", ""),
        "total_issues": getattr(report, "total_issues", len(findings)),
        "critical_count": getattr(report, "critical_count", 0),
        "script_coverage": getattr(report, "script_coverage", {}),
        "findings": findings,
    }


def run_investigation(
    logs: List[str | Path],
    output_dir: str | Path,
    formats: List[str] | None = None,
    export_events_jsonl: bool = False,
    no_filter: bool = False,
    progress: ProgressCallback | None = None,
) -> Dict[str, Any]:
    formats = [str(f).lower() for f in (formats or ["html", "json", "csv"])]
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    t_start = perf_counter()
    timings: Dict[str, float] = {}

    def mark(step: str) -> None:
        timings[step] = round(perf_counter() - t_start, 3)

    def announce(step: str, detail: str) -> None:
        if progress:
            progress(step, detail)

    loader = LogLoader()
    converter = CanonicalJsonlConverter(loader=LogLoader())
    canonical_dir = out_dir / "converted_inputs"
    announce("conversion", "Conversion des sources vers le format canonique JSONL")
    conversion = converter.convert_inputs(logs, canonical_dir)
    mark("conversion")

    if not (conversion.get("canonical_files") or []):
        summary = conversion.get("summary") or {}
        raise ValueError(
            "Aucune source exploitable n'a été convertie vers le format canonique JSONL. "
            f"Scannés={summary.get('files_scanned', 0)}, "
            f"convertis={summary.get('files_converted', 0)}, "
            f"échoués={summary.get('files_failed', 0)}, "
            f"vides={summary.get('files_empty', 0)}."
        )

    raw_events: List[Dict[str, Any]] = []
    announce("ingestion", "Lecture des traces canoniques JSONL")
    for p in conversion.get("canonical_files", []) or []:
        raw_events.extend(loader.load(str(p)))
    mark("ingestion")

    normalizer = EventNormalizer()
    announce("normalization", "Normalisation des événements")
    norm_events = normalizer.normalize_all(raw_events)
    mark("normalization")

    det_engine = DetectionEngine()
    announce("detection", "Détection des signaux d'attaque")
    detections = det_engine.run(norm_events)
    mark("detection")

    events_ref_path = ""
    if export_events_jsonl:
        announce("events_export", "Export des événements normalisés")
        events_ref_path = str((out_dir / "adft_events.jsonl").resolve())
        with open(events_ref_path, "w", encoding="utf-8") as fh:
            for ev in norm_events:
                fh.write(json.dumps(_event_to_dict(ev), ensure_ascii=False, default=str) + "\n")

    corr_engine = CorrelationEngine()
    announce("correlation", "Corrélation des signaux")
    investigations = corr_engine.correlate(detections)
    mark("correlation")

    tl_engine = TimelineEngine()
    announce("timeline", "Reconstruction de la timeline")
    timeline_entries = tl_engine.build(investigations, detections)
    timeline = AttackTimeline(entries=timeline_entries)
    mark("timeline")

    alerts: List[DetectionAlert] = [detection_to_alert(d) for d in detections]

    if not no_filter:
        announce("noise_filter", "Filtrage du bruit")
        alerts = NoiseFilter().filter_alerts(alerts)
        mark("noise_filter")

    sample_limit = 2000
    events_dump = [_event_to_dict(ev) for ev in norm_events[:sample_limit]]
    events_truncated = len(norm_events) > sample_limit

    announce("entity_graph", "Construction du graphe d'entités")
    graph = build_entity_graph(events_dump)
    alerts = enrich_alerts_with_entities(alerts, graph)
    mark("entity_graph")

    announce("risk_scoring", "Scoring des alertes et investigations")
    rs = RiskScorer()
    for a in alerts:
        a.risk_score = round(rs.score_alert(a), 1)
        a.risk_level = rs.risk_level_from_score(a.risk_score)
    investigations = rs.score_all_investigations(investigations)
    mark("risk_scoring")

    announce("ad_score", "Calcul du score d'exposition AD")
    ad_score = ADSecurityScoreCalculator().calculate(alerts, investigations)
    mark("ad_score")

    announce("hardening", "Génération du hardening guidé par preuves")
    hard_report = RemediationAdvisor().advise(alerts, investigations)
    mark("hardening")

    announce("case_explanation", "Production de l'explication de cas")
    pipeline_out = run_investigation_pipeline(
        events=events_dump,
        detections=detections,
        timeline=timeline,
        alerts=[a.to_dict() for a in alerts],
        investigations=[_serialize_report_obj(i) for i in investigations],
        security_score=_serialize_report_obj(ad_score),
        hardening=serialize_hardening_report(hard_report),
        enable_ai=False,
    )
    mark("case_explanation")

    data_quality = {
        "schema_version": EventNormalizer.SCHEMA_VERSION,
        "conversion": conversion,
        "ingestion": loader.quality_report,
        "normalization": normalizer.quality_report,
        "detection": det_engine.quality_report,
        "correlation": corr_engine.quality_report,
        "summary": {
            "warnings": sum(len((module.get("issues") or [])) for module in [converter.quality_report, loader.quality_report, normalizer.quality_report, det_engine.quality_report, corr_engine.quality_report]),
            "dropped_events": normalizer.stats.get("dropped", 0),
            "files_failed": loader.stats.get("files_failed", 0),
            "rules_failed": det_engine.stats.get("rules_failed", 0),
        },
    }

    announce("reporting", "Génération des rapports")
    report_engine = ReportingEngine(output_dir=str(out_dir))
    report_date = datetime.now(UTC).isoformat()
    log_sources = [str(p) for p in logs]
    report = InvestigationReport(
        date=report_date,
        events=events_dump,
        events_ref=events_ref_path or None,
        events_truncated=events_truncated,
        alerts=alerts,
        investigations=investigations,
        timeline=timeline,
        security_score=ad_score,
        hardening=hard_report,
        attack_story=pipeline_out.get("attack_story", []),
        entity_graph=pipeline_out.get("graph", {}) or graph,
        case_explanation=pipeline_out.get("case_explanation", {}),
        reconstruction=pipeline_out.get("reconstruction", {}),
        data_quality=data_quality,
        integrity={"algorithm": "sha256", "manifest": "adft_integrity.json"},
        total_events_processed=len(raw_events),
        total_events_after_filter=len(norm_events),
        log_sources=log_sources,
    )
    generated = report_engine.generate(report, formats=formats)
    mark("reporting")

    announce("exports", "Création des exports complémentaires")
    navigator_layer = build_attack_navigator_layer([a.to_dict() for a in alerts])
    navigator_path = out_dir / "attack_navigator_layer.json"
    navigator_path.write_text(json.dumps(navigator_layer, ensure_ascii=False, indent=2), encoding="utf-8")

    replay_payload = build_replay_payload(
        alerts=[a.to_dict() for a in alerts],
        timeline=timeline.to_dict(),
        investigations=[_serialize_report_obj(i) for i in investigations],
        entity_graph=report.entity_graph,
        reconstruction=pipeline_out.get("reconstruction", {}),
    )
    replay_path = out_dir / "adft_replay.json"
    replay_path.write_text(json.dumps(replay_payload, ensure_ascii=False, indent=2), encoding="utf-8")

    mermaid_path = out_dir / "attack_graph.mmd"
    mermaid_path.write_text((report.entity_graph or {}).get("mermaid", graph.get("mermaid", "")), encoding="utf-8")
    mark("exports")

    payload = {
        "date": report_date,
        "metadata": {
            "title": report.title,
            "analyst": report.analyst,
            "date": report_date,
            "total_events_processed": len(raw_events),
            "total_events_after_filter": len(norm_events),
            "log_sources": log_sources,
            "canonical_sources": conversion.get("canonical_files", []),
        },
        "output_dir": str(out_dir.resolve()),
        "formats": formats,
        "conversion": conversion,
        "stats": {
            "raw_events": len(raw_events),
            "timings_sec": timings,
            "normalized_events": len(norm_events),
            "detections": len(detections),
            "alerts": len(alerts),
            "investigations": len(investigations),
            "timeline_entries": len(timeline_entries),
        },
        "events": events_dump,
        "events_ref": events_ref_path or None,
        "events_truncated": events_truncated,
        "alerts": [a.to_dict() for a in alerts],
        "investigations": [_serialize_report_obj(i) for i in investigations],
        "timeline": timeline.to_dict(),
        "timeline_entries": [_serialize_report_obj(t) for t in timeline_entries],
        "security_score": _serialize_report_obj(ad_score),
        "hardening": serialize_hardening_report(hard_report),
        "attack_story": pipeline_out.get("attack_story", []),
        "entity_graph": report.entity_graph,
        "case_explanation": pipeline_out.get("case_explanation", {}),
        "reconstruction": pipeline_out.get("reconstruction", {}),
        "data_quality": data_quality,
        "integrity": {"algorithm": "sha256", "manifest": "adft_integrity.json"},
        "exports": {
            "navigator": str(navigator_path.resolve()),
            "replay": str(replay_path.resolve()),
            "graph_mermaid": str(mermaid_path.resolve()),
        },
    }
    save_last_run(out_dir, payload)
    integrity_path = write_integrity_manifest(out_dir, [
        "adft_report.html",
        "adft_report.json",
        "adft_report.csv",
        "attack_graph.mmd",
        "adft_replay.json",
        "attack_navigator_layer.json",
        state_path(out_dir),
    ])
    payload["integrity"] = {"algorithm": "sha256", "manifest": str(integrity_path.resolve())}
    save_last_run(out_dir, payload)

    generated_paths = [str(p) for p in generated]
    return {
        "payload": payload,
        "generated": generated_paths,
        "state_path": str(state_path(out_dir)),
        "integrity_path": str(integrity_path),
        "navigator_path": str(navigator_path),
        "replay_path": str(replay_path),
        "mermaid_path": str(mermaid_path),
    }
