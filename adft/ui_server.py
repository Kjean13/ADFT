from __future__ import annotations

import json
import mimetypes
import os
import posixpath
import shutil
import tempfile
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.parser import BytesParser
from email.policy import default as email_default_policy
from functools import partial
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlparse

from adft import RELEASE_LABEL, __version__
from adft.core.ingestion.canonical import CanonicalJsonlConverter
from adft.runtime import LAST_RUN_FILE, load_last_run, run_investigation


SUPPORTED_INPUTS = [
    ".json", ".jsonl", ".ndjson", ".evtx", ".yaml", ".yml", ".csv", ".tsv",
    ".cef", ".leef", ".xml", ".log", ".syslog", ".txt", ".md", ".markdown", ".zip",
]


def _json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _slug(name: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in name)
    return safe or "file"


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def _severity_from_french(value: str | None) -> str:
    mapping = {
        None: "info",
        "critique": "critical",
        "haute": "high",
        "élevée": "high",
        "elevee": "high",
        "modéré": "medium",
        "moderee": "medium",
        "modérée": "medium",
        "faible": "low",
        "info": "info",
    }
    return mapping.get((value or "").strip().lower(), (value or "info").strip().lower() or "info")


def _infer_entity_type(value: str | None) -> str:
    if not value:
        return "ad_object"
    v = value.strip()
    if not v:
        return "ad_object"
    if all(part.isdigit() and 0 <= int(part) <= 255 for part in v.split(".") if part) and v.count(".") == 3:
        return "ip"
    if v.endswith("$") or "." in v:
        return "host"
    return "user"


def _risk_label(score: float) -> str:
    if score <= 25:
        return "critical"
    if score <= 50:
        return "high"
    if score <= 75:
        return "medium"
    return "low"


@dataclass
class Job:
    id: str
    kind: str
    status: str = "queued"
    stage: str = "queued"
    progress_pct: int = 0
    message: str = "Waiting"
    started_at: float | None = None
    finished_at: float | None = None
    errors: list[str] = field(default_factory=list)
    result: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.id,
            "kind": self.kind,
            "status": self.status,
            "stage": self.stage,
            "progress_pct": self.progress_pct,
            "message": self.message,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "errors": self.errors,
            "result": self.result,
        }


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def create(self, kind: str) -> Job:
        job = Job(id=f"job_{uuid.uuid4().hex[:12]}", kind=kind)
        with self._lock:
            self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def update(self, job_id: str, **kwargs: Any) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            for key, value in kwargs.items():
                setattr(job, key, value)


class AppState:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = _ensure_dir(output_dir)
        self.upload_root = _ensure_dir(self.output_dir / ".ui_uploads")
        self.jobs = JobStore()
        self.lock = threading.Lock()
        self.raw_state: dict[str, Any] | None = None
        self.adapted_run: dict[str, Any] | None = None
        self.artifacts: list[dict[str, Any]] = []
        self.conversion_manifest: dict[str, Any] | None = None
        self.last_error: str | None = None
        self.refresh_from_disk()

    def refresh_from_disk(self) -> None:
        with self.lock:
            state_path = self.output_dir / LAST_RUN_FILE
            self.raw_state = _load_json(state_path) if state_path.exists() else None
            manifest_path = self.output_dir / "converted_inputs" / "conversion_manifest.json"
            self.conversion_manifest = _load_json(manifest_path) if manifest_path.exists() else None
            self.artifacts = self._collect_artifacts()
            self.adapted_run = adapt_state_to_ui(self.raw_state, self.artifacts) if self.raw_state else empty_ui_run()

    def _collect_artifacts(self) -> list[dict[str, Any]]:
        artifacts: list[dict[str, Any]] = []
        candidates: list[tuple[str, Path, str]] = [
            ("adft_report.html", self.output_dir / "adft_report.html", "HTML report"),
            ("adft_report.json", self.output_dir / "adft_report.json", "JSON report"),
            ("adft_report.csv", self.output_dir / "adft_report.csv", "CSV report"),
            ("attack_graph.mmd", self.output_dir / "attack_graph.mmd", "Mermaid graph"),
            ("attack_navigator_layer.json", self.output_dir / "attack_navigator_layer.json", "ATT&CK Navigator layer"),
            ("adft_replay.json", self.output_dir / "adft_replay.json", "Replay payload"),
            ("adft_integrity.json", self.output_dir / "adft_integrity.json", "Integrity manifest"),
            (".adft_last_run.json", self.output_dir / LAST_RUN_FILE, "Run state"),
            ("adft_events.jsonl", self.output_dir / "adft_events.jsonl", "Normalized events JSONL"),
            ("conversion_manifest.json", self.output_dir / "converted_inputs" / "conversion_manifest.json", "Conversion manifest"),
            ("hardening_scripts.zip", self.output_dir / "hardening_scripts.zip", "Hardening scripts archive"),
        ]
        for name, path, label in candidates:
            if path.exists():
                artifacts.append({
                    "name": name,
                    "label": label,
                    "size_bytes": path.stat().st_size,
                    "created_at": path.stat().st_mtime,
                    "download_url": f"/api/artifacts/{name}",
                    "preview_url": f"/api/artifacts/{name}" if path.suffix in {'.html', '.json', '.csv', '.mmd'} else None,
                })
        return artifacts


def empty_ui_run() -> dict[str, Any]:
    return {
        "id": "",
        "timestamp": "",
        "sources": [],
        "normalizedEvents": [],
        "alerts": [],
        "investigations": [],
        "timeline": [],
        "entityGraph": {"nodes": [], "edges": []},
        "riskScore": {"global": 0, "adScore": 0, "breakdown": [], "summary": "", "riskLevel": ""},
        "hardeningRecommendations": [],
        "reconstruction": {
            "story": "",
            "attackChain": [],
            "attackPath": [],
            "patientZero": {"entity": "", "confidence": 0, "evidence": ""},
            "estimatedImpacts": [],
        },
        "status": "idle",
        "progress": [],
        "artifacts": [],
    }


def _ui_entity_type(raw_type: str | None) -> str:
    return {
        "account": "user",
        "host": "host",
        "ip": "ip",
        "service": "service",
        "process": "process",
        "domain_controller": "ad_object",
    }.get((raw_type or "ad_object").strip().lower(), "ad_object")


RELATION_LABELS = {
    "logged_on_as": "s’est authentifié comme",
    "accessed": "a accédé à",
    "connected_to": "a contacté",
    "seen_on": "vu sur",
    "executed": "a exécuté",
    "hosts_service": "héberge",
    "related": "lié à",
}


SEVERITY_WEIGHT = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _canonical_edge(source: str | None, relation: str | None, target: str | None) -> tuple[str, str, str] | None:
    src = str(source or "").strip()
    tgt = str(target or "").strip()
    rel = str(relation or "related").strip() or "related"
    if not src or not tgt or src == tgt:
        return None
    return src, rel, tgt


def _event_timestamp(value: Any) -> str:
    return str(value or "").strip()


def _event_has_known_ioc(event: dict[str, Any]) -> bool:
    keys = (
        "ioc", "iocs", "ioc_match", "ioc_matches", "indicator", "indicator_match", "indicator_matches",
    )
    for key in keys:
        value = event.get(key)
        if value not in (None, "", [], {}):
            return True
    raw = event.get("raw_event")
    if isinstance(raw, dict):
        for key in keys:
            value = raw.get(key)
            if value not in (None, "", [], {}):
                return True
    return False


def _register_seen(bounds: dict[str, str | None], timestamp: str) -> None:
    if not timestamp:
        return
    if not bounds.get("firstSeen") or timestamp < str(bounds["firstSeen"]):
        bounds["firstSeen"] = timestamp
    if not bounds.get("lastSeen") or timestamp > str(bounds["lastSeen"]):
        bounds["lastSeen"] = timestamp


def _build_ui_graph(state: dict[str, Any], alerts: list[dict[str, Any]]) -> dict[str, Any]:
    raw_graph = state.get("entity_graph") or {}
    events = state.get("events") or []

    node_records: dict[str, dict[str, Any]] = {}
    value_to_node_ids: dict[str, list[str]] = {}
    edge_records: dict[tuple[str, str, str], dict[str, Any]] = {}

    def node_id(node_type: str, label: str) -> str:
        return f"{node_type}:{label}"

    def ensure_node(label: str, node_type: str, **extra: Any) -> dict[str, Any]:
        clean_label = str(label or "").strip()
        clean_type = _ui_entity_type(node_type)
        if not clean_label:
            clean_label = "unknown"
        nid = node_id(clean_type, clean_label)
        record = node_records.get(nid)
        if not record:
            record = {
                "id": nid,
                "type": clean_type,
                "label": clean_label,
                "risk": 25,
                "alertCount": 0,
                "isCritical": False,
                "firstSeen": None,
                "lastSeen": None,
                "isKnownIoc": False,
                "degree": 0,
                "role": "entity",
                "clusterSize": 0,
            }
            node_records[nid] = record
            value_to_node_ids.setdefault(clean_label, []).append(nid)
        for key, value in extra.items():
            if value is None:
                continue
            if key in {"firstSeen", "lastSeen"}:
                current = record.get(key)
                if not current:
                    record[key] = value
                elif key == "firstSeen" and str(value) < str(current):
                    record[key] = value
                elif key == "lastSeen" and str(value) > str(current):
                    record[key] = value
            elif key == "clusterSize":
                record[key] = max(int(record.get(key) or 0), int(value or 0))
            elif key == "alertCount":
                record[key] = int(record.get(key) or 0) + int(value or 0)
            elif key == "isCritical":
                record[key] = bool(record.get(key)) or bool(value)
            elif key == "isKnownIoc":
                record[key] = bool(record.get(key)) or bool(value)
            else:
                record[key] = value
        return record

    def infer_node_from_value(value: str) -> dict[str, Any]:
        ids = value_to_node_ids.get(value) or []
        if ids:
            return node_records[ids[0]]
        return ensure_node(value, _infer_entity_type(value))

    def register_edge(source: str | None, relation: str | None, target: str | None, timestamp: str = "", weight: int = 1) -> None:
        canonical = _canonical_edge(source, relation, target)
        if not canonical:
            return
        src_label, raw_rel, tgt_label = canonical
        src_node = infer_node_from_value(src_label)
        tgt_node = infer_node_from_value(tgt_label)
        edge_key = (src_node["id"], raw_rel, tgt_node["id"])
        record = edge_records.get(edge_key)
        if not record:
            record = {
                "source": src_node["id"],
                "target": tgt_node["id"],
                "label": RELATION_LABELS.get(raw_rel, raw_rel.replace("_", " ")),
                "relation": raw_rel,
                "weight": 0,
                "firstSeen": None,
                "lastSeen": None,
            }
            edge_records[edge_key] = record
        record["weight"] = int(record.get("weight") or 0) + max(1, int(weight or 1))
        _register_seen(record, timestamp)

    for node in raw_graph.get("nodes") or []:
        raw_type = str(node.get("type") or "ad_object")
        mapped_type = _ui_entity_type(raw_type)
        value = str(node.get("value") or node.get("label") or "unknown")
        ensure_node(
            value,
            mapped_type,
            role=node.get("role") or "entity",
            clusterSize=int(node.get("count") or 0),
            degree=int(node.get("degree") or 0),
            isCritical=(node.get("criticality") or "").lower() in {"high", "critical"} or bool(node.get("is_critical")),
            risk={"low": 20, "medium": 45, "high": 70, "critical": 90}.get((node.get("criticality") or "low").lower(), 25),
        )

    for event in events:
        timestamp = _event_timestamp(event.get("timestamp"))
        user = str(event.get("user") or "").strip()
        src_host = str(event.get("source_host") or "").strip()
        tgt_host = str(event.get("target_host") or "").strip()
        ip_addr = str(event.get("ip_address") or event.get("source_ip") or "").strip()
        process_name = str(event.get("process_name") or event.get("process") or "").strip()
        service_name = str(event.get("service_name") or "").strip()
        has_ioc = _event_has_known_ioc(event)

        candidates = [
            ("user", user),
            ("host", src_host),
            ("host", tgt_host),
            ("ip", ip_addr),
            ("process", process_name),
            ("service", service_name),
        ]
        for entity_type, value in candidates:
            if not value:
                continue
            record = ensure_node(value, entity_type, isKnownIoc=has_ioc)
            _register_seen(record, timestamp)

        register_edge(ip_addr, "seen_on", src_host, timestamp)
        register_edge(src_host, "logged_on_as", user, timestamp)
        register_edge(user, "accessed", tgt_host, timestamp)
        register_edge(src_host, "connected_to", tgt_host, timestamp)
        register_edge(src_host, "executed", process_name, timestamp)
        register_edge(tgt_host or src_host, "hosts_service", service_name, timestamp)

    for edge in raw_graph.get("edges") or []:
        source = edge.get("source", edge.get("from"))
        target = edge.get("target", edge.get("to"))
        relation = edge.get("label", edge.get("rel"))
        weight = int(edge.get("weight", edge.get("count", 1)) or 1)
        register_edge(str(source or ""), str(relation or "related"), str(target or ""), "", weight)

    for alert in alerts:
        severity = str(alert.get("severity") or "info")
        weight = SEVERITY_WEIGHT.get(severity, 0)
        entities = [
            ("user", alert.get("user") or ""),
            ("host", alert.get("host") or ""),
            ("ip", alert.get("ip") or ""),
        ]
        rule_text = f"{alert.get('ruleName', '')} {alert.get('description', '')}".lower()
        is_known_ioc = "ioc" in rule_text or "indicator" in rule_text
        for entity_type, value in entities:
            clean = str(value or "").strip()
            if not clean or clean == "N/A" or clean == "-":
                continue
            record = ensure_node(clean, entity_type, alertCount=1, isKnownIoc=is_known_ioc)
            record["risk"] = min(100, int(record.get("risk") or 0) + (weight * 6))
            if severity in {"critical", "high"}:
                record["isCritical"] = True

    for edge in edge_records.values():
        node_records[edge["source"]]["degree"] = int(node_records[edge["source"]].get("degree") or 0) + 1
        node_records[edge["target"]]["degree"] = int(node_records[edge["target"]].get("degree") or 0) + 1

    for record in node_records.values():
        degree_bonus = min(18, int(record.get("degree") or 0) * 2)
        alert_bonus = min(18, int(record.get("alertCount") or 0) * 5)
        ioc_bonus = 12 if record.get("isKnownIoc") else 0
        critical_bonus = 10 if record.get("isCritical") else 0
        base = int(record.get("risk") or 25)
        record["risk"] = min(100, base + degree_bonus + alert_bonus + ioc_bonus + critical_bonus)

    nodes = sorted(node_records.values(), key=lambda item: (-int(item.get("risk") or 0), -int(item.get("alertCount") or 0), str(item.get("label") or "").lower()))
    edges = sorted(edge_records.values(), key=lambda item: (-int(item.get("weight") or 0), str(item.get("label") or "")))

    all_ts = [str(x) for x in [*(n.get("firstSeen") for n in nodes), *(n.get("lastSeen") for n in nodes), *(e.get("firstSeen") for e in edges), *(e.get("lastSeen") for e in edges)] if x]
    timeframe = {
        "start": min(all_ts) if all_ts else "",
        "end": max(all_ts) if all_ts else "",
    }
    summary = raw_graph.get("summary") or {}
    analysis = raw_graph.get("analysis") or {}
    return {
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "nodes": len(nodes),
            "edges": len(edges),
            "accounts": int(summary.get("accounts") or 0),
            "hosts": int(summary.get("hosts") or 0),
            "ips": int(summary.get("ips") or 0),
            "domainControllers": int(summary.get("domain_controllers") or 0),
            "privilegedAccounts": int(summary.get("privileged_accounts") or 0),
            "hotNodes": len(analysis.get("hot_nodes") or []),
        },
        "analysis": analysis,
        "mermaid": raw_graph.get("mermaid") or "",
        "timeframe": timeframe,
    }


def adapt_state_to_ui(state: dict[str, Any] | None, artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    if not state:
        run = empty_ui_run()
        run["artifacts"] = artifacts
        return run

    security = state.get("security_score") or {}
    hardening = state.get("hardening") or {}
    reconstruction = state.get("reconstruction") or {}
    case_expl = state.get("case_explanation") or {}
    timeline_entries = state.get("timeline_entries") or []

    alerts = []
    for alert in state.get("alerts") or []:
        alerts.append({
            "id": alert.get("id") or alert.get("rule_id") or uuid.uuid4().hex[:8],
            "ruleId": alert.get("rule_id") or "",
            "ruleName": alert.get("rule_name") or "",
            "severity": _severity_from_french(alert.get("severity")),
            "mitreTactic": alert.get("mitre_tactic") or "",
            "mitreId": alert.get("mitre_id") or "",
            "timestamp": alert.get("timestamp") or "",
            "host": alert.get("source_host") or alert.get("target_host") or "N/A",
            "user": alert.get("user") or "N/A",
            "ip": alert.get("source_ip") or alert.get("ip_address") or "N/A",
            "description": alert.get("description") or "",
            "eventId": alert.get("id") or alert.get("rule_id") or "",
            "investigationId": None,
            "event": {
                "id": alert.get("id") or "",
                "timestamp": alert.get("timestamp") or "",
                "eventId": 0,
                "source": alert.get("source_host") or "",
                "channel": "",
                "computer": alert.get("source_host") or "",
                "user": alert.get("user") or "",
                "ip": alert.get("source_ip") or alert.get("ip_address") or "",
                "process": alert.get("process_name") or "",
                "message": alert.get("description") or "",
                "raw": alert,
            },
        })

    inv_map: dict[str, str] = {}
    investigations = []
    for inv in state.get("investigations") or []:
        entity_refs = []
        primary = inv.get("primary_entity")
        if primary:
            entity_refs.append({"type": _infer_entity_type(primary), "value": primary})
        for ent in inv.get("related_entities") or []:
            entity_refs.append({"type": _infer_entity_type(ent), "value": ent})
        det_ids = inv.get("detection_ids") or []
        for a in alerts:
            if a["id"] in det_ids:
                a["investigationId"] = inv.get("id")
                inv_map[a["id"]] = inv.get("id")
        investigations.append({
            "id": inv.get("id") or uuid.uuid4().hex[:8],
            "title": inv.get("title") or "Investigation",
            "severity": _severity_from_french(inv.get("severity")),
            "score": round(float(inv.get("risk_score") or 0)),
            "hypothesis": inv.get("attack_phase") or "investigation",
            "analystSummary": inv.get("summary") or case_expl.get("analyst") or "",
            "managerSummary": case_expl.get("manager") or inv.get("summary") or "",
            "entities": entity_refs,
            "alerts": det_ids,
            "createdAt": inv.get("start_time") or state.get("date") or "",
        })

    timeline = []
    for idx, entry in enumerate(timeline_entries):
        entities = []
        ent = entry.get("entities") or {}
        if isinstance(ent, dict):
            for k, values in ent.items():
                if isinstance(values, list):
                    for value in values:
                        entities.append({"type": _infer_entity_type(value), "value": str(value)})
        timeline.append({
            "id": f"timeline_{idx}",
            "timestamp": entry.get("timestamp") or "",
            "type": "alert",
            "severity": _severity_from_french(entry.get("severity")),
            "title": entry.get("title") or "",
            "description": entry.get("description") or "",
            "entities": entities,
            "sourceId": entry.get("rule_id") or "",
        })

    enriched_graph = _build_ui_graph(state, alerts)

    findings = []
    for finding in hardening.get("findings") or []:
        confidence = (finding.get("confidence") or "medium").lower()
        difficulty = {"low": "easy", "medium": "medium", "high": "hard"}.get(confidence, "medium")
        findings.append({
            "id": finding.get("finding_id") or uuid.uuid4().hex[:8],
            "title": finding.get("title") or "Hardening finding",
            "description": finding.get("recommendation") or finding.get("risk_explanation") or "",
            "priority": _severity_from_french(finding.get("priority")),
            "difficulty": difficulty,
            "expectedImpact": finding.get("impact") or "",
            "evidence": finding.get("evidence") or [],
            "category": finding.get("category") or "general",
        })

    attack_story = reconstruction.get("attack_story") or state.get("attack_story") or []
    narrative_steps = reconstruction.get("narrative_steps") or []
    chain = []
    for idx, step in enumerate(narrative_steps, start=1):
        mitre = ", ".join(step.get("mitre_ids") or []) if isinstance(step.get("mitre_ids"), list) else ""
        chain.append({
            "step": int(step.get("step") or idx),
            "phase": step.get("phase") or "phase",
            "description": step.get("description") or step.get("title") or "",
            "mitre": mitre,
            "timestamp": step.get("timestamp") or "",
        })
    path = []
    for candidate in reconstruction.get("path_candidates") or []:
        if isinstance(candidate, dict):
            if candidate.get("nodes"):
                path = [str(x) for x in candidate.get("nodes")]
                break
            if candidate.get("path"):
                path = [str(x) for x in candidate.get("path")]
                break
    if not path:
        pz = reconstruction.get("patient_zero_account") or reconstruction.get("patient_zero_host")
        if pz:
            path.append(str(pz))
        for inv in investigations[:2]:
            if inv["title"] not in path:
                path.append(inv["title"])

    impacts = []
    if any(a["severity"] == "critical" for a in alerts):
        impacts.append({"area": "Administrative control", "severity": "critical", "description": "Critical findings may indicate rapid privilege expansion or domain-level impact."})
    if alerts:
        impacts.append({"area": "Identity exposure", "severity": "medium", "description": f"{len(alerts)} alert(s) and {len(investigations)} investigation(s) were correlated from observed evidence."})
    if enriched_graph.get("nodes"):
        impacts.append({"area": "Asset exposure", "severity": "low", "description": f"{len(enriched_graph['nodes'])} graph node(s) were mapped from the investigated dataset."})

    story = "\n\n".join([str(x) for x in attack_story if x])
    if not story:
        story = reconstruction.get("summary") or case_expl.get("analyst") or ""

    global_score = float(security.get("global_score") or 0)
    conversion_summary = ((state.get("conversion") or {}).get("summary") or {})
    payload_stats = state.get("stats") or {}
    event_dates = sorted(
        [datetime.fromisoformat(str(ev.get("timestamp")).replace("Z", "+00:00")) for ev in state.get("events") or [] if ev.get("timestamp")],
        key=lambda item: item.timestamp(),
    )
    incident_start = event_dates[0] if event_dates else None
    incident_end = event_dates[-1] if event_dates else None
    incident_span_seconds = max(1, int((incident_end - incident_start).total_seconds())) if incident_start and incident_end else 0
    timings = payload_stats.get("timings_sec") or {}
    runtime_seconds = 0.0
    if isinstance(timings, dict) and timings:
        try:
            runtime_seconds = float(max(float(value) for value in timings.values() if value is not None))
        except Exception:
            runtime_seconds = 0.0
    raw_events_count = int(payload_stats.get("raw_events") or len(state.get("events") or []))
    processing_eps = (raw_events_count / runtime_seconds) if runtime_seconds > 0 else 0.0
    processing_epm = processing_eps * 60.0 if processing_eps > 0 else 0.0
    incident_epm = ((raw_events_count / incident_span_seconds) * 60.0) if incident_span_seconds > 0 else 0.0

    benchmark = {
        "release": RELEASE_LABEL,
        "packageVersion": __version__,
        "supportedInputs": SUPPORTED_INPUTS,
        "evtxAvailable": _evtx_available(),
        "conversion": {
            "filesScanned": int(conversion_summary.get("files_scanned") or 0),
            "filesConverted": int(conversion_summary.get("files_converted") or 0),
            "filesFailed": int(conversion_summary.get("files_failed") or 0),
            "filesSkipped": int(conversion_summary.get("files_skipped") or 0),
            "eventsWritten": int(conversion_summary.get("events_written") or 0),
        },
        "pipeline": {
            "rawEvents": raw_events_count,
            "detections": int(payload_stats.get("detections") or 0),
            "alerts": int(payload_stats.get("alerts") or len(alerts)),
            "investigations": int(payload_stats.get("investigations") or len(investigations)),
            "timelineEntries": int(payload_stats.get("timeline_entries") or len(timeline)),
            "graphNodes": len(enriched_graph.get("nodes") or []),
            "graphEdges": len(enriched_graph.get("edges") or []),
            "artifacts": len(artifacts),
            "runtimeSeconds": round(runtime_seconds, 3),
            "processingEventsPerSecond": round(processing_eps, 3),
            "processingEventsPerMinute": round(processing_epm, 2),
        },
        "incident": {
            "start": incident_start.isoformat() if incident_start else "",
            "end": incident_end.isoformat() if incident_end else "",
            "spanSeconds": incident_span_seconds,
            "eventsPerMinute": round(incident_epm, 2),
        },
    }
    run = {
        "id": state.get("date") or f"run_{uuid.uuid4().hex[:8]}",
        "timestamp": state.get("date") or "",
        "sources": (state.get("metadata") or {}).get("log_sources") or [],
        "normalizedEvents": state.get("events") or [],
        "alerts": alerts,
        "investigations": investigations,
        "timeline": timeline,
        "entityGraph": enriched_graph,
        "riskScore": {
            "global": global_score,
            "adScore": global_score,
            "breakdown": [
                {
                    "category": cat.get("name") or "",
                    "score": cat.get("score") or 0,
                    "weight": cat.get("weight") or 0,
                    "details": cat.get("details") or "",
                }
                for cat in security.get("categories") or []
            ],
            "summary": security.get("summary") or "",
            "riskLevel": _risk_label(global_score),
        },
        "hardeningRecommendations": findings,
        "reconstruction": {
            "story": story,
            "attackChain": chain,
            "attackPath": path,
            "patientZero": {
                "entity": reconstruction.get("patient_zero_account") or reconstruction.get("patient_zero_host") or "unknown",
                "confidence": int(round(float(reconstruction.get("confidence") or 0) * 100)),
                "evidence": "; ".join(reconstruction.get("key_observations") or []) or reconstruction.get("summary") or "",
            },
            "estimatedImpacts": impacts,
        },
        "benchmark": benchmark,
        "status": "complete",
        "progress": [],
        "artifacts": artifacts,
        "rawState": state,
    }
    return run


def _parse_multipart(handler: BaseHTTPRequestHandler) -> tuple[list[tuple[str, str, bytes]], dict[str, str]]:
    content_type = handler.headers.get("Content-Type", "")
    content_length = int(handler.headers.get("Content-Length", "0") or "0")
    body = handler.rfile.read(content_length)
    if "multipart/form-data" not in content_type:
        return [], {}
    raw = (f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n").encode("utf-8") + body
    message = BytesParser(policy=email_default_policy).parsebytes(raw)
    files: list[tuple[str, str, bytes]] = []
    fields: dict[str, str] = {}
    for part in message.iter_parts():
        if part.get_content_disposition() != "form-data":
            continue
        name = part.get_param("name", header="content-disposition") or "field"
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if filename:
            files.append((name, filename, payload))
        else:
            fields[name] = payload.decode("utf-8", errors="replace")
    return files, fields


def _save_uploaded_files(file_parts: list[tuple[str, str, bytes]], target_dir: Path) -> list[str]:
    paths: list[str] = []
    for _field_name, filename, payload in file_parts:
        filename = _slug(Path(filename).name)
        dest = target_dir / filename
        dest.write_bytes(payload)
        paths.append(str(dest))
    return paths


class ADFTUIHandler(BaseHTTPRequestHandler):
    server_version = "ADFTUI/1.0"

    @property
    def app_state(self) -> AppState:
        return self.server.app_state  # type: ignore[attr-defined]

    @property
    def static_dir(self) -> Path:
        return self.server.static_dir  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[ADFT UI] {self.address_string()} - {format % args}")

    def _send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=_json_default).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path, status: int = 200, download: bool = False) -> None:
        if not path.exists() or not path.is_file():
            self.send_error(404, "File not found")
            return
        ctype, _ = mimetypes.guess_type(str(path))
        ctype = ctype or "application/octet-stream"
        data = path.read_bytes()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
        self.end_headers()
        self.wfile.write(data)

    def _serve_spa(self, path_str: str) -> None:
        path_str = path_str.lstrip("/") or "index.html"
        static_path = self.static_dir / path_str
        if static_path.exists() and static_path.is_file():
            return self._send_file(static_path)
        return self._send_file(self.static_dir / "index.html")


    def do_HEAD(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/"):
            self.send_response(200)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        path_str = path.lstrip("/") or "index.html"
        static_path = self.static_dir / path_str
        if not static_path.exists() or not static_path.is_file():
            static_path = self.static_dir / "index.html"
        ctype, _ = mimetypes.guess_type(str(static_path))
        ctype = ctype or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(static_path.stat().st_size))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/health":
            self.app_state.refresh_from_disk()
            return self._send_json({
                "status": "ok",
                "release": RELEASE_LABEL,
                "package_version": __version__,
                "output_dir": str(self.app_state.output_dir.resolve()),
                "current_run_available": bool(self.app_state.raw_state),
                "artifacts": len(self.app_state.artifacts),
            })
        if path == "/api/capabilities":
            return self._send_json({
                "release": RELEASE_LABEL,
                "package_version": __version__,
                "supported_inputs": SUPPORTED_INPUTS,
                "commands": ["convert", "investigate", "summary", "alerts", "score", "story", "attack-chain", "attack-path", "reconstruct", "harden", "report"],
                "gui_mode": "integrated",
                "evtx_available": _evtx_available(),
            })
        if path == "/api/run":
            self.app_state.refresh_from_disk()
            return self._send_json({
                "run": self.app_state.adapted_run or empty_ui_run(),
                "conversion_manifest": self.app_state.conversion_manifest,
                "artifacts": self.app_state.artifacts,
            })
        if path.startswith("/api/jobs/"):
            job_id = path.rsplit("/", 1)[-1]
            job = self.app_state.jobs.get(job_id)
            if not job:
                return self._send_json({"error": "Job not found"}, status=404)
            return self._send_json(job.to_dict())
        if path == "/api/artifacts":
            self.app_state.refresh_from_disk()
            return self._send_json({"artifacts": self.app_state.artifacts})
        if path.startswith("/api/artifacts/"):
            name = unquote(path.split("/api/artifacts/", 1)[1])
            artifact_map = {
                item["name"]: self.app_state.output_dir / item["name"] if item["name"] != "conversion_manifest.json" else self.app_state.output_dir / "converted_inputs" / "conversion_manifest.json"
                for item in self.app_state._collect_artifacts()  # type: ignore[attr-defined]
            }
            candidate = artifact_map.get(name)
            if not candidate:
                self.send_error(404, "Artifact not found")
                return
            return self._send_file(candidate)
        return self._serve_spa(path)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if path in {"/api/convert", "/api/investigate"}:
            file_parts, form_fields = _parse_multipart(self)
            batch_dir = _ensure_dir(self.app_state.upload_root / f"batch_{uuid.uuid4().hex[:8]}")
            files = _save_uploaded_files(file_parts, batch_dir)
            if not files:
                return self._send_json({"error": "No files uploaded"}, status=400)
            job = self.app_state.jobs.create("convert" if path.endswith("convert") else "investigate")
            target = self.app_state.output_dir
            export_events = str(form_fields.get("export_events_jsonl", "true")).lower() in {"1", "true", "yes", "on"}
            no_filter = str(form_fields.get("no_filter", "false")).lower() in {"1", "true", "yes", "on"}
            thread = threading.Thread(
                target=self._run_job,
                args=(job.id, files, target, path.endswith("investigate"), export_events, no_filter),
                daemon=True,
            )
            thread.start()
            return self._send_json({"job_id": job.id}, status=202)
        if path == "/api/refresh":
            self.app_state.refresh_from_disk()
            return self._send_json({
                "status": "ok",
                "refreshed_at": datetime.now(UTC).isoformat(),
                "current_run_available": bool(self.app_state.raw_state),
                "artifacts": len(self.app_state.artifacts),
            })
        if path == "/api/export-scripts":
            self.app_state.refresh_from_disk()
            if not self.app_state.raw_state:
                return self._send_json({"error": "No run available"}, status=400)
            archive_path = export_hardening_scripts(self.app_state.output_dir)
            self.app_state.refresh_from_disk()
            return self._send_json({"artifact": "hardening_scripts.zip", "download_url": "/api/artifacts/hardening_scripts.zip", "path": str(archive_path)})
        self._send_json({"error": "Unsupported endpoint"}, status=404)

    def _run_job(self, job_id: str, files: list[str], target: Path, investigate: bool, export_events_jsonl: bool, no_filter: bool) -> None:
        stage_weights = {
            "conversion": 10,
            "ingestion": 20,
            "normalization": 30,
            "detection": 40,
            "correlation": 55,
            "timeline": 65,
            "noise_filter": 72,
            "entity_graph": 80,
            "risk_scoring": 86,
            "ad_score": 90,
            "hardening": 93,
            "case_explanation": 96,
            "reporting": 99,
            "exports": 100,
        }
        self.app_state.jobs.update(job_id, status="running", started_at=time.time(), message="Starting", progress_pct=1)
        try:
            if not investigate:
                converter = CanonicalJsonlConverter()
                self.app_state.jobs.update(job_id, stage="conversion", message="Converting to canonical JSONL", progress_pct=20)
                manifest = converter.convert_inputs(files, target / "converted_inputs")
                self.app_state.refresh_from_disk()
                self.app_state.jobs.update(job_id, status="completed", finished_at=time.time(), progress_pct=100, message="Conversion complete", result={"manifest_path": manifest.get("manifest_path")})
                return

            def progress(step: str, detail: str) -> None:
                self.app_state.jobs.update(
                    job_id,
                    stage=step,
                    message=detail or step,
                    progress_pct=stage_weights.get(step, 50),
                )

            result = run_investigation(
                logs=files,
                output_dir=target,
                formats=["html", "json", "csv"],
                export_events_jsonl=export_events_jsonl,
                no_filter=no_filter,
                progress=progress,
            )
            self.app_state.refresh_from_disk()
            self.app_state.jobs.update(job_id, status="completed", finished_at=time.time(), progress_pct=100, message="Investigation complete", result={"state_path": result.get("state_path")})
        except Exception as exc:  # noqa: BLE001
            self.app_state.jobs.update(job_id, status="failed", finished_at=time.time(), message=str(exc), errors=[str(exc)])


def export_hardening_scripts(output_dir: Path) -> Path:
    state = load_last_run(output_dir)
    hard = state.get("hardening") or {}
    findings = hard.get("findings") or []
    export_dir = _ensure_dir(output_dir / "hardening_scripts")
    manifest = {
        "summary": hard.get("summary"),
        "coverage": hard.get("script_coverage") or {},
        "scripts": [],
    }
    for finding in findings:
        script = finding.get("powershell_fix")
        if not script:
            continue
        name = finding.get("finding_id") or uuid.uuid4().hex[:8]
        path = export_dir / f"{name}_remediation.ps1"
        path.write_text(script, encoding="utf-8")
        manifest["scripts"].append({
            "finding_id": name,
            "title": finding.get("title"),
            "priority": finding.get("priority"),
            "path": path.name,
        })
    (export_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    archive_path = output_dir / "hardening_scripts.zip"
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in export_dir.iterdir():
            if file.is_file():
                zf.write(file, arcname=file.name)
    return archive_path


def _evtx_available() -> bool:
    try:
        import Evtx  # type: ignore  # noqa: F401
        return True
    except Exception:
        return False


def serve_ui(output_dir: str | Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    static_dir = resources.files("adft").joinpath("webui_dist")
    static_path = Path(str(static_dir))
    if not static_path.exists():
        raise FileNotFoundError("Integrated web UI assets were not found in adft/webui_dist")

    app_state = AppState(Path(output_dir))
    server = ThreadingHTTPServer((host, port), ADFTUIHandler)
    server.app_state = app_state  # type: ignore[attr-defined]
    server.static_dir = static_path  # type: ignore[attr-defined]
    print(f"[ADFT] Integrated GUI ready on http://{host}:{port}")
    print(f"[ADFT] Output directory: {Path(output_dir).resolve()}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[ADFT] GUI server stopped.")
    finally:
        server.server_close()
