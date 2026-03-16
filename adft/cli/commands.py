"""ADFT CLI commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adft.core.ingestion.canonical import CanonicalJsonlConverter
from adft.exports import build_attack_navigator_layer, build_replay_payload
from adft.presentation import (
    render_alerts_text,
    render_attack_chain_text,
    render_attack_path_text,
    render_explain_text,
    render_hardening_text,
    render_reconstruct_text,
    render_score_text,
    render_story_text,
    render_summary_text,
)
from adft.runtime import LAST_RUN_FILE, detection_to_alert, run_investigation
from adft.ui_server import serve_ui


STAGE_LABELS = {
    "conversion": "Conversion JSONL",
    "ingestion": "Ingestion",
    "normalization": "Normalisation",
    "detection": "Détection",
    "events_export": "Export events JSONL",
    "correlation": "Corrélation",
    "timeline": "Timeline",
    "noise_filter": "Noise filtering",
    "entity_graph": "Entity graph",
    "risk_scoring": "Risk scoring",
    "ad_score": "AD security score",
    "hardening": "Hardening",
    "case_explanation": "Case explanation",
    "reporting": "Reporting",
    "exports": "Exports",
}


def _stage(name: str, width: int = 34) -> None:
    label = f"[ADFT] {name}"
    dots = "." * max(1, width - len(label))
    print(f"{label} {dots}", end="", flush=True)


def _done(msg: str = "OK") -> None:
    print(f" {msg}")


def _load_last_run(output_dir: str | Path) -> dict[str, Any]:
    path = Path(output_dir) / LAST_RUN_FILE
    if not path.exists():
        raise FileNotFoundError(
            f"Aucune investigation trouvée dans {path.parent}. Lance d'abord: adft investigate <logs> -o {path.parent}"
        )
    return json.loads(path.read_text(encoding="utf-8"))


# Compatibility export kept for existing tests and helpers.
def _detection_to_alert(detection):
    return detection_to_alert(detection)


def cmd_convert(args) -> None:
    converter = CanonicalJsonlConverter()
    manifest = converter.convert_inputs(args.logs, args.output)
    summary = manifest.get("summary", {}) or {}
    print("\nADFT Canonical Conversion")
    print("─────────────────────────")
    print(f"Sources scanned : {summary.get('files_scanned', 0)}")
    print(f"Files converted : {summary.get('files_converted', 0)}")
    print(f"Files failed    : {summary.get('files_failed', 0)}")
    print(f"Files skipped   : {summary.get('files_skipped', 0)}")
    print(f"Files empty     : {summary.get('files_empty', 0)}")
    print(f"Events written  : {summary.get('events_written', 0)}")
    print(f"Manifest        : {manifest.get('manifest_path')}")
    print(f"Output dir      : {Path(args.output).resolve()}")
    print("")


def cmd_investigate(args) -> None:
    current_stage: str | None = None

    def progress(step: str, detail: str) -> None:
        nonlocal current_stage
        if step != current_stage:
            if current_stage is not None:
                _done("OK")
            _stage(STAGE_LABELS.get(step, step))
            current_stage = step
        if detail:
            print(f"\r[ADFT] {STAGE_LABELS.get(step, step)} — {detail}", end="", flush=True)

    result = run_investigation(
        logs=list(args.logs),
        output_dir=args.output,
        formats=[str(f).lower() for f in (getattr(args, "format", None) or ["html", "json", "csv"])],
        export_events_jsonl=bool(getattr(args, "export_events_jsonl", False)),
        no_filter=bool(getattr(args, "no_filter", False)),
        progress=progress,
    )
    if current_stage is not None:
        _done("OK")

    payload = result["payload"]
    stats = payload.get("stats", {}) or {}
    generated = [Path(path).name for path in result.get("generated", [])]
    conversion = payload.get("conversion", {}) or {}
    conversion_summary = conversion.get("summary", {}) or {}
    print("\nADFT Investigation Summary")
    print("──────────────────────────")
    print(f"Sources converted: {conversion_summary.get('files_converted', 0)}")
    print(f"Sources failed   : {conversion_summary.get('files_failed', 0)}")
    print(f"Sources skipped  : {conversion_summary.get('files_skipped', 0)}")
    print(f"Sources empty    : {conversion_summary.get('files_empty', 0)}")
    print(f"Events analyzed  : {stats.get('raw_events', 0)}")
    print(f"Detections       : {stats.get('detections', 0)}")
    print(f"Alerts           : {stats.get('alerts', 0)}")
    print(f"Investigations   : {stats.get('investigations', 0)}")
    print(f"Timeline         : {stats.get('timeline_entries', 0)}")
    print(f"Outputs          : {', '.join(generated)}")
    print(f"State            : {result.get('state_path')}")
    print(f"Integrity        : {result.get('integrity_path')}")
    print("")


def cmd_report(args) -> None:
    output_dir = Path(args.output)
    candidates = [
        ("JSON report", output_dir / "adft_report.json"),
        ("HTML report", output_dir / "adft_report.html"),
        ("CSV report", output_dir / "adft_report.csv"),
        ("Navigator", output_dir / "attack_navigator_layer.json"),
        ("Replay", output_dir / "adft_replay.json"),
        ("Mermaid graph", output_dir / "attack_graph.mmd"),
        ("Integrity manifest", output_dir / "adft_integrity.json"),
        ("Run state", output_dir / LAST_RUN_FILE),
        ("Conversion manifest", output_dir / "converted_inputs" / "conversion_manifest.json"),
    ]
    print("\nADFT Artefacts")
    print("──────────────")
    for label, path in candidates:
        status = "✓" if path.exists() else "·"
        print(f"{status} {label:20} {path}")
    print("")


def cmd_summary(args) -> None:
    state = _load_last_run(getattr(args, "output", "./reports_core"))
    print(render_summary_text(state))


def cmd_alerts(args) -> None:
    state = _load_last_run(getattr(args, "output", "./reports_core"))
    print(render_alerts_text(state, full=bool(getattr(args, "full", False))))


def cmd_attack_chain(args) -> None:
    state = _load_last_run(getattr(args, "output", "./reports_core"))
    print(render_attack_chain_text(state))


def cmd_attack_path(args) -> None:
    state = _load_last_run(getattr(args, "output", "./reports_core"))
    print(render_attack_path_text(state))


def cmd_story(args) -> None:
    state = _load_last_run(getattr(args, "output", "./reports_core"))
    print(render_story_text(state, full=bool(getattr(args, "full", False))))


def cmd_reconstruct(args) -> None:
    state = _load_last_run(getattr(args, "output", "./reports_core"))
    print(render_reconstruct_text(state, full=bool(getattr(args, "full", False))))


def cmd_score(args) -> None:
    state = _load_last_run(getattr(args, "output", "./reports_core"))
    print(render_score_text(state))


def cmd_harden(args) -> None:
    output_dir = getattr(args, "output", "./reports_core")
    state = _load_last_run(output_dir)
    hard = state.get("hardening", {}) or {}
    findings = hard.get("findings", []) or []
    print(render_hardening_text(state))

    export_dir = getattr(args, "export_scripts", None)
    if export_dir:
        base = Path(export_dir)
        base.mkdir(parents=True, exist_ok=True)
        exported = 0
        manifest = {
            "summary": hard.get("summary"),
            "coverage": hard.get("script_coverage") or {},
            "scripts": [],
        }
        for finding in findings:
            script = finding.get("powershell_fix")
            if not script:
                continue
            name = finding.get("finding_id") or f"finding_{exported + 1}"
            path = base / f"{name}_remediation.ps1"
            path.write_text(script, encoding="utf-8")
            exported += 1
            manifest["scripts"].append(
                {
                    "finding_id": name,
                    "title": finding.get("title"),
                    "priority": finding.get("priority"),
                    "confidence": finding.get("confidence"),
                    "validation_steps": finding.get("validation_steps") or [],
                    "path": path.name,
                }
            )
            print(f"[ADFT]   ✓ {path}")
        (base / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[ADFT] {exported} script(s) exporté(s) vers {base}")


def cmd_explain(args) -> None:
    state = _load_last_run(getattr(args, "output", "./reports_core"))
    print(render_explain_text(state, getattr(args, "level", "analyst")))


def cmd_navigator(args) -> None:
    state = _load_last_run(getattr(args, "output", "./reports_core"))
    out = Path(getattr(args, "output", "./reports_core")) / "attack_navigator_layer.json"
    layer = build_attack_navigator_layer(state.get("alerts", []) or [])
    out.write_text(json.dumps(layer, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[ADFT] ✓ Navigator layer written to {out}")


def cmd_replay(args) -> None:
    state = _load_last_run(getattr(args, "output", "./reports_core"))
    out = Path(getattr(args, "output", "./reports_core")) / "adft_replay.json"
    payload = build_replay_payload(
        alerts=state.get("alerts", []) or [],
        timeline=state.get("timeline", {}) or {},
        investigations=state.get("investigations", []) or [],
        entity_graph=state.get("entity_graph", {}) or {},
        reconstruction=state.get("reconstruction", {}) or {},
    )
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[ADFT] ✓ Replay payload written to {out}")



def cmd_ui(args) -> None:
    serve_ui(output_dir=getattr(args, "output", "./reports_core"), host=getattr(args, "host", "127.0.0.1"), port=int(getattr(args, "port", 8765)))
