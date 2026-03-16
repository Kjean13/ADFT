from __future__ import annotations

import json
from pathlib import Path

from adft.core.ingestion.canonical import CanonicalJsonlConverter
from adft.runtime import run_investigation


def test_convert_mixed_inputs_continues_after_parser_failure(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[1] / "datasets" / "demo_mixed_inputs"
    manifest = CanonicalJsonlConverter().convert_inputs([source], tmp_path / "converted")
    summary = manifest["summary"]

    assert summary["files_scanned"] >= 8
    assert summary["files_converted"] >= 7
    assert summary["events_written"] >= 10
    assert summary["files_failed"] >= 1
    statuses = {entry["status"] for entry in manifest["entries"]}
    assert "converted" in statuses
    assert "failed" in statuses


def test_investigate_mixed_inputs_produces_outputs_even_with_failed_source(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[1] / "datasets" / "demo_mixed_inputs"
    result = run_investigation([source], tmp_path / "run")
    payload = result["payload"]
    conversion = payload["conversion"]

    assert conversion["summary"]["files_converted"] >= 7
    assert conversion["summary"]["files_failed"] >= 1
    assert payload["stats"]["raw_events"] > 0
    assert (tmp_path / "run" / ".adft_last_run.json").exists()
    assert (tmp_path / "run" / "adft_report.json").exists()

    manifest_path = tmp_path / "run" / "converted_inputs" / "conversion_manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert data["environment"]["optional_dependencies"]["python-evtx"] is False
