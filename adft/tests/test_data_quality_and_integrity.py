
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from adft.core.ingestion.loader import LogLoader
from adft.core.normalization.normalizer import EventNormalizer
from adft.reporting.integrity import write_integrity_manifest


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_normalization_records_quality_warnings_for_malformed_events():
    dataset = REPO_ROOT / "adft" / "datasets" / "malformed_events.ndjson"
    raw = LogLoader().load(dataset)
    normalizer = EventNormalizer()
    events = normalizer.normalize_all(raw)
    quality = normalizer.quality_report
    assert len(events) >= 2
    assert quality["stats"]["warnings"] >= 1
    assert normalizer.stats["dropped"] >= 1


def test_integrity_manifest_contains_sha256_for_files():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        (base / "a.txt").write_text("hello", encoding="utf-8")
        (base / "b.json").write_text(json.dumps({"ok": True}), encoding="utf-8")
        manifest = write_integrity_manifest(base, ["a.txt", "b.json"])
        data = json.loads(manifest.read_text(encoding="utf-8"))
        assert data["algorithm"] == "sha256"
        assert {item["path"] for item in data["files"]} == {"a.txt", "b.json"}
        assert all(len(item["sha256"]) == 64 for item in data["files"])
