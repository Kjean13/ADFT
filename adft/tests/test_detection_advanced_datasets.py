
from __future__ import annotations

from pathlib import Path

from adft.core.ingestion.loader import LogLoader
from adft.core.normalization.normalizer import EventNormalizer
from adft.detection.engine import DetectionEngine

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASETS = {
    "kerberoast": REPO_ROOT / "adft" / "datasets" / "kerberoasting_massive.json",
    "spray": REPO_ROOT / "adft" / "datasets" / "password_spray_distributed.json",
    "golden": REPO_ROOT / "adft" / "datasets" / "golden_ticket_suspected.json",
}


def _run_dataset(path: Path):
    loader = LogLoader()
    raw = loader.load(str(path))
    normalizer = EventNormalizer()
    events = normalizer.normalize_all(raw)
    engine = DetectionEngine()
    detections = engine.run(events)
    return loader, normalizer, detections


def test_massive_kerberoasting_dataset_triggers_kerberoasting():
    _, normalizer, detections = _run_dataset(DATASETS["kerberoast"])
    rule_ids = {d.rule_id for d in detections}
    assert "KERB-001" in rule_ids
    kerb = [d for d in detections if d.rule_id == "KERB-001"][0]
    assert len(kerb.events) == 200
    assert kerb.severity.value == "critical"
    assert normalizer.stats["normalized"] == 200


def test_password_spray_dataset_triggers_bruteforce_rule():
    _, _, detections = _run_dataset(DATASETS["spray"])
    rule_ids = {d.rule_id for d in detections}
    assert "AUTH-001" in rule_ids
    spray = [d for d in detections if d.rule_id == "AUTH-001"][0]
    assert spray.severity.value == "critical"
    assert "Password spraying" in spray.description


def test_golden_ticket_dataset_triggers_golden_ticket_rule():
    _, _, detections = _run_dataset(DATASETS["golden"])
    rule_ids = {d.rule_id for d in detections}
    assert "KERB-003" in rule_ids
