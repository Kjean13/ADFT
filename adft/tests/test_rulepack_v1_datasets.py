from __future__ import annotations

from pathlib import Path

import pytest

from adft.core.ingestion.loader import LogLoader
from adft.core.normalization.normalizer import EventNormalizer
from adft.detection.engine import DetectionEngine
from adft.detection.rulepacks import RulePackV1


REPO_ROOT = Path(__file__).resolve().parents[2]
DATASETS = [
    REPO_ROOT / "adft" / "datasets" / "sample_logs.json",
    REPO_ROOT / "test_logs" / "attack.json",
    REPO_ROOT / "adft" / "datasets" / "kerberoasting_massive.json",
    REPO_ROOT / "adft" / "datasets" / "password_spray_distributed.json",
    REPO_ROOT / "adft" / "datasets" / "golden_ticket_suspected.json",
]


@pytest.mark.parametrize("dataset", DATASETS)
def test_rulepack_v1_runs_on_dataset(dataset: Path):
    assert dataset.exists(), f"Dataset missing: {dataset}"

    pack = RulePackV1()
    pack.validate()

    loader = LogLoader()
    raw = loader.load(str(dataset))
    assert isinstance(raw, list)

    normalizer = EventNormalizer()
    events = normalizer.normalize_all(raw)
    assert isinstance(events, list)

    engine = DetectionEngine(rulepack=pack)
    detections = engine.run(events)
    assert isinstance(detections, list)

    for d in detections:
        assert getattr(d, "rule_id", None)
        assert getattr(d, "rule_name", None)
        assert getattr(d, "timestamp", None)


def test_rulepack_v1_mitre_mapping_is_consistent():
    pack = RulePackV1()
    mapping = pack.mitre_mapping()
    assert len(mapping) >= 15

    ids = [m.get("rule_id", "") for m in mapping]
    assert len(ids) == len(set(ids))

    for m in mapping:
        assert m.get("rule_id")
        assert m.get("rule_name")
        assert m.get("mitre_tactic")


def test_attack_dataset_triggers_some_detections():
    pack = RulePackV1()
    engine = DetectionEngine(rulepack=pack)
    loader = LogLoader()
    normalizer = EventNormalizer()

    raw = loader.load(str(REPO_ROOT / "test_logs" / "attack.json"))
    events = normalizer.normalize_all(raw)
    detections = engine.run(events)
    assert len(detections) >= 1
