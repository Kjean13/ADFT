from __future__ import annotations

from adft.tests.scenario_utils import DATASETS, run_full_case


def test_benign_edge_threshold_dataset_resists_false_positives():
    case = run_full_case(DATASETS['benign_edge'])

    assert len(case['normalized_events']) >= 290
    assert case['detections'] == []
    assert case['investigations'] == []
    assert case['timeline_entries'] == []

    score = case['security_score']
    assert score.global_score == 100.0
    assert score.risk_level == 'faible'
    assert score.evidence_confidence <= 0.1

    reconstruction = case['pipeline']['reconstruction']
    assert reconstruction['available'] is False
    assert reconstruction['available'] is False
