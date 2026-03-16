from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from adft.analysis.ad_security_score import ADSecurityScoreCalculator
from adft.analysis.noise_filter import NoiseFilter
from adft.analysis.risk_scorer import RiskScorer
from adft.cli.commands import _detection_to_alert
from adft.core.ingestion.loader import LogLoader
from adft.core.models.timeline import AttackTimeline
from adft.core.normalization.normalizer import EventNormalizer
from adft.correlation.engine import CorrelationEngine
from adft.detection.engine import DetectionEngine
from adft.graph.entity_graph import build_entity_graph, enrich_alerts_with_entities
from adft.investigation.pipeline import run_investigation_pipeline
from adft.timeline.engine import TimelineEngine

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASETS = {
    'domain_dominance': REPO_ROOT / 'adft' / 'datasets' / 'domain_dominance_campaign.json',
    'ransomware_pre': REPO_ROOT / 'adft' / 'datasets' / 'ransomware_pre_encryption_campaign.json',
    'benign_edge': REPO_ROOT / 'adft' / 'datasets' / 'benign_edge_thresholds.json',
}


def run_full_case(path: Path | str) -> dict[str, Any]:
    loader = LogLoader()
    raw_events = loader.load(str(path))
    normalizer = EventNormalizer()
    norm_events = normalizer.normalize_all(raw_events)

    detection_engine = DetectionEngine()
    detections = detection_engine.run(norm_events)

    correlation_engine = CorrelationEngine()
    investigations = correlation_engine.correlate(detections)

    timeline_engine = TimelineEngine()
    timeline_entries = timeline_engine.build(investigations, detections)
    timeline = AttackTimeline(entries=timeline_entries)

    graph = build_entity_graph([event.to_dict() for event in norm_events])
    alerts = [_detection_to_alert(d) for d in detections]
    alerts = enrich_alerts_with_entities(alerts, graph)
    alerts = NoiseFilter().filter_alerts(alerts)

    risk_scorer = RiskScorer()
    for alert in alerts:
        alert.risk_score = risk_scorer.score_alert(alert)
        alert.risk_level = risk_scorer.risk_level_from_score(alert.risk_score)

    security_score = ADSecurityScoreCalculator().calculate(alerts, investigations)

    pipeline = run_investigation_pipeline(
        events=[event.to_dict() for event in norm_events],
        detections=detections,
        timeline=timeline,
        alerts=[alert.to_dict() for alert in alerts],
        investigations=[inv.to_dict() for inv in investigations],
        security_score=asdict(security_score),
    )

    return {
        'loader': loader,
        'normalizer': normalizer,
        'raw_events': raw_events,
        'normalized_events': norm_events,
        'detections': detections,
        'alerts': alerts,
        'investigations': investigations,
        'timeline_entries': timeline_entries,
        'timeline': timeline,
        'graph': graph,
        'security_score': security_score,
        'pipeline': pipeline,
        'rule_ids': {d.rule_id for d in detections},
    }
