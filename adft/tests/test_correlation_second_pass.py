
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from adft.core.models.events import Detection, NormalizedEvent, Severity
from adft.correlation.engine import CorrelationEngine


def _event(ts, user, source, target, ip):
    return NormalizedEvent(
        timestamp=ts,
        event_id=4624,
        user=user,
        source_host=source,
        target_host=target,
        action="Connexion réussie",
        severity=Severity.INFO,
        ip_address=ip,
    )


def _detection(rule_id, ts, user, source, target, ip, mitre_tactic="Lateral Movement"):
    ev = _event(ts, user, source, target, ip)
    return Detection(
        id=f"{rule_id}-{user}",
        rule_id=rule_id,
        rule_name=rule_id,
        description=f"{rule_id} for {user}",
        severity=Severity.HIGH,
        mitre_tactic=mitre_tactic,
        mitre_technique="Remote Desktop Protocol",
        mitre_id="T1021.001",
        events=[ev],
        timestamp=ts,
        entities=[user, source, target, ip],
        confidence=0.8,
    )


def test_second_pass_merges_investigations_sharing_host_and_time():
    base = datetime(2026, 3, 11, 8, 0, tzinfo=timezone.utc)
    detections = [
        _detection("AUTH-001", base, "user-a", "WS-01", "DC01", "10.10.10.10"),
        _detection("AUTH-002", base + timedelta(minutes=10), "user-b", "WS-01", "SRV01", "10.10.10.10"),
        _detection("AUTH-003", base + timedelta(minutes=20), "user-c", "WS-01", "DC01", "10.10.10.10"),
    ]
    investigations = CorrelationEngine().correlate(detections)
    assert len(investigations) == 1
    assert investigations[0].start_time == base
    assert investigations[0].end_time == base + timedelta(minutes=20)


def test_correlation_window_splits_distant_clusters():
    base = datetime(2026, 3, 11, 8, 0, tzinfo=timezone.utc)
    detections = [
        _detection("AUTH-001", base, "user-a", "WS-01", "DC01", "10.10.10.10"),
        _detection("AUTH-002", base + timedelta(days=2), "user-a", "WS-01", "DC01", "10.10.10.10"),
    ]
    investigations = CorrelationEngine().correlate(detections)
    assert len(investigations) == 2
