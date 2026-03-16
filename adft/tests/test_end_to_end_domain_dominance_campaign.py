from __future__ import annotations

from adft.tests.scenario_utils import DATASETS, run_full_case


def test_domain_dominance_campaign_end_to_end_detects_the_full_chain():
    case = run_full_case(DATASETS['domain_dominance'])

    expected_rules = {
        'AUTH-001', 'KERB-001', 'AUTH-002', 'AUTH-003',
        'PRIV-001', 'COMP-001', 'COMP-002', 'PERS-7045', 'KERB-003',
    }
    assert expected_rules.issubset(case['rule_ids'])
    assert len(case['normalized_events']) >= 240
    assert len(case['detections']) >= 12
    assert len(case['investigations']) == 1

    inv = case['investigations'][0]
    assert inv.start_time.isoformat().startswith('2026-03-11T22:45:00')
    assert inv.end_time.isoformat().startswith('2026-03-11T23:48:00')
    assert len(inv.detections) >= 12

    phases = {entry.phase.value for entry in case['timeline_entries']}
    assert {'credential_access', 'privilege_escalation', 'lateral_movement', 'persistence', 'defense_evasion'}.issubset(phases)

    score = case['security_score']
    assert score.global_score <= 35.0
    assert score.risk_level in {'élevé', 'critique'}
    critical_count = int(str(score.severity_mix).split(' critiques', 1)[0])
    assert critical_count >= 5
    assert score.evidence_confidence >= 0.8

    reconstruction = case['pipeline']['reconstruction']
    assert reconstruction['patient_zero_host'] == 'WS-ATTACK01'
    assert reconstruction['scope'] == 'domain_tier_observed'
    assert reconstruction['confidence_label'] in {'high', 'moderate'}
    assert 'DC01.corp.local' in reconstruction['domain_controllers']
    assert 'backupadmin' in reconstruction['affected_accounts']

    graph = case['graph']
    assert graph['summary']['domain_controllers'] >= 1
    assert graph['summary']['privileged_accounts'] >= 1
    assert graph['analysis']['paths']
    assert any(node['value'] == 'DC01.corp.local' for node in graph['analysis']['crown_jewels'])
