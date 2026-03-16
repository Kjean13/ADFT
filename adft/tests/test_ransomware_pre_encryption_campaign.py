from __future__ import annotations

from adft.tests.scenario_utils import DATASETS, run_full_case


def test_ransomware_pre_encryption_campaign_triggers_impact_and_evasion_stack():
    case = run_full_case(DATASETS['ransomware_pre'])

    assert {'RANS-AVSTOP', 'RANS-VSS', 'RANS-4663', 'PERS-7045', 'COMP-001', 'COMP-002'}.issubset(case['rule_ids'])
    assert len(case['normalized_events']) >= 150
    assert len(case['investigations']) == 1

    phases = {entry.phase.value for entry in case['timeline_entries']}
    assert 'defense_evasion' in phases
    assert 'persistence' in phases
    assert 'domain_dominance' in phases

    score = case['security_score']
    assert score.global_score <= 70.0
    critical_count = int(str(score.severity_mix).split(' critiques', 1)[0])
    assert critical_count >= 4

    reconstruction = case['pipeline']['reconstruction']
    assert reconstruction['available'] is True
    assert reconstruction['patient_zero_host'] == 'WS-ATTACK01'
    assert reconstruction['impacted_hosts']
    assert 'FS01.corp.local' in reconstruction['impacted_hosts']

    graph = case['graph']
    assert graph['analysis']['hot_nodes']
    assert graph['analysis']['paths']
    assert any(node['value'] == 'backupadmin' for node in graph['analysis']['hot_nodes'])
