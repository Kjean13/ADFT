from __future__ import annotations

from adft.ui_server import adapt_state_to_ui


def test_ui_adapter_maps_graph_edges_and_enriches_time_metadata() -> None:
    state = {
        'date': '2026-03-15T10:00:00+00:00',
        'metadata': {'log_sources': ['demo.json']},
        'events': [
            {
                'timestamp': '2026-03-15T10:00:00+00:00',
                'event_id': 4624,
                'user': 'backupadmin',
                'source_host': 'WS01.corp.local',
                'target_host': 'DC01.corp.local',
                'ip_address': '10.0.0.10',
                'process_name': 'powershell.exe',
                'service_name': 'WinRM',
                'id': 'evt-1',
            },
            {
                'timestamp': '2026-03-15T10:05:00+00:00',
                'event_id': 4624,
                'user': 'backupadmin',
                'source_host': 'WS01.corp.local',
                'target_host': 'DC01.corp.local',
                'ip_address': '10.0.0.10',
                'id': 'evt-2',
                'ioc_match': {'value': '10.0.0.10'},
            },
        ],
        'alerts': [
            {
                'id': 'det-1',
                'rule_id': 'AD-LATERAL-001',
                'rule_name': 'Suspicious admin logon',
                'severity': 'critique',
                'timestamp': '2026-03-15T10:05:00+00:00',
                'source_host': 'WS01.corp.local',
                'target_host': 'DC01.corp.local',
                'user': 'backupadmin',
                'source_ip': '10.0.0.10',
                'description': 'Suspicious admin logon observed',
            }
        ],
        'investigations': [],
        'timeline_entries': [],
        'security_score': {'global_score': 41, 'categories': []},
        'hardening': {'findings': []},
        'reconstruction': {'patient_zero_account': 'backupadmin', 'confidence': 0.8},
        'entity_graph': {
            'nodes': [
                {'type': 'account', 'value': 'backupadmin', 'count': 2, 'role': 'privileged_account', 'criticality': 'high', 'degree': 2},
                {'type': 'host', 'value': 'WS01.corp.local', 'count': 2, 'role': 'endpoint', 'criticality': 'medium', 'degree': 2},
                {'type': 'host', 'value': 'DC01.corp.local', 'count': 2, 'role': 'domain_controller', 'criticality': 'high', 'degree': 2},
                {'type': 'ip', 'value': '10.0.0.10', 'count': 2, 'role': 'network_origin', 'criticality': 'medium', 'degree': 1},
            ],
            'edges': [
                {'from': 'WS01.corp.local', 'rel': 'logged_on_as', 'to': 'backupadmin', 'count': 2},
                {'from': 'backupadmin', 'rel': 'accessed', 'to': 'DC01.corp.local', 'count': 2},
                {'from': '10.0.0.10', 'rel': 'seen_on', 'to': 'WS01.corp.local', 'count': 2},
            ],
            'summary': {'accounts': 1, 'hosts': 2, 'ips': 1, 'domain_controllers': 1, 'privileged_accounts': 1},
            'analysis': {'hot_nodes': [{'value': 'backupadmin'}]},
        },
        'stats': {'raw_events': 2, 'detections': 1, 'alerts': 1, 'investigations': 0, 'timeline_entries': 0, 'timings_sec': {'conversion': 0.1, 'exports': 0.5}},
        'conversion': {'summary': {'files_scanned': 1, 'files_converted': 1, 'files_failed': 0, 'files_skipped': 0, 'events_written': 2}},
    }

    run = adapt_state_to_ui(state, artifacts=[])
    graph = run['entityGraph']

    assert graph['edges']
    assert any(edge['label'] == 's’est authentifié comme' for edge in graph['edges'])
    assert graph['timeframe']['start'] == '2026-03-15T10:00:00+00:00'
    assert graph['timeframe']['end'] == '2026-03-15T10:05:00+00:00'

    backup_node = next(node for node in graph['nodes'] if node['label'] == 'backupadmin')
    ip_node = next(node for node in graph['nodes'] if node['label'] == '10.0.0.10')
    assert backup_node['firstSeen'] == '2026-03-15T10:00:00+00:00'
    assert backup_node['lastSeen'] == '2026-03-15T10:05:00+00:00'
    assert backup_node['alertCount'] >= 1
    assert backup_node['isCritical'] is True
    assert ip_node['isKnownIoc'] is True

    assert run['benchmark']['conversion']['filesConverted'] == 1
    assert run['benchmark']['pipeline']['graphEdges'] >= 3


    assert run['benchmark']['pipeline']['runtimeSeconds'] == 0.5
    assert run['benchmark']['pipeline']['processingEventsPerMinute'] == 240.0
