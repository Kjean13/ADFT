import unittest

from adft.reconstruction import build_compromise_reconstruction


def _summary(payload: dict) -> dict:
    stats = payload.get('stats') or {}
    score = payload.get('security_score') or {}
    timeline = payload.get('timeline') or {}
    graph = payload.get('entity_graph') or {}
    return {
        'alerts': stats.get('alerts', len(payload.get('alerts') or [])),
        'investigations': stats.get('investigations', len(payload.get('investigations') or [])),
        'timeline_entries': stats.get('timeline_entries', len(timeline.get('entries') or [])),
        'score': score.get('global_score') or score.get('score'),
        'risk_level': score.get('risk_level') or score.get('level'),
        'graph_nodes': len(graph.get('nodes') or []),
        'graph_edges': len(graph.get('edges') or []),
        'patient_zero_host': (payload.get('reconstruction') or {}).get('patient_zero_host'),
        'patient_zero_account': (payload.get('reconstruction') or {}).get('patient_zero_account'),
    }


class TestReconstruction(unittest.TestCase):
    def test_reconstruction_extracts_pivot_scope_and_paths(self) -> None:
        alerts = [
            {
                'timestamp': '2026-03-11T10:00:00+00:00',
                'severity': 'high',
                'rule_name': 'Suspicious RDP',
                'mitre_tactic': 'lateral movement',
                'mitre_technique': 'Remote Services',
                'user': 'admin1',
                'source_host': 'WS01',
                'target_host': 'DC01',
                'source_ip': '10.0.0.5',
            },
            {
                'timestamp': '2026-03-11T10:02:00+00:00',
                'severity': 'critical',
                'rule_name': 'Golden Ticket',
                'mitre_tactic': 'domain dominance',
                'mitre_technique': 'Golden Ticket',
                'user': 'krbtgt',
                'source_host': 'WS01',
                'target_host': 'DC01',
                'source_ip': '10.0.0.5',
            },
        ]
        timeline = {
            'entries': [
                {'timestamp': '2026-03-11T10:00:00+00:00', 'phase': 'lateral_movement', 'title': 'RDP', 'description': 'WS01 -> DC01'},
                {'timestamp': '2026-03-11T10:02:00+00:00', 'phase': 'domain_dominance', 'title': 'GT', 'description': 'ticket abuse'},
            ]
        }
        graph = {
            'nodes': [
                {'type': 'ip', 'value': '10.0.0.5'},
                {'type': 'host', 'value': 'WS01'},
                {'type': 'account', 'value': 'admin1'},
                {'type': 'host', 'value': 'DC01'},
            ],
            'edges': [
                {'from': '10.0.0.5', 'to': 'WS01', 'rel': 'seen_on'},
                {'from': 'WS01', 'to': 'admin1', 'rel': 'logged_on_as'},
                {'from': 'admin1', 'to': 'DC01', 'rel': 'accessed'},
            ],
        }
        reconstruction = build_compromise_reconstruction(alerts=alerts, investigations=[], timeline=timeline, entity_graph=graph, attack_story=[])
        self.assertTrue(reconstruction['available'])
        self.assertEqual(reconstruction['patient_zero_account'], 'admin1')
        self.assertEqual(reconstruction['patient_zero_host'], 'WS01')
        self.assertIn('DC01', reconstruction['domain_controllers'])
        self.assertTrue(reconstruction['path_candidates'])
        self.assertEqual(reconstruction['scope'], 'domain_tier_observed')

    def test_summary_exposes_reconstruction_pivot(self) -> None:
        payload = {
            'stats': {'alerts': 2, 'investigations': 1, 'timeline_entries': 2},
            'security_score': {'global_score': 40.0, 'risk_level': 'high'},
            'entity_graph': {'nodes': [1], 'edges': [1, 2]},
            'reconstruction': {'patient_zero_host': 'WS01', 'patient_zero_account': 'admin1'},
        }
        summary = _summary(payload)
        self.assertEqual(summary['patient_zero_host'], 'WS01')
        self.assertEqual(summary['patient_zero_account'], 'admin1')


if __name__ == '__main__':
    unittest.main()
