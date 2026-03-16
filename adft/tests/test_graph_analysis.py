import unittest

from adft.graph.attack_path import analyze_attack_paths
from adft.graph.entity_graph import build_entity_graph


class TestGraphAnalysis(unittest.TestCase):
    def test_entity_graph_exposes_analysis_hot_nodes_and_paths(self) -> None:
        events = [
            {
                'event_id': 4624,
                'user': 'admin1',
                'source_host': 'WS01',
                'target_host': 'DC01',
                'source_ip': '10.0.0.5',
                'WorkstationName': 'WS01',
            },
            {
                'event_id': 4624,
                'user': 'admin1',
                'source_host': 'WS01',
                'target_host': 'DC01',
                'source_ip': '10.0.0.5',
                'WorkstationName': 'WS01',
            },
            {
                'event_id': 4624,
                'user': 'krbtgt',
                'source_host': 'WS01',
                'target_host': 'DC01',
                'source_ip': '10.0.0.5',
                'WorkstationName': 'WS01',
            },
        ]
        graph = build_entity_graph(events)
        analysis = graph.get('analysis') or {}
        self.assertEqual(graph['summary']['domain_controllers'], 1)
        self.assertGreaterEqual(graph['summary']['privileged_accounts'], 2)
        self.assertTrue(analysis.get('hot_nodes'))
        self.assertTrue(analysis.get('crown_jewels'))
        self.assertTrue(analysis.get('paths'))
        self.assertIn('summary', analysis)
        self.assertEqual(analysis['paths'][0]['risk_level'], 'high')

    def test_attack_path_analysis_prioritizes_dc_paths(self) -> None:
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
        paths = analyze_attack_paths(graph)
        self.assertTrue(paths)
        self.assertEqual(paths[0]['target'], 'DC01')
        self.assertIn('cible AD sensible', paths[0]['reasons'])
        self.assertGreaterEqual(paths[0]['risk_score'], 6)


if __name__ == '__main__':
    unittest.main()
