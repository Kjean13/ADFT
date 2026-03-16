from __future__ import annotations

import json
from argparse import Namespace

from adft.cli.commands import cmd_investigate
from adft.tests.scenario_utils import DATASETS


def test_cli_investigate_generates_reports_and_integrity_for_heavy_campaign(tmp_path):
    args = Namespace(
        logs=[str(DATASETS['domain_dominance'])],
        output=str(tmp_path),
        format=['json', 'html', 'csv'],
        export_events_jsonl=False,
        no_filter=False,
    )

    cmd_investigate(args)

    assert (tmp_path / 'adft_report.json').exists()
    assert (tmp_path / 'adft_report.html').exists()
    assert (tmp_path / 'adft_report.csv').exists()
    assert (tmp_path / 'adft_integrity.json').exists()
    assert (tmp_path / '.adft_last_run.json').exists()

    manifest = json.loads((tmp_path / 'adft_integrity.json').read_text(encoding='utf-8'))
    assert manifest['algorithm'] == 'sha256'
    paths = {entry['path'] for entry in manifest['files']}
    assert {'adft_report.json', 'adft_report.html', 'adft_report.csv'}.issubset(paths)

    report = json.loads((tmp_path / 'adft_report.json').read_text(encoding='utf-8'))
    assert len(report['alerts']) >= 10
    assert len(report['investigations']) == 1
    assert report['integrity']['algorithm'] == 'sha256'
    assert report['reconstruction']['patient_zero_host'] == 'WS-ATTACK01'
