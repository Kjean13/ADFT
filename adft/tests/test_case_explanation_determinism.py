import json
import subprocess
from pathlib import Path


def run_once(tmpdir: Path):
    out = tmpdir / "reports"
    out.mkdir(parents=True, exist_ok=True)

    subprocess.check_call([
        "python3", "main.py", "investigate",
        "test_logs/attack.json", "-o", str(out), "-f", "json"
    ])

    report = json.loads((out / "adft_report.json").read_text())
    return report["case_explanation"]


def test_case_explanation_is_deterministic(tmp_path):
    a1 = run_once(tmp_path / "r1")
    a2 = run_once(tmp_path / "r2")
    assert a1 == a2
