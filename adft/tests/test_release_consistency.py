from __future__ import annotations

import tomllib
from pathlib import Path

from adft import RELEASE_LABEL, __version__


def test_release_metadata_consistent() -> None:
    root = Path(__file__).resolve().parents[2]
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project_version = pyproject["project"]["version"]

    assert __version__ == project_version
    assert RELEASE_LABEL == "v1.0"
    assert project_version.startswith("1.0")


def test_readme_mentions_current_release_and_rule_count() -> None:
    root = Path(__file__).resolve().parents[2]
    readme = (root / "README.md").read_text(encoding="utf-8")
    assert f"# ADFT {RELEASE_LABEL}" in readme
    assert "34 rules" in readme
    assert "canonical JSONL" in readme
