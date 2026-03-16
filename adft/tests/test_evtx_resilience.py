from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from adft.core.ingestion.loader import LogLoader


@pytest.mark.skipif(importlib.util.find_spec("Evtx") is None, reason="python-evtx non installé")
def test_evtx_path_is_recognized_when_optional_dependency_is_present() -> None:
    sample = Path(__file__).resolve().parents[2] / "test_logs" / "dummy.evtx"
    loader = LogLoader()
    result = loader.parse_file_status(sample)
    assert result["parser_name"] == "EVTX Parser (Windows Event Log)"
    assert result["status"] in {"parsed", "failed"}
