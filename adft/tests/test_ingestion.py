from adft.core.ingestion.loader import LogLoader
from pathlib import Path

def test_loader_rejects_missing_path():
    loader = LogLoader()
    try:
        loader.load("/path/that/does/not/exist")
        assert False, "Expected FileNotFoundError"
    except FileNotFoundError:
        assert True
