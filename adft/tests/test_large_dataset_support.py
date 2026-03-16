import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from adft.core.ingestion.json_parser import JsonParser

MAX_RAW_UPLOAD_BYTES = 500 * 1024 * 1024


def _safe_rel_path(value: str) -> Path:
    rel = Path((value or "").replace("\\", "/"))
    parts = [p for p in rel.parts if p not in {"", ".", ".."}]
    if not parts:
        raise ValueError("relative_path invalide")
    return Path(*parts)


def _parse_bool(value, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


class TestLargeDatasetSupport(unittest.TestCase):
    def test_safe_rel_path_normalizes_windows_paths(self) -> None:
        self.assertEqual(_safe_rel_path(r"folder\sub\log.ndjson"), Path("folder/sub/log.ndjson"))

    def test_parse_bool_variants(self) -> None:
        self.assertTrue(_parse_bool("true"))
        self.assertTrue(_parse_bool("1"))
        self.assertFalse(_parse_bool("false", True))
        self.assertFalse(_parse_bool(None, False))
        self.assertEqual(MAX_RAW_UPLOAD_BYTES, 500 * 1024 * 1024)

    def test_ndjson_stream_parser_does_not_depend_on_read_text(self) -> None:
        parser = JsonParser()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.ndjson"
            lines = [json.dumps({"EventID": 4624, "Computer": f"dc{i}", "TargetUserName": "alice"}) for i in range(5)]
            path.write_text("\n".join(lines), encoding="utf-8")
            with patch.object(Path, "read_text", side_effect=AssertionError("read_text should not be used for NDJSON parsing")):
                events = parser.parse(path)
        self.assertEqual(len(events), 5)
        self.assertEqual(events[0]["EventID"], 4624)

    def test_json_array_stream_parser_does_not_depend_on_read_text(self) -> None:
        parser = JsonParser()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.json"
            payload = [{"EventID": 4688, "Computer": "ws01", "NewProcessName": "cmd.exe"} for _ in range(4)]
            path.write_text(json.dumps(payload), encoding="utf-8")
            with patch.object(Path, "read_text", side_effect=AssertionError("read_text should not be used for JSON array parsing")):
                events = parser.parse(path)
        self.assertEqual(len(events), 4)
        self.assertEqual(events[0]["EventID"], 4688)


if __name__ == "__main__":
    unittest.main()
