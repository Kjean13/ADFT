from __future__ import annotations

import importlib.util
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List

from adft.core.ingestion.loader import LogLoader
from adft.core.quality import QualityCollector

_SAFE_CHARS_RE = re.compile(r"[^A-Za-z0-9._-]+")


class CanonicalJsonlConverter:
    """Convert supported evidence formats into canonical JSONL files.

    The runtime uses JSONL as the single internal ingestion contract.
    Every supported source is parsed first, then re-emitted as canonical JSONL.
    """

    def __init__(self, loader: LogLoader | None = None) -> None:
        self._loader = loader or LogLoader()
        self._quality = QualityCollector("canonical_conversion")

    @staticmethod
    def _slug(text: str) -> str:
        clean = _SAFE_CHARS_RE.sub("_", text.strip())
        clean = clean.strip("._")
        return clean or "source"

    def _environment_snapshot(self) -> Dict[str, Any]:
        optional = {
            "python-evtx": bool(importlib.util.find_spec("Evtx")),
        }
        return {
            "optional_dependencies": optional,
            "registered_parsers": list(getattr(self._loader, "registered_parsers", [])),
        }

    def convert_inputs(self, inputs: Iterable[str | Path], output_dir: str | Path) -> Dict[str, Any]:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        entries: List[Dict[str, Any]] = []
        canonical_files: List[str] = []
        scanned_files = 0
        converted_files = 0
        skipped_files = 0
        failed_files = 0
        empty_files = 0
        total_events = 0

        for item in inputs:
            for source_file in self._loader.iter_input_files(item):
                scanned_files += 1
                result = self._loader.parse_file_status(source_file)
                parser_name = result.get("parser_name")
                status = result.get("status")
                events = list(result.get("events") or [])
                error = result.get("error")

                if status == "skipped" or parser_name is None:
                    skipped_files += 1
                    self._quality.warn(
                        "conversion_no_parser",
                        "Aucun parseur n'a reconnu ce fichier pour la conversion canonique.",
                        file=str(source_file),
                    )
                    entries.append(
                        {
                            "status": "skipped",
                            "source_path": str(source_file),
                            "source_extension": source_file.suffix.lower(),
                            "parser": None,
                            "canonical_path": None,
                            "canonical_format": "jsonl",
                            "events_written": 0,
                        }
                    )
                    continue

                if status == "failed":
                    failed_files += 1
                    self._quality.error(
                        "conversion_parser_failed",
                        "La source a été reconnue mais n'a pas pu être convertie vers JSONL canonique.",
                        file=str(source_file),
                        parser=str(parser_name),
                        error=str(error or ""),
                    )
                    entries.append(
                        {
                            "status": "failed",
                            "source_path": str(source_file),
                            "source_extension": source_file.suffix.lower(),
                            "parser": parser_name,
                            "canonical_path": None,
                            "canonical_format": "jsonl",
                            "events_written": 0,
                            "error": error,
                        }
                    )
                    continue

                if not events:
                    empty_files += 1
                    self._quality.warn(
                        "conversion_empty_source",
                        "La source a été lue mais n'a produit aucun événement exploitable.",
                        file=str(source_file),
                        parser=str(parser_name),
                    )
                    entries.append(
                        {
                            "status": "empty",
                            "source_path": str(source_file),
                            "source_extension": source_file.suffix.lower(),
                            "parser": parser_name,
                            "canonical_path": None,
                            "canonical_format": "jsonl",
                            "events_written": 0,
                        }
                    )
                    continue

                canonical_name = f"{converted_files + 1:04d}_{self._slug(source_file.stem)}.jsonl"
                canonical_path = out_dir / canonical_name
                written = self._write_canonical_file(
                    source_file=source_file,
                    parser_name=parser_name,
                    events=events,
                    canonical_path=canonical_path,
                )
                total_events += written
                converted_files += 1
                canonical_files.append(str(canonical_path))
                entries.append(
                    {
                        "status": "converted",
                        "source_path": str(source_file),
                        "source_extension": source_file.suffix.lower(),
                        "parser": parser_name,
                        "canonical_path": str(canonical_path),
                        "canonical_format": "jsonl",
                        "events_written": written,
                    }
                )

        manifest = {
            "canonical_format": "jsonl",
            "generated_at": datetime.now(UTC).isoformat(),
            "source_inputs": [str(Path(p)) for p in inputs],
            "canonical_files": canonical_files,
            "entries": entries,
            "environment": self._environment_snapshot(),
            "summary": {
                "files_scanned": scanned_files,
                "files_converted": converted_files,
                "files_failed": failed_files,
                "files_skipped": skipped_files,
                "files_empty": empty_files,
                "events_written": total_events,
            },
            "quality": self._quality.snapshot(),
        }
        manifest_path = out_dir / "conversion_manifest.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        manifest["manifest_path"] = str(manifest_path)
        return manifest

    def _write_canonical_file(
        self,
        *,
        source_file: Path,
        parser_name: str,
        events: List[Dict[str, Any]],
        canonical_path: Path,
    ) -> int:
        count = 0
        with canonical_path.open("w", encoding="utf-8") as handle:
            for event in events:
                payload = dict(event)
                payload.setdefault("_source_file", str(source_file))
                payload.setdefault("_parser", parser_name)
                payload["_canonical_format"] = "jsonl"
                payload["_source_extension"] = source_file.suffix.lower()
                payload["_conversion"] = {
                    "converter": parser_name,
                    "mode": "canonical-jsonl",
                    "canonical_path": str(canonical_path),
                }
                handle.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
                count += 1
        self._quality.incr("files_converted")
        self._quality.incr("events_written", count)
        return count

    @property
    def quality_report(self) -> Dict[str, Any]:
        return self._quality.snapshot()
