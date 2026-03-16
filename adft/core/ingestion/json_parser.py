from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TextIO

from adft.core.ingestion.base_parser import BaseParser
from adft.core.quality import QualityCollector


class JsonParser(BaseParser):
    CHUNK_SIZE = 1024 * 1024

    @property
    def parser_name(self) -> str:
        return "JSON Parser (SIEM Export / Winlogbeat)"

    def __init__(self) -> None:
        self._quality = QualityCollector("json_parser")

    def can_parse(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in (".json", ".jsonl", ".ndjson")

    def parse(self, file_path: Path) -> list[dict[str, Any]]:
        self._quality = QualityCollector("json_parser")
        suffix = file_path.suffix.lower()

        if suffix in (".jsonl", ".ndjson"):
            events = self._parse_ndjson_stream(file_path)
            self._quality.incr("ndjson_documents", 1)
        else:
            events = self._parse_json_document(file_path)

        for event in events:
            event.setdefault("_source_file", str(file_path))
            event.setdefault("_parser", self.parser_name)
            event["_canonical_source_file"] = str(file_path)

        self._quality.incr("events_extracted", len(events))
        return events

    def _parse_ndjson_stream(self, file_path: Path) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        # Utiliser utf-8-sig pour ignorer une éventuelle BOM UTF‑8
        # afin d'améliorer la robustesse face aux exports qui préfixent
        # leurs fichiers d'un marqueur d'ordre d'octet. Ce fallback
        # n'a aucun effet sur les fichiers UTF‑8 standards.
        with file_path.open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if isinstance(event, dict):
                        events.append(event)
                    else:
                        self._quality.warn(
                            "json_line_not_object",
                            "Ligne NDJSON ignorée car elle n'est pas un objet JSON.",
                            file=str(file_path),
                            line=line_number,
                        )
                except json.JSONDecodeError as exc:
                    self._quality.warn(
                        "json_line_invalid",
                        "Ligne NDJSON malformée ignorée.",
                        file=str(file_path),
                        line=line_number,
                        error=str(exc),
                    )
        return events

    def _parse_json_document(self, file_path: Path) -> list[dict[str, Any]]:
        # Lecture en utf-8-sig pour éliminer les BOM éventuelles
        with file_path.open("r", encoding="utf-8-sig") as handle:
            lead = self._peek_non_whitespace(handle)
            handle.seek(0)
            if lead == "[":
                events = self._parse_json_array_stream(handle, file_path)
                self._quality.incr("json_arrays_streamed", 1)
                return events
            parsed = json.load(handle)
            self._quality.incr("json_documents", 1)
            return self._extract_events(parsed)

    def _peek_non_whitespace(self, handle: TextIO) -> str:
        while True:
            char = handle.read(1)
            if not char:
                return ""
            if not char.isspace():
                return char

    def _parse_json_array_stream(self, handle: TextIO, file_path: Path) -> list[dict[str, Any]]:
        decoder = json.JSONDecoder()
        events: list[dict[str, Any]] = []
        buffer = ""
        started = False
        finished = False
        eof = False

        while not finished:
            if not eof and len(buffer) < self.CHUNK_SIZE // 2:
                chunk = handle.read(self.CHUNK_SIZE)
                if chunk:
                    buffer += chunk
                else:
                    eof = True

            while True:
                buffer = buffer.lstrip()
                if not buffer:
                    break
                if not started:
                    if buffer[0] != "[":
                        raise ValueError(f"Le fichier JSON {file_path} n'est pas un tableau JSON valide")
                    started = True
                    buffer = buffer[1:]
                    continue
                if buffer[0] == ",":
                    buffer = buffer[1:]
                    continue
                if buffer[0] == "]":
                    finished = True
                    buffer = buffer[1:]
                    break
                try:
                    event, consumed = decoder.raw_decode(buffer)
                except json.JSONDecodeError as exc:
                    if eof:
                        raise ValueError(f"Tableau JSON incomplet ou invalide dans {file_path}: {exc}") from exc
                    break
                if isinstance(event, dict):
                    events.append(event)
                else:
                    self._quality.warn(
                        "json_array_item_not_object",
                        "Élément de tableau JSON ignoré car il n'est pas un objet.",
                        file=str(file_path),
                    )
                buffer = buffer[consumed:]

            if eof and not buffer.strip():
                break
            if eof and buffer.strip() and not finished:
                raise ValueError(f"Fin de fichier inattendue pendant le parsing de {file_path}")

        trailing = buffer.strip()
        if trailing:
            self._quality.warn(
                "json_trailing_content",
                "Contenu supplémentaire ignoré après la fin du document JSON.",
                file=str(file_path),
            )
        return events

    def _extract_events(self, parsed: Any) -> list[dict[str, Any]]:
        if isinstance(parsed, list):
            return [e for e in parsed if isinstance(e, dict)]

        if isinstance(parsed, dict):
            if "Events" in parsed and isinstance(parsed["Events"], list):
                return [e for e in parsed["Events"] if isinstance(e, dict) and ("EventID" in e or "event_id" in e or "System" in e or "EventData" in e)]
            if "events" in parsed and isinstance(parsed["events"], list):
                return [e for e in parsed["events"] if isinstance(e, dict) and ("EventID" in e or "event_id" in e or "System" in e or "EventData" in e)]

            for key in ("records", "hits", "logs", "data"):
                if key in parsed and isinstance(parsed[key], list):
                    return [e for e in parsed[key] if isinstance(e, dict) and ("EventID" in e or "event_id" in e or "System" in e or "EventData" in e)]

            for key in ("result", "payload", "body"):
                if key in parsed and isinstance(parsed[key], dict):
                    inner = parsed[key]
                    for k2 in ("events", "Events", "records", "data", "logs"):
                        if k2 in inner and isinstance(inner[k2], list):
                            return [e for e in inner[k2] if isinstance(e, dict) and ("EventID" in e or "event_id" in e or "System" in e or "EventData" in e)]

            return [parsed]

        self._quality.warn("json_root_unsupported", "Structure JSON racine non supportée.")
        return []

    @property
    def quality_report(self) -> dict[str, Any]:
        return self._quality.snapshot()

    def pop_quality_report(self) -> dict[str, Any]:
        snap = self._quality.snapshot()
        self._quality = QualityCollector("json_parser")
        return snap
