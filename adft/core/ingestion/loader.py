from __future__ import annotations

from pathlib import Path
from typing import Any

from adft.core.ingestion.base_parser import BaseParser
from adft.core.ingestion.evtx_parser import EvtxParser
from adft.core.ingestion.json_parser import JsonParser
from adft.core.ingestion.zip_parser import ZipParser
from adft.core.ingestion.soc_parsers import (
    CefParser,
    CsvParser,
    LeefParser,
    MarkdownTableParser,
    SyslogParser,
    XmlEventParser,
    YamlParser,
)
from adft.core.quality import QualityCollector


class LogLoader:
    """Charge et dispatche les fichiers de log vers le parseur adapte.

    Parseurs enregistres par defaut (ordre de priorite) :

    1.  EVTX        — logs Windows natifs (.evtx)
    2.  JSON/JSONL  — exports SIEM, Winlogbeat (.json, .jsonl, .ndjson)
    3.  YAML        — exports structures, regles Sigma (.yaml, .yml)
    4.  CSV / TSV   — exports tabulaires Splunk, QRadar, osquery (.csv, .tsv)
    5.  CEF         — Common Event Format (.cef, .log, .txt avec header CEF)
    6.  LEEF        — IBM QRadar (.leef, .log, .txt avec header LEEF)
    7.  XML         — WEF, exports Event Viewer (.xml)
    8.  Syslog      — RFC 3164 / 5424 (.syslog, .log, .txt avec <priority>)
    9.  Markdown    — tableaux d'investigation (.md, .markdown)
    10. ZIP         — archives récursives (délègue vers les parseurs 1-9)
    """

    def __init__(self) -> None:
        self._parsers: list[BaseParser] = []
        self._stats: dict[str, int] = {
            "files_scanned": 0,
            "files_parsed": 0,
            "files_skipped": 0,
            "files_failed": 0,
            "events_loaded": 0,
        }
        self._quality = QualityCollector("ingestion")

        # Parseurs principaux (Windows / SIEM)
        self.register_parser(EvtxParser())
        self.register_parser(JsonParser())

        # Parseurs SOC multi-format
        self.register_parser(YamlParser())
        self.register_parser(CsvParser())
        self.register_parser(CefParser())
        self.register_parser(LeefParser())
        self.register_parser(XmlEventParser())
        self.register_parser(SyslogParser())
        self.register_parser(MarkdownTableParser())

        # ZIP en dernier : délègue vers tous les parseurs ci-dessus
        self._zip_parser = ZipParser()
        self._zip_parser.set_parsers(self._parsers)
        self.register_parser(self._zip_parser)

    def register_parser(self, parser: BaseParser) -> None:
        self._parsers.append(parser)
        # Mettre à jour le ZipParser si déjà instancié et que ce n'est pas lui-même
        if hasattr(self, "_zip_parser") and parser is not self._zip_parser:
            self._zip_parser.set_parsers(self._parsers)

    def iter_input_files(self, path: str | Path) -> list[Path]:
        target = Path(path)
        if not target.exists():
            raise FileNotFoundError(
                f"Chemin introuvable : {target}\n"
                f"Vérifiez que le répertoire ou fichier de logs existe."
            )
        return [target] if target.is_file() else [p for p in sorted(target.rglob("*")) if p.is_file()]

    def parse_file_status(self, file_path: str | Path) -> dict[str, Any]:
        file_path = Path(file_path)
        self._stats["files_scanned"] += 1

        for parser in self._parsers:
            if not parser.can_parse(file_path):
                continue
            parser_name = getattr(parser, "parser_name", parser.__class__.__name__)
            try:
                events = parser.parse(file_path)
                self._stats["files_parsed"] += 1
                self._stats["events_loaded"] += len(events)
                self._quality.extend(parser.pop_quality_report())
                return {
                    "status": "parsed",
                    "events": events,
                    "parser_name": parser_name,
                    "error": None,
                    "exception": None,
                }
            except Exception as exc:
                self._stats["files_failed"] += 1
                self._stats["files_skipped"] += 1
                self._quality.error(
                    "parser_failed",
                    "Le fichier a été reconnu mais n'a pas pu être parsé.",
                    file=str(file_path),
                    parser=parser_name,
                    error=str(exc),
                )
                self._quality.extend(parser.pop_quality_report())
                return {
                    "status": "failed",
                    "events": [],
                    "parser_name": parser_name,
                    "error": str(exc),
                    "exception": exc,
                }

        self._stats["files_skipped"] += 1
        self._quality.warn(
            "no_parser_matched",
            "Aucun parseur compatible trouvé pour ce fichier.",
            file=str(file_path),
        )
        return {
            "status": "skipped",
            "events": [],
            "parser_name": None,
            "error": None,
            "exception": None,
        }

    def parse_file(self, file_path: str | Path, *, raise_on_error: bool = True) -> tuple[list[dict[str, Any]], str | None]:
        result = self.parse_file_status(file_path)
        if result["status"] == "failed" and raise_on_error:
            exc = result.get("exception")
            if isinstance(exc, Exception):
                raise exc
            raise RuntimeError(result.get("error") or "Erreur de parsing inconnue")
        return list(result.get("events") or []), result.get("parser_name")

    def load(self, path: str | Path) -> list[dict[str, Any]]:
        all_events: list[dict[str, Any]] = []
        for file_path in self.iter_input_files(path):
            events, _ = self.parse_file(file_path)
            all_events.extend(events)
        return all_events

    @property
    def stats(self) -> dict[str, int]:
        data = dict(self._stats)
        data.update(self._quality.snapshot().get("stats", {}))
        return data

    @property
    def quality_report(self) -> dict[str, Any]:
        snap = self._quality.snapshot()
        snap["stats"] = {**self._stats, **(snap.get("stats") or {})}
        return snap

    @property
    def registered_parsers(self) -> list[str]:
        return [p.parser_name for p in self._parsers]
