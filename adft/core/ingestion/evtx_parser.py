
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from adft.core.ingestion.base_parser import BaseParser
from adft.core.quality import QualityCollector

_EVTX_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


class EvtxParser(BaseParser):
    @property
    def parser_name(self) -> str:
        return "EVTX Parser (Windows Event Log)"

    def __init__(self) -> None:
        self._quality = QualityCollector("evtx_parser")

    def can_parse(self, file_path: Path) -> bool:
        if file_path.suffix.lower() != ".evtx":
            return False
        try:
            with open(file_path, "rb") as f:
                magic = f.read(8)
                return magic[:7] == b"ElfFile"
        except (IOError, OSError):
            return False

    def parse(self, file_path: Path) -> list[dict[str, Any]]:
        self._quality = QualityCollector("evtx_parser")
        events: list[dict[str, Any]] = []

        try:
            import Evtx.Evtx as evtx
        except ImportError:
            raise ImportError(
                "La bibliothèque python-evtx est requise pour parser les fichiers EVTX. Installez-la avec : pip install python-evtx"
            )

        with evtx.Evtx(str(file_path)) as log:
            for idx, record in enumerate(log.records(), start=1):
                try:
                    xml_content = record.xml()
                    event_dict = self._xml_to_dict(xml_content)
                    event_dict["_source_file"] = str(file_path)
                    event_dict["_parser"] = self.parser_name
                    events.append(event_dict)
                except Exception as exc:
                    self._quality.warn(
                        "evtx_record_skipped",
                        "Enregistrement EVTX corrompu ou illisible ignoré.",
                        file=str(file_path),
                        record_index=idx,
                        error=str(exc),
                    )
        self._quality.incr("events_extracted", len(events))
        return events

    def _xml_to_dict(self, xml_string: str) -> dict[str, Any]:
        root = ET.fromstring(xml_string)
        event: dict[str, Any] = {}

        system = root.find(f"{_EVTX_NS}System")
        if system is not None:
            event_id_elem = system.find(f"{_EVTX_NS}EventID")
            if event_id_elem is not None and event_id_elem.text:
                event["EventID"] = int(event_id_elem.text)

            time_elem = system.find(f"{_EVTX_NS}TimeCreated")
            if time_elem is not None and time_elem.attrib.get("SystemTime"):
                event["TimeCreated"] = time_elem.attrib["SystemTime"]

            computer = system.find(f"{_EVTX_NS}Computer")
            if computer is not None and computer.text:
                event["Computer"] = computer.text

        eventdata = root.find(f"{_EVTX_NS}EventData")
        if eventdata is not None:
            for data in eventdata.findall(f"{_EVTX_NS}Data"):
                name = data.attrib.get("Name")
                if name:
                    event[name] = data.text or ""

        return event

    @property
    def quality_report(self) -> dict[str, Any]:
        return self._quality.snapshot()

    def pop_quality_report(self) -> dict[str, Any]:
        snap = self._quality.snapshot()
        self._quality = QualityCollector("evtx_parser")
        return snap
