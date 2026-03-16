"""
Parseurs multi-format pour les sources SOC.

Couvre les formats courants des terminaux qui communiquent avec un SOC :

- YAML / YML        : exports SIEM structurés, playbooks, configurations Sigma
- CSV / TSV         : exports tabulaires (Splunk, QRadar, ArcSight, osquery)
- CEF               : Common Event Format (ArcSight, McAfee ESM, Fortinet)
- LEEF              : Log Event Extended Format (IBM QRadar)
- XML               : Windows Event Forwarding (WEF), nmap, Nessus
- Syslog (RFC 3164/5424) : pare-feux, routeurs, appliances réseau
- Markdown tables   : rapports d'investigation manuels, documentation SOC
"""

from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from adft.core.ingestion.base_parser import BaseParser
from adft.core.quality import QualityCollector


# ---------------------------------------------------------------------------
# YAML Parser
# ---------------------------------------------------------------------------
class YamlParser(BaseParser):
    """Parse les fichiers YAML/YML (exports SIEM, Sigma, playbooks)."""

    @property
    def parser_name(self) -> str:
        return "YAML Parser (SIEM Export / Sigma)"

    def __init__(self) -> None:
        self._quality = QualityCollector("yaml_parser")

    def can_parse(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in (".yaml", ".yml")

    def parse(self, file_path: Path) -> list[dict[str, Any]]:
        self._quality = QualityCollector("yaml_parser")
        try:
            import yaml
        except ImportError:
            raise ImportError(
                "PyYAML est requis pour parser les fichiers YAML. "
                "Installez-le avec : pip install pyyaml"
            )

        content = file_path.read_text(encoding="utf-8")
        events: list[dict[str, Any]] = []

        # YAML peut contenir plusieurs documents (---)
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError as exc:
            self._quality.error(
                "yaml_parse_error",
                "Fichier YAML malformé.",
                file=str(file_path),
                error=str(exc),
            )
            return []

        for doc_idx, doc in enumerate(docs):
            if doc is None:
                continue
            extracted = self._extract_events(doc, file_path, doc_idx)
            events.extend(extracted)

        for event in events:
            event["_source_file"] = str(file_path)
            event["_parser"] = self.parser_name

        self._quality.incr("events_extracted", len(events))
        return events

    def _extract_events(
        self, doc: Any, file_path: Path, doc_idx: int
    ) -> list[dict[str, Any]]:
        if isinstance(doc, list):
            return [e for e in doc if isinstance(e, dict)]

        if isinstance(doc, dict):
            # Sigma rule : extraire les métadonnées de détection
            if "detection" in doc and "logsource" in doc:
                return [self._sigma_to_event(doc)]

            # Wrapper courant : events, records, data, logs, hits
            for key in ("events", "Events", "records", "data", "logs", "hits"):
                if key in doc and isinstance(doc[key], list):
                    return [e for e in doc[key] if isinstance(e, dict)]

            # Document unique = un événement
            return [doc]

        return []

    @staticmethod
    def _sigma_to_event(sigma: dict[str, Any]) -> dict[str, Any]:
        """Convertit une règle Sigma en pseudo-événement pour traçabilité."""
        logsource = sigma.get("logsource", {})
        detection = sigma.get("detection", {})
        return {
            "EventID": 0,
            "_sigma_rule": True,
            "title": sigma.get("title", ""),
            "description": sigma.get("description", ""),
            "level": sigma.get("level", ""),
            "logsource_product": logsource.get("product", ""),
            "logsource_service": logsource.get("service", ""),
            "logsource_category": logsource.get("category", ""),
            "detection_raw": json.dumps(detection, default=str),
            "tags": sigma.get("tags", []),
            "references": sigma.get("references", []),
        }

    @property
    def quality_report(self) -> dict[str, Any]:
        return self._quality.snapshot()

    def pop_quality_report(self) -> dict[str, Any]:
        snap = self._quality.snapshot()
        self._quality = QualityCollector("yaml_parser")
        return snap


# ---------------------------------------------------------------------------
# CSV / TSV Parser
# ---------------------------------------------------------------------------
class CsvParser(BaseParser):
    """Parse les fichiers CSV/TSV (exports Splunk, QRadar, ArcSight, osquery)."""

    @property
    def parser_name(self) -> str:
        return "CSV/TSV Parser (Tabular SIEM Export)"

    def __init__(self) -> None:
        self._quality = QualityCollector("csv_parser")

    def can_parse(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in (".csv", ".tsv")

    def parse(self, file_path: Path) -> list[dict[str, Any]]:
        self._quality = QualityCollector("csv_parser")
        content = file_path.read_text(encoding="utf-8", errors="replace")
        events: list[dict[str, Any]] = []

        delimiter = "\t" if file_path.suffix.lower() == ".tsv" else ","

        try:
            # Détection automatique du dialecte
            sample = content[:8192]
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
                delimiter = dialect.delimiter
            except csv.Error:
                pass

            reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)
            for row_idx, row in enumerate(reader):
                event = self._normalize_row(dict(row), row_idx)
                if event:
                    event["_source_file"] = str(file_path)
                    event["_parser"] = self.parser_name
                    events.append(event)
        except Exception as exc:
            self._quality.error(
                "csv_parse_error",
                "Erreur de parsing CSV/TSV.",
                file=str(file_path),
                error=str(exc),
            )

        self._quality.incr("events_extracted", len(events))
        return events

    def _normalize_row(
        self, row: dict[str, Any], row_idx: int
    ) -> Optional[dict[str, Any]]:
        """Normalise les clés CSV courantes vers le schéma ADFT."""
        if not any(row.values()):
            return None

        # Tenter de convertir EventID en int
        for key in ("EventID", "event_id", "EventCode", "event.code", "eventid"):
            val = row.get(key)
            if val is not None:
                try:
                    row["EventID"] = int(val)
                    break
                except (ValueError, TypeError):
                    continue

        # Mapper les noms de colonnes courants
        mappings = {
            "Time": "TimeCreated",
            "time": "TimeCreated",
            "_time": "TimeCreated",
            "Timestamp": "TimeCreated",
            "timestamp": "TimeCreated",
            "Date": "TimeCreated",
            "date": "TimeCreated",
            "DateTime": "TimeCreated",
            "datetime": "TimeCreated",
            "ComputerName": "Computer",
            "computer_name": "Computer",
            "host": "Computer",
            "Host": "Computer",
            "hostname": "Computer",
            "src_host": "WorkstationName",
            "SourceIP": "IpAddress",
            "src_ip": "IpAddress",
            "source_ip": "IpAddress",
            "ClientIP": "IpAddress",
            "UserName": "TargetUserName",
            "user": "TargetUserName",
            "User": "TargetUserName",
            "username": "TargetUserName",
            "Account": "TargetUserName",
            "account_name": "TargetUserName",
            "Message": "Message",
            "message": "Message",
            "msg": "Message",
            "Description": "Message",
        }
        for src, dst in mappings.items():
            if src in row and dst not in row:
                row[dst] = row[src]

        return row

    @property
    def quality_report(self) -> dict[str, Any]:
        return self._quality.snapshot()

    def pop_quality_report(self) -> dict[str, Any]:
        snap = self._quality.snapshot()
        self._quality = QualityCollector("csv_parser")
        return snap


# ---------------------------------------------------------------------------
# CEF Parser (Common Event Format)
# ---------------------------------------------------------------------------
_CEF_RE = re.compile(
    r"(?:.*?\s)?CEF:\s*(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)"
)
_CEF_EXT_RE = re.compile(r"(\w+)=((?:[^=](?!(?:\s\w+=)))*[^=]?)")


class CefParser(BaseParser):
    """Parse les fichiers CEF (ArcSight, McAfee ESM, Fortinet, etc.)."""

    @property
    def parser_name(self) -> str:
        return "CEF Parser (Common Event Format)"

    def __init__(self) -> None:
        self._quality = QualityCollector("cef_parser")

    def can_parse(self, file_path: Path) -> bool:
        if file_path.suffix.lower() not in (".cef", ".log", ".txt"):
            return False
        try:
            head = file_path.read_text(encoding="utf-8", errors="replace")[:2048]
            return "CEF:" in head
        except (IOError, OSError):
            return False

    def parse(self, file_path: Path) -> list[dict[str, Any]]:
        self._quality = QualityCollector("cef_parser")
        content = file_path.read_text(encoding="utf-8", errors="replace")
        events: list[dict[str, Any]] = []

        for line_num, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            m = _CEF_RE.match(line)
            if not m:
                continue

            event: dict[str, Any] = {
                "cef_version": m.group(1),
                "DeviceVendor": m.group(2),
                "DeviceProduct": m.group(3),
                "DeviceVersion": m.group(4),
                "SignatureID": m.group(5),
                "Name": m.group(6),
                "Severity": m.group(7),
            }

            # Parse extensions
            ext_str = m.group(8)
            for ext_m in _CEF_EXT_RE.finditer(ext_str):
                event[ext_m.group(1)] = ext_m.group(2).strip()

            # Map CEF vers schéma ADFT
            self._map_cef_fields(event)
            event["_source_file"] = str(file_path)
            event["_parser"] = self.parser_name
            events.append(event)

        self._quality.incr("events_extracted", len(events))
        return events

    @staticmethod
    def _map_cef_fields(event: dict[str, Any]) -> None:
        mappings = {
            "src": "IpAddress",
            "dst": "TargetServerAddress",
            "suser": "SubjectUserName",
            "duser": "TargetUserName",
            "shost": "WorkstationName",
            "dhost": "Computer",
            "rt": "TimeCreated",
            "end": "TimeCreated",
            "start": "TimeCreated",
            "act": "Message",
            "msg": "Message",
            "deviceEventClassId": "EventID",
            "cn1": "EventID",
            "fname": "ProcessName",
            "sproc": "ProcessName",
            "dproc": "NewProcessName",
            "cs1": "ServiceName",
        }
        for src, dst in mappings.items():
            if src in event and dst not in event:
                event[dst] = event[src]

        # Tenter de convertir EventID
        for key in ("EventID", "SignatureID"):
            val = event.get(key)
            if val is not None:
                try:
                    event["EventID"] = int(val)
                    break
                except (ValueError, TypeError):
                    continue

    @property
    def quality_report(self) -> dict[str, Any]:
        return self._quality.snapshot()

    def pop_quality_report(self) -> dict[str, Any]:
        snap = self._quality.snapshot()
        self._quality = QualityCollector("cef_parser")
        return snap


# ---------------------------------------------------------------------------
# LEEF Parser (IBM QRadar)
# ---------------------------------------------------------------------------
_LEEF_RE = re.compile(
    r"(?:.*?\s)?LEEF:(\d+(?:\.\d+)?)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)"
)


class LeefParser(BaseParser):
    """Parse les fichiers LEEF (IBM QRadar)."""

    @property
    def parser_name(self) -> str:
        return "LEEF Parser (IBM QRadar)"

    def __init__(self) -> None:
        self._quality = QualityCollector("leef_parser")

    def can_parse(self, file_path: Path) -> bool:
        if file_path.suffix.lower() not in (".leef", ".log", ".txt"):
            return False
        try:
            head = file_path.read_text(encoding="utf-8", errors="replace")[:2048]
            return "LEEF:" in head
        except (IOError, OSError):
            return False

    def parse(self, file_path: Path) -> list[dict[str, Any]]:
        self._quality = QualityCollector("leef_parser")
        content = file_path.read_text(encoding="utf-8", errors="replace")
        events: list[dict[str, Any]] = []

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _LEEF_RE.match(line)
            if not m:
                continue

            event: dict[str, Any] = {
                "leef_version": m.group(1),
                "DeviceVendor": m.group(2),
                "DeviceProduct": m.group(3),
                "DeviceVersion": m.group(4),
                "EventID_raw": m.group(5),
            }

            # Parse key=value pairs (tab-separated in LEEF)
            sep = "\t"
            ext = m.group(6)
            if "\t" not in ext and "=" in ext:
                sep = " "
            for pair in ext.split(sep):
                pair = pair.strip()
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    event[k.strip()] = v.strip()

            # Map LEEF
            leef_map = {
                "src": "IpAddress",
                "dst": "TargetServerAddress",
                "usrName": "TargetUserName",
                "srcHostName": "WorkstationName",
                "dstHostName": "Computer",
                "devTime": "TimeCreated",
                "sev": "Severity",
            }
            for src, dst in leef_map.items():
                if src in event and dst not in event:
                    event[dst] = event[src]

            try:
                event["EventID"] = int(event.get("EventID_raw", 0))
            except (ValueError, TypeError):
                event["EventID"] = 0

            event["_source_file"] = str(file_path)
            event["_parser"] = self.parser_name
            events.append(event)

        self._quality.incr("events_extracted", len(events))
        return events

    @property
    def quality_report(self) -> dict[str, Any]:
        return self._quality.snapshot()

    def pop_quality_report(self) -> dict[str, Any]:
        snap = self._quality.snapshot()
        self._quality = QualityCollector("leef_parser")
        return snap


# ---------------------------------------------------------------------------
# XML Parser (WEF, Nmap, Nessus)
# ---------------------------------------------------------------------------
class XmlEventParser(BaseParser):
    """Parse les fichiers XML (Windows Event Forwarding, exports WEF, Nmap)."""

    @property
    def parser_name(self) -> str:
        return "XML Parser (WEF / Event Log Export)"

    def __init__(self) -> None:
        self._quality = QualityCollector("xml_parser")

    def can_parse(self, file_path: Path) -> bool:
        if file_path.suffix.lower() != ".xml":
            return False
        try:
            head = file_path.read_bytes()[:512]
            return b"<Event" in head or b"<Events" in head or b"<?xml" in head
        except (IOError, OSError):
            return False

    def parse(self, file_path: Path) -> list[dict[str, Any]]:
        self._quality = QualityCollector("xml_parser")
        events: list[dict[str, Any]] = []

        try:
            tree = ET.parse(str(file_path))
            root = tree.getroot()
        except ET.ParseError as exc:
            self._quality.error(
                "xml_parse_error",
                "Fichier XML malformé.",
                file=str(file_path),
                error=str(exc),
            )
            return []

        # Supprimer les namespaces pour simplifier l'extraction
        ns_re = re.compile(r"\{[^}]+\}")

        def strip_ns(tag: str) -> str:
            return ns_re.sub("", tag)

        # Chercher tous les <Event> ou traiter la racine comme un Event
        event_elements = root.findall(".//{*}Event")
        if not event_elements:
            event_elements = root.findall(".//Event")
        if not event_elements and strip_ns(root.tag) == "Event":
            event_elements = [root]
        if not event_elements:
            # Fallback : traiter chaque enfant direct comme un événement
            event_elements = list(root)

        for elem in event_elements:
            event = self._element_to_dict(elem, ns_re)
            if event:
                event["_source_file"] = str(file_path)
                event["_parser"] = self.parser_name
                events.append(event)

        self._quality.incr("events_extracted", len(events))
        return events

    def _element_to_dict(
        self, elem: ET.Element, ns_re: re.Pattern
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}

        # System
        system = elem.find("{*}System")
        if system is None:
            system = elem.find("System")
        if system is not None:
            eid = system.find("{*}EventID")
            if eid is None:
                eid = system.find("EventID")
            if eid is not None and eid.text:
                try:
                    result["EventID"] = int(eid.text)
                except ValueError:
                    pass
            tc = system.find("{*}TimeCreated")
            if tc is None:
                tc = system.find("TimeCreated")
            if tc is not None:
                result["TimeCreated"] = tc.attrib.get(
                    "SystemTime", tc.text or ""
                )
            comp = system.find("{*}Computer")
            if comp is None:
                comp = system.find("Computer")
            if comp is not None and comp.text:
                result["Computer"] = comp.text

        # EventData
        evdata = elem.find("{*}EventData")
        if evdata is None:
            evdata = elem.find("EventData")
        if evdata is not None:
            for data in evdata:
                name = data.attrib.get("Name")
                if name:
                    result[name] = data.text or ""

        # Fallback : attributs et enfants directs
        if not result:
            for child in elem:
                tag = ns_re.sub("", child.tag)
                if child.text and child.text.strip():
                    result[tag] = child.text.strip()
                for k, v in child.attrib.items():
                    result[f"{tag}.{k}"] = v

        return result

    @property
    def quality_report(self) -> dict[str, Any]:
        return self._quality.snapshot()

    def pop_quality_report(self) -> dict[str, Any]:
        snap = self._quality.snapshot()
        self._quality = QualityCollector("xml_parser")
        return snap


# ---------------------------------------------------------------------------
# Syslog Parser (RFC 3164 / 5424)
# ---------------------------------------------------------------------------
_SYSLOG_3164_RE = re.compile(
    r"^<(\d{1,3})>"
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(\S+)\s+"
    r"(\S+?)(?:\[(\d+)\])?:\s*(.*)"
)
_SYSLOG_5424_RE = re.compile(
    r"^<(\d{1,3})>\d?\s*"
    r"(\d{4}-\d{2}-\d{2}T\S+)\s+"
    r"(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+"
    r"(?:\[([^\]]*)\]\s*)?(.*)"
)


class SyslogParser(BaseParser):
    """Parse les fichiers syslog (pare-feux, routeurs, Linux, appliances)."""

    @property
    def parser_name(self) -> str:
        return "Syslog Parser (RFC 3164/5424)"

    def __init__(self) -> None:
        self._quality = QualityCollector("syslog_parser")

    def can_parse(self, file_path: Path) -> bool:
        if file_path.suffix.lower() not in (".log", ".syslog", ".txt"):
            return False
        try:
            head = file_path.read_text(encoding="utf-8", errors="replace")[:2048]
            # Doit commencer par <priority>
            return bool(re.search(r"^<\d{1,3}>", head, re.MULTILINE))
        except (IOError, OSError):
            return False

    def parse(self, file_path: Path) -> list[dict[str, Any]]:
        self._quality = QualityCollector("syslog_parser")
        content = file_path.read_text(encoding="utf-8", errors="replace")
        events: list[dict[str, Any]] = []

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue

            event = self._parse_line(line)
            if event:
                event["_source_file"] = str(file_path)
                event["_parser"] = self.parser_name
                events.append(event)

        self._quality.incr("events_extracted", len(events))
        return events

    def _parse_line(self, line: str) -> Optional[dict[str, Any]]:
        # RFC 5424
        m = _SYSLOG_5424_RE.match(line)
        if m:
            return {
                "priority": int(m.group(1)),
                "TimeCreated": m.group(2),
                "Computer": m.group(3),
                "ProviderName": m.group(4),
                "ProcessID": m.group(5),
                "MessageID": m.group(6),
                "StructuredData": m.group(7) or "",
                "Message": m.group(8),
                "EventID": 0,
            }

        # RFC 3164
        m = _SYSLOG_3164_RE.match(line)
        if m:
            # Ajouter l'annee courante au timestamp BSD
            ts_raw = m.group(2)
            year = datetime.now(tz=timezone.utc).year
            try:
                ts = datetime.strptime(
                    f"{year} {ts_raw}", "%Y %b %d %H:%M:%S"
                ).replace(tzinfo=timezone.utc)
                ts_str = ts.isoformat()
            except ValueError:
                ts_str = ts_raw

            return {
                "priority": int(m.group(1)),
                "TimeCreated": ts_str,
                "Computer": m.group(3),
                "ProviderName": m.group(4),
                "ProcessID": m.group(5) or "",
                "Message": m.group(6),
                "EventID": 0,
            }

        return None

    @property
    def quality_report(self) -> dict[str, Any]:
        return self._quality.snapshot()

    def pop_quality_report(self) -> dict[str, Any]:
        snap = self._quality.snapshot()
        self._quality = QualityCollector("syslog_parser")
        return snap


# ---------------------------------------------------------------------------
# Markdown Table Parser
# ---------------------------------------------------------------------------
_MD_TABLE_ROW = re.compile(r"^\|(.+)\|$")
_MD_SEPARATOR = re.compile(r"^[\|\s\-:]+$")


class MarkdownTableParser(BaseParser):
    """Parse les tableaux Markdown (rapports d'investigation, documentation SOC)."""

    @property
    def parser_name(self) -> str:
        return "Markdown Table Parser (SOC Documentation)"

    def __init__(self) -> None:
        self._quality = QualityCollector("markdown_parser")

    def can_parse(self, file_path: Path) -> bool:
        if file_path.suffix.lower() not in (".md", ".markdown"):
            return False
        try:
            head = file_path.read_text(encoding="utf-8", errors="replace")[:4096]
            # Doit contenir au moins une ligne de tableau avec pipe
            return bool(re.search(r"^\|.*\|.*\|$", head, re.MULTILINE))
        except (IOError, OSError):
            return False

    def parse(self, file_path: Path) -> list[dict[str, Any]]:
        self._quality = QualityCollector("markdown_parser")
        content = file_path.read_text(encoding="utf-8", errors="replace")
        events: list[dict[str, Any]] = []
        lines = content.splitlines()

        i = 0
        while i < len(lines):
            # Chercher un header de tableau
            header_match = _MD_TABLE_ROW.match(lines[i].strip())
            if header_match and i + 1 < len(lines) and _MD_SEPARATOR.match(
                lines[i + 1].strip()
            ):
                headers = [
                    h.strip() for h in header_match.group(1).split("|")
                ]
                i += 2  # Sauter header + separateur

                while i < len(lines):
                    row_match = _MD_TABLE_ROW.match(lines[i].strip())
                    if not row_match:
                        break
                    cells = [
                        c.strip() for c in row_match.group(1).split("|")
                    ]
                    event: dict[str, Any] = {}
                    for j, header in enumerate(headers):
                        if j < len(cells) and header:
                            event[header] = cells[j]
                    if event:
                        # Mapper les colonnes courantes
                        self._map_md_fields(event)
                        event["_source_file"] = str(file_path)
                        event["_parser"] = self.parser_name
                        events.append(event)
                    i += 1
            else:
                i += 1

        self._quality.incr("events_extracted", len(events))
        return events

    @staticmethod
    def _map_md_fields(event: dict[str, Any]) -> None:
        mappings = {
            "Event ID": "EventID",
            "EventID": "EventID",
            "event_id": "EventID",
            "Timestamp": "TimeCreated",
            "Time": "TimeCreated",
            "Date": "TimeCreated",
            "Host": "Computer",
            "Computer": "Computer",
            "Hostname": "Computer",
            "User": "TargetUserName",
            "Username": "TargetUserName",
            "Account": "TargetUserName",
            "IP": "IpAddress",
            "Source IP": "IpAddress",
            "Severity": "Severity",
            "Description": "Message",
            "Action": "Message",
        }
        for src, dst in mappings.items():
            if src in event and dst not in event:
                event[dst] = event[src]

        # Tenter de convertir EventID en int
        val = event.get("EventID")
        if val is not None:
            try:
                event["EventID"] = int(val)
            except (ValueError, TypeError):
                pass

    @property
    def quality_report(self) -> dict[str, Any]:
        return self._quality.snapshot()

    def pop_quality_report(self) -> dict[str, Any]:
        snap = self._quality.snapshot()
        self._quality = QualityCollector("markdown_parser")
        return snap
