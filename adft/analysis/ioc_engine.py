"""IOC Engine — Ingestion et croisement d'indicateurs de compromission.

Formats supportés : JSON, CSV, TXT (un IOC par ligne), STIX 2.x (JSON).

Types d'IOC : ip, domain, md5, sha1, sha256, url, email, cve.

Usage:
    engine = IOCEngine()
    engine.load_file("threat_feed.csv")
    engine.load_file("stix_bundle.json")

    matches = engine.match_events(normalized_events)
    matches = engine.match_entities(["192.168.1.5", "evil.com"])
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# IOC Types
# ---------------------------------------------------------------------------

class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    URL = "url"
    EMAIL = "email"
    CVE = "cve"
    UNKNOWN = "unknown"


@dataclass
class IOC:
    value: str
    ioc_type: IOCType
    source: str = ""
    description: str = ""
    confidence: float = 1.0
    tags: list[str] = field(default_factory=list)
    tlp: str = "WHITE"

    @property
    def normalized(self) -> str:
        v = self.value.strip().lower()
        if self.ioc_type == IOCType.URL:
            return v
        if self.ioc_type == IOCType.DOMAIN:
            return v.lstrip("*.")
        return v


@dataclass
class IOCMatch:
    ioc: IOC
    entity: str
    match_type: str     # "exact", "domain_contains", "url_contains"
    source_event_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Detectors / patterns
# ---------------------------------------------------------------------------

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV6_RE = re.compile(r"^[0-9a-f:]{3,39}$", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9\-_]+\.)+[a-z]{2,}$", re.IGNORECASE)
_MD5_RE = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)
_SHA1_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _infer_type(value: str) -> IOCType:
    v = value.strip()
    if _CVE_RE.match(v):
        return IOCType.CVE
    if _URL_RE.match(v):
        return IOCType.URL
    if _EMAIL_RE.match(v):
        return IOCType.EMAIL
    if _SHA256_RE.match(v):
        return IOCType.SHA256
    if _SHA1_RE.match(v):
        return IOCType.SHA1
    if _MD5_RE.match(v):
        return IOCType.MD5
    if _IP_RE.match(v) or _IPV6_RE.match(v):
        try:
            ipaddress.ip_address(v)
            return IOCType.IP
        except ValueError:
            pass
    if _DOMAIN_RE.match(v):
        return IOCType.DOMAIN
    return IOCType.UNKNOWN


# ---------------------------------------------------------------------------
# Main Engine
# ---------------------------------------------------------------------------

class IOCEngine:
    """Moteur d'ingestion et de croisement d'IOCs."""

    def __init__(self) -> None:
        # Indices par type pour match rapide
        self._iocs: list[IOC] = []
        self._index: dict[IOCType, set[str]] = {t: set() for t in IOCType}
        self._ioc_map: dict[str, IOC] = {}  # normalized value → IOC (last wins)

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def load_file(self, path: str | Path, source: str = "") -> int:
        """Charge les IOCs depuis un fichier (auto-détecte le format)."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"IOC file not found: {p}")

        src = source or p.name
        raw_content = p.read_bytes()

        # Détection de format
        text = raw_content.decode("utf-8-sig", errors="replace")
        ext = p.suffix.lower()

        if ext == ".json" or (text.lstrip().startswith("{") and '"type"' in text[:200]):
            count = self._load_json(text, src)
        elif ext in (".csv", ".tsv"):
            count = self._load_csv(text, src, delimiter="\t" if ext == ".tsv" else ",")
        else:
            count = self._load_txt(text, src)

        return count

    def load_raw(self, iocs: list[IOC]) -> None:
        """Injecter des IOCs directement."""
        for ioc in iocs:
            self._register(ioc)

    def load_text(self, text: str, source: str = "inline") -> int:
        """Charger depuis une chaîne brute (un IOC par ligne)."""
        return self._load_txt(text, source)

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def match_entities(self, entities: list[str]) -> list[IOCMatch]:
        """Croiser une liste de valeurs (users, IPs, hosts, hashes) avec les IOCs."""
        matches: list[IOCMatch] = []
        for entity in entities:
            e = entity.strip().lower()
            if not e:
                continue
            m = self._match_value(e)
            if m:
                matches.append(m)
        return matches

    def match_events(self, events: Any) -> list[IOCMatch]:
        """Croiser les événements normalisés avec les IOCs.

        Extrait automatiquement : ip_address, source_host, target_host, user,
        process_name, service_name et les valeurs hash du raw_event.
        """
        from adft.core.models.events import NormalizedEvent  # lazy import

        matches: list[IOCMatch] = []
        for ev in events:
            if not isinstance(ev, NormalizedEvent):
                continue
            candidates = [
                ev.ip_address,
                ev.source_host,
                ev.target_host,
                ev.user,
                ev.process_name,
                getattr(ev, "service_name", None),
            ]
            raw = ev.raw_event or {}
            for hash_key in ("Hashes", "Hash", "MD5", "SHA256", "SHA1", "FileHash"):
                v = raw.get(hash_key)
                if v:
                    # "MD5=abc...,SHA256=def..." format
                    for part in str(v).replace(",", " ").split():
                        if "=" in part:
                            candidates.append(part.split("=", 1)[1])
                        else:
                            candidates.append(part)

            for c in candidates:
                if not c:
                    continue
                m = self._match_value(str(c).strip().lower())
                if m:
                    m.source_event_id = ev.id
                    matches.append(m)

        return matches

    # ------------------------------------------------------------------
    # Stats / introspection
    # ------------------------------------------------------------------

    @property
    def stats(self) -> dict[str, Any]:
        by_type: dict[str, int] = {}
        for t in IOCType:
            cnt = len(self._index[t])
            if cnt:
                by_type[t.value] = cnt
        return {
            "total_iocs": len(self._iocs),
            "by_type": by_type,
        }

    def __len__(self) -> int:
        return len(self._iocs)

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _register(self, ioc: IOC) -> None:
        norm = ioc.normalized
        if not norm:
            return
        self._iocs.append(ioc)
        self._index[ioc.ioc_type].add(norm)
        self._ioc_map[norm] = ioc

    def _match_value(self, value: str) -> Optional[IOCMatch]:
        # Exact match
        if value in self._ioc_map:
            ioc = self._ioc_map[value]
            return IOCMatch(ioc=ioc, entity=value, match_type="exact")

        # Domain: vérifier sous-domaines (*.evil.com vs sub.evil.com)
        if "." in value:
            for domain in self._index[IOCType.DOMAIN]:
                if value == domain or value.endswith("." + domain):
                    ioc = self._ioc_map[domain]
                    return IOCMatch(ioc=ioc, entity=value, match_type="domain_contains")

        # URL: vérifier si le domaine d'un IOC URL est dans la valeur
        for url_ioc in self._index[IOCType.URL]:
            if url_ioc in value:
                ioc = self._ioc_map[url_ioc]
                return IOCMatch(ioc=ioc, entity=value, match_type="url_contains")

        return None

    # ------------------------------------------------------------------
    # Loaders
    # ------------------------------------------------------------------

    def _load_txt(self, text: str, source: str) -> int:
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            ioc_type = _infer_type(line)
            if ioc_type == IOCType.UNKNOWN:
                continue
            self._register(IOC(value=line, ioc_type=ioc_type, source=source))
            count += 1
        return count

    def _load_csv(self, text: str, source: str, delimiter: str = ",") -> int:
        count = 0
        reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
        if not reader.fieldnames:
            return self._load_txt(text, source)

        for row in reader:
            # Chercher les colonnes ioc_value, indicator, value, ioc, ip, domain, hash…
            value = ""
            ioc_type_str = ""
            for key in ("ioc_value", "indicator", "value", "ioc", "observable", "indicator_value"):
                v = row.get(key) or row.get(key.title()) or ""
                if v.strip():
                    value = v.strip()
                    break
            if not value:
                # Fallback: chercher une valeur qui ressemble à un IOC
                for v in row.values():
                    if v and _infer_type(str(v).strip()) != IOCType.UNKNOWN:
                        value = str(v).strip()
                        break
            if not value:
                continue

            for key in ("type", "ioc_type", "indicator_type", "category"):
                t = row.get(key) or row.get(key.title()) or ""
                if t.strip():
                    ioc_type_str = t.strip().lower()
                    break

            # Mapper le type
            type_map = {
                "ip": IOCType.IP, "ipv4": IOCType.IP, "ipv6": IOCType.IP,
                "domain": IOCType.DOMAIN, "fqdn": IOCType.DOMAIN,
                "md5": IOCType.MD5,
                "sha1": IOCType.SHA1,
                "sha256": IOCType.SHA256,
                "url": IOCType.URL, "uri": IOCType.URL,
                "email": IOCType.EMAIL,
                "cve": IOCType.CVE,
            }
            ioc_type = type_map.get(ioc_type_str) or _infer_type(value)
            if ioc_type == IOCType.UNKNOWN:
                continue

            desc = row.get("description") or row.get("comment") or ""
            conf_raw = row.get("confidence") or row.get("score") or "1.0"
            try:
                conf = float(str(conf_raw).strip()) / (100.0 if float(str(conf_raw).strip()) > 1.0 else 1.0)
            except ValueError:
                conf = 1.0

            self._register(IOC(
                value=value,
                ioc_type=ioc_type,
                source=source,
                description=str(desc),
                confidence=conf,
            ))
            count += 1
        return count

    def _load_json(self, text: str, source: str) -> int:
        """Charge JSON (STIX 2.x bundle ou liste plate ou dict d'IOCs)."""
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return self._load_txt(text, source)

        count = 0

        # STIX 2.x bundle
        if isinstance(data, dict) and data.get("type") == "bundle":
            for obj in data.get("objects", []):
                if obj.get("type") not in ("indicator", "observed-data"):
                    continue
                pattern = obj.get("pattern") or ""
                # Extraire la valeur du pattern STIX "[ipv4-addr:value = '1.2.3.4']"
                stix_vals = re.findall(r"'([^']+)'", pattern)
                for val in stix_vals:
                    t = _infer_type(val)
                    if t != IOCType.UNKNOWN:
                        self._register(IOC(
                            value=val,
                            ioc_type=t,
                            source=source,
                            description=obj.get("description") or obj.get("name") or "",
                        ))
                        count += 1
            return count

        # Liste plate d'objets IOC
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    t = _infer_type(item)
                    if t != IOCType.UNKNOWN:
                        self._register(IOC(value=item, ioc_type=t, source=source))
                        count += 1
                elif isinstance(item, dict):
                    count += self._load_json_obj(item, source)
            return count

        # Dict unique
        if isinstance(data, dict):
            return self._load_json_obj(data, source)

        return count

    def _load_json_obj(self, obj: dict[str, Any], source: str) -> int:
        """Tente d'extraire un IOC d'un objet JSON."""
        for key in ("value", "ioc", "indicator", "ip", "domain", "hash", "url", "email"):
            v = obj.get(key) or obj.get(key.upper()) or ""
            if not v:
                continue
            v = str(v).strip()
            t = _infer_type(v)
            if t != IOCType.UNKNOWN:
                desc = str(obj.get("description") or obj.get("name") or obj.get("comment") or "")
                self._register(IOC(
                    value=v,
                    ioc_type=t,
                    source=source,
                    description=desc,
                ))
                return 1
        return 0
