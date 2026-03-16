"""ZipParser — Extraction récursive de fichiers ZIP pour l'ingestion ADFT.

Fonctionnalités :
  - Extraction récursive jusqu'à 3 niveaux
  - Sniffing de format automatique par extension + magic bytes
  - Délégation vers les parseurs existants (EVTX, JSON, CSV, YAML…)
  - Limites de sécurité : taille max, nombre de fichiers max, protection zip-bomb
  - Qualité : stats et issues remontées au QualityCollector
"""

from __future__ import annotations

import io
import tempfile
from pathlib import Path
from typing import Any

from adft.core.ingestion.base_parser import BaseParser
from adft.core.quality import QualityCollector

# Limites de sécurité
MAX_EXTRACTION_DEPTH = 3
MAX_FILES_PER_ZIP = 2000
MAX_UNCOMPRESSED_SIZE = 512 * 1024 * 1024   # 512 MB total
MAX_SINGLE_FILE_SIZE = 128 * 1024 * 1024    # 128 MB par fichier
ZIP_RATIO_LIMIT = 100                        # Ratio compression max (anti zip-bomb)

# Extensions traitées (autres sont ignorées silencieusement)
_SUPPORTED_EXTENSIONS = {
    ".evtx", ".json", ".jsonl", ".ndjson",
    ".yaml", ".yml", ".csv", ".tsv",
    ".cef", ".leef", ".xml", ".log",
    ".syslog", ".txt", ".md", ".markdown",
    ".zip",  # ZIP récursif
}


class ZipParser(BaseParser):
    """Parse les archives ZIP en déléguant vers les parseurs connus."""

    @property
    def parser_name(self) -> str:
        return "ZIP Parser (Recursive Archive Extractor)"

    def __init__(self, sub_parsers: list[BaseParser] | None = None) -> None:
        """
        Args:
            sub_parsers: Liste ordonnée des parseurs vers qui déléguer.
                         Si None, doit être injecté via set_parsers() avant usage.
        """
        self._sub_parsers: list[BaseParser] = sub_parsers or []
        self._quality = QualityCollector("zip_parser")

    def set_parsers(self, parsers: list[BaseParser]) -> None:
        """Injecter la liste de parseurs (appelé par LogLoader)."""
        # Exclure self pour éviter la récursion infinie au même niveau
        self._sub_parsers = [p for p in parsers if p is not self]

    def can_parse(self, file_path: Path) -> bool:
        if file_path.suffix.lower() != ".zip":
            return False
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
                return magic[:2] == b"PK"
        except (IOError, OSError):
            return False

    def parse(self, file_path: Path) -> list[dict[str, Any]]:
        self._quality = QualityCollector("zip_parser")
        events: list[dict[str, Any]] = []
        self._extract_zip(file_path, events, depth=0, root=file_path)
        self._quality.incr("events_extracted", len(events))
        return events

    def _extract_zip(
        self,
        zip_path: Path,
        events: list[dict[str, Any]],
        depth: int,
        root: Path,
    ) -> None:
        if depth >= MAX_EXTRACTION_DEPTH:
            self._quality.warn(
                "zip_depth_exceeded",
                f"Profondeur maximale {MAX_EXTRACTION_DEPTH} atteinte, extraction arrêtée.",
                file=str(zip_path),
                depth=depth,
            )
            return

        try:
            import zipfile
        except ImportError:
            raise ImportError("Module 'zipfile' non disponible.")

        try:
            with zipfile.ZipFile(str(zip_path), "r") as zf:
                members = zf.infolist()
        except zipfile.BadZipFile as exc:
            self._quality.error(
                "zip_bad_file",
                "Archive ZIP corrompue ou invalide.",
                file=str(zip_path),
                error=str(exc),
            )
            return
        except Exception as exc:
            self._quality.error(
                "zip_open_error",
                "Impossible d'ouvrir l'archive ZIP.",
                file=str(zip_path),
                error=str(exc),
            )
            return

        if len(members) > MAX_FILES_PER_ZIP:
            self._quality.warn(
                "zip_too_many_files",
                f"Archive contient {len(members)} fichiers > {MAX_FILES_PER_ZIP}. "
                "Seuls les premiers {MAX_FILES_PER_ZIP} sont traités.",
                file=str(zip_path),
            )
            members = members[:MAX_FILES_PER_ZIP]

        total_uncompressed = sum(m.file_size for m in members)
        if total_uncompressed > MAX_UNCOMPRESSED_SIZE:
            self._quality.warn(
                "zip_too_large",
                f"Taille décompressée {total_uncompressed // (1024**2)} MB "
                f"> limite {MAX_UNCOMPRESSED_SIZE // (1024**2)} MB.",
                file=str(zip_path),
            )
            # Continuer quand même, la limite par fichier protège

        with tempfile.TemporaryDirectory(prefix="adft_zip_") as tmpdir:
            tmp_path = Path(tmpdir)
            import zipfile  # noqa: F811 (already imported above but inside try)
            with zipfile.ZipFile(str(zip_path), "r") as zf:
                for member in members:
                    # Sécurité : path traversal
                    member_name = member.filename
                    if ".." in member_name or member_name.startswith("/"):
                        self._quality.warn(
                            "zip_path_traversal",
                            "Fichier ignoré (path traversal détecté).",
                            file=str(zip_path),
                            member=member_name,
                        )
                        continue

                    # Dossier : ignorer
                    if member_name.endswith("/"):
                        continue

                    # Extension non supportée
                    suffix = Path(member_name).suffix.lower()
                    if suffix not in _SUPPORTED_EXTENSIONS:
                        self._quality.incr("files_skipped_unsupported")
                        continue

                    # Anti zip-bomb par fichier
                    if member.compress_size > 0:
                        ratio = member.file_size / member.compress_size
                        if ratio > ZIP_RATIO_LIMIT:
                            self._quality.warn(
                                "zip_bomb_suspected",
                                f"Ratio de compression {ratio:.0f}x suspect sur '{member_name}'.",
                                file=str(zip_path),
                                member=member_name,
                            )
                            continue

                    if member.file_size > MAX_SINGLE_FILE_SIZE:
                        self._quality.warn(
                            "zip_file_too_large",
                            f"Fichier '{member_name}' ({member.file_size // (1024**2)} MB) "
                            "dépasse la limite par fichier.",
                            file=str(zip_path),
                            member=member_name,
                        )
                        continue

                    # Extraire vers temp
                    try:
                        extracted_path = tmp_path / Path(member_name).name
                        with zf.open(member) as src, open(extracted_path, "wb") as dst:
                            dst.write(src.read())
                    except Exception as exc:
                        self._quality.warn(
                            "zip_extract_error",
                            f"Impossible d'extraire '{member_name}'.",
                            file=str(zip_path),
                            member=member_name,
                            error=str(exc),
                        )
                        continue

                    # ZIP récursif
                    if suffix == ".zip":
                        self._extract_zip(extracted_path, events, depth + 1, root)
                        continue

                    # Déléguer au parseur approprié
                    self._parse_extracted_file(
                        extracted_path,
                        original_name=str(zip_path) + "!" + member_name,
                        events=events,
                    )

    def _parse_extracted_file(
        self,
        file_path: Path,
        original_name: str,
        events: list[dict[str, Any]],
    ) -> None:
        if not self._sub_parsers:
            self._quality.warn(
                "zip_no_sub_parsers",
                "Aucun sous-parseur configuré pour déléguer les fichiers extraits.",
                file=original_name,
            )
            return

        for parser in self._sub_parsers:
            if not parser.can_parse(file_path):
                continue
            try:
                parsed = parser.parse(file_path)
                # Enrichir la provenance
                for event in parsed:
                    event["_source_file"] = original_name
                    event["_zip_extracted"] = True
                events.extend(parsed)
                self._quality.incr("files_parsed_from_zip")
                self._quality.extend(parser.pop_quality_report())
                return
            except Exception as exc:
                self._quality.warn(
                    "zip_sub_parser_failed",
                    f"Parseur '{parser.parser_name}' a échoué sur '{original_name}'.",
                    file=original_name,
                    parser=parser.parser_name,
                    error=str(exc),
                )
                self._quality.extend(parser.pop_quality_report())
                return  # Ne pas essayer d'autres parseurs après échec

        self._quality.incr("files_skipped_no_parser")
        self._quality.warn(
            "zip_no_parser_matched",
            f"Aucun parseur compatible pour '{Path(original_name).name}'.",
            file=original_name,
        )

    @property
    def quality_report(self) -> dict[str, Any]:
        return self._quality.snapshot()

    def pop_quality_report(self) -> dict[str, Any]:
        snap = self._quality.snapshot()
        self._quality = QualityCollector("zip_parser")
        return snap
