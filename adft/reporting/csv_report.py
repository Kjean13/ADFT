"""
╔══════════════════════════════════════════════════════════════════╗
║  ADFT — Générateur de Rapport CSV                                ║
╚══════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations
import csv
from pathlib import Path
from typing import TYPE_CHECKING
from datetime import datetime

if TYPE_CHECKING:
    from adft.reporting.engine import InvestigationReport


class CSVReportGenerator:

    COLUMNS = [
        "timestamp",
        "rule_id",
        "rule_name",
        "severity",
        "user",
        "source_host",
        "target_host",
        "mitre_tactic",
        "mitre_technique",
        "description",
        "event_count",
    ]

    # ================================================================
    # Safe timestamp formatter
    # ================================================================
    @staticmethod
    def _format_ts(ts) -> str:
        if ts is None:
            return "N/A"

        # déjà string → OK
        if isinstance(ts, str):
            return ts

        # datetime → format propre
        if isinstance(ts, datetime):
            return ts.strftime("%Y-%m-%d %H:%M:%S")

        return str(ts)

    # ================================================================
    # CSV generation
    # ================================================================
    def generate(self, report: InvestigationReport, output_path: Path) -> None:

        with open(output_path, "w", newline="", encoding="utf-8-sig") as csvfile:
            writer = csv.DictWriter(
                csvfile,
                fieldnames=self.COLUMNS,
                delimiter=";",
            )

            writer.writeheader()

            for alert in report.alerts:
                writer.writerow({
                    "timestamp": self._format_ts(
                        getattr(alert, "timestamp", None)
                    ),
                    "rule_id": getattr(alert, "rule_id", ""),
                    "rule_name": getattr(alert, "rule_name", ""),
                    "severity": str(getattr(alert, "severity", "")),
                    "user": getattr(alert, "user", ""),
                    "source_host": getattr(alert, "source_host", ""),
                    "target_host": getattr(alert, "target_host", ""),
                    "mitre_tactic": getattr(alert, "mitre_tactic", ""),
                    "mitre_technique": getattr(alert, "mitre_technique", ""),
                    "description": getattr(alert, "description", ""),
                    "event_count": len(getattr(alert, "events", None) or []),
                })