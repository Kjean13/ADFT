"""ADFT command-line application."""

from __future__ import annotations

import argparse
import sys

from adft import RELEASE_LABEL
from adft.cli.commands import (
    cmd_alerts,
    cmd_attack_chain,
    cmd_attack_path,
    cmd_convert,
    cmd_explain,
    cmd_harden,
    cmd_investigate,
    cmd_navigator,
    cmd_ui,
    cmd_reconstruct,
    cmd_replay,
    cmd_report,
    cmd_score,
    cmd_story,
    cmd_summary,
)

BANNER = fr"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║      ___    ____    ______   ______                          ║
║     /   |  / __ \  / ____/  /_  __/                          ║
║    / /| | / / / / / /_       / /                             ║
║   / ___ |/ /_/ / / __/      / /                              ║
║  /_/  |_/_____/ /_/        /_/                               ║
║                                                              ║
║   A D F T v1.0 — AD Forensic Toolkit                         ║
║   Investigate • Correlate • Score • Harden                   ║
║   Author : Jean.KM                                           ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""".strip("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="adft",
        description=f"ADFT {RELEASE_LABEL} — offline Active Directory investigation toolkit with canonical JSONL ingestion",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  adft convert test_logs -o converted_inputs\n"
            "  adft investigate test_logs/attack.json -o reports_core\n"
            "  adft summary -o reports_core\n"
            "  adft explain -o reports_core --level manager\n"
            "  adft navigator -o reports_core\n"
            "  adft replay -o reports_core\n"
            "  adft reconstruct -o reports_core --full\n"
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    p_convert = subparsers.add_parser("convert", help="convert supported evidence files to canonical JSONL")
    p_convert.add_argument("logs", nargs="+")
    p_convert.add_argument("--output", "-o", default="./converted_inputs")

    p_investigate = subparsers.add_parser("investigate", help="run a full investigation")
    p_investigate.add_argument("logs", nargs="+")
    p_investigate.add_argument("--format", "-f", nargs="+", default=["html", "json", "csv"], choices=["html", "json", "csv"])
    p_investigate.add_argument("--output", "-o", default="./reports_core")
    p_investigate.add_argument("--export-events-jsonl", action="store_true")
    p_investigate.add_argument("--no-filter", action="store_true")


    p_ui = subparsers.add_parser("ui", help="launch the integrated ADFT web UI")
    p_ui.add_argument("--output", "-o", default="./reports_core")
    p_ui.add_argument("--host", default="127.0.0.1")
    p_ui.add_argument("--port", type=int, default=8765)

    p_report = subparsers.add_parser("report", help="list generated artefacts")
    p_report.add_argument("--output", "-o", default="./reports_core")

    p_summary = subparsers.add_parser("summary", help="show a run summary")
    p_summary.add_argument("--output", "-o", default="./reports_core")

    p_alerts = subparsers.add_parser("alerts", help="show generated alerts")
    p_alerts.add_argument("--output", "-o", default="./reports_core")
    p_alerts.add_argument("--full", "--details", dest="full", action="store_true")

    p_attack_chain = subparsers.add_parser("attack-chain", help="print the attack chain")
    p_attack_chain.add_argument("--output", "-o", default="./reports_core")

    p_attack_path = subparsers.add_parser("attack-path", help="print attack paths")
    p_attack_path.add_argument("--output", "-o", default="./reports_core")

    p_story = subparsers.add_parser("story", help="print the attack story")
    p_story.add_argument("--output", "-o", default="./reports_core")
    p_story.add_argument("--full", action="store_true")

    p_reconstruct = subparsers.add_parser("reconstruct", help="print compromise reconstruction")
    p_reconstruct.add_argument("--output", "-o", default="./reports_core")
    p_reconstruct.add_argument("--full", action="store_true")

    p_score = subparsers.add_parser("score", help="print the AD exposure score")
    p_score.add_argument("--output", "-o", default="./reports_core")

    p_harden = subparsers.add_parser("harden", help="print hardening findings")
    p_harden.add_argument("--dry-run", action="store_true", required=True)
    p_harden.add_argument("--export-scripts", default=None)
    p_harden.add_argument("--output", "-o", default="./reports_core")

    p_explain = subparsers.add_parser("explain", help="render a deterministic explanation")
    p_explain.add_argument("--level", choices=["analyst", "ir", "manager", "pedagogic"], default="analyst")
    p_explain.add_argument("--output", "-o", default="./reports_core")

    p_nav = subparsers.add_parser("navigator", help="rebuild the ATT&CK Navigator export")
    p_nav.add_argument("--output", "-o", default="./reports_core")

    p_replay = subparsers.add_parser("replay", help="rebuild the replay export")
    p_replay.add_argument("--output", "-o", default="./reports_core")

    return parser


def main() -> None:
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    command_map = {
        "convert": cmd_convert,
        "investigate": cmd_investigate,
        "ui": cmd_ui,
        "report": cmd_report,
        "summary": cmd_summary,
        "alerts": cmd_alerts,
        "attack-chain": cmd_attack_chain,
        "attack-path": cmd_attack_path,
        "story": cmd_story,
        "reconstruct": cmd_reconstruct,
        "score": cmd_score,
        "harden": cmd_harden,
        "explain": cmd_explain,
        "navigator": cmd_navigator,
        "replay": cmd_replay,
    }
    try:
        command_map[args.command](args)
    except KeyboardInterrupt:
        print("\n[ADFT] Interrupted by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()
