"""
Point d'entrée CLI pour l'installation (project.scripts).

Permet: `adft ...` après `pip install -e .`
"""
from __future__ import annotations

from adft.cli.app import main as _main

def cli() -> None:
    _main()
