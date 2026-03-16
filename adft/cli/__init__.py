"""ADFT — package CLI.

Important : on n'importe pas ``adft.cli.app`` au chargement.

Raison : ``python -m adft.cli.app`` charge d'abord le package ``adft.cli``
(donc ce fichier). Si on importe ``adft.cli.app`` ici, Python détecte le module
dans ``sys.modules`` avant son exécution et émet un RuntimeWarning (runpy).

On expose donc ``main`` via un import lazy.
"""

from __future__ import annotations


def main() -> None:
    """Point d'entrée CLI (lazy import pour éviter le RuntimeWarning)."""
    from .app import main as _main

    _main()


__all__ = ["main"]