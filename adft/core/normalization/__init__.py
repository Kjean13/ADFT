"""
Couche de normalisation — Conversion vers le schéma unifié.

Responsabilité UNIQUE : transformer les événements bruts
(format variable selon la source) en NormalizedEvent
(format unique pour toute l'application).

C'est la FONDATION de tout le pipeline ADFT.
"""

from adft.core.normalization.normalizer import EventNormalizer

__all__ = ["EventNormalizer"]