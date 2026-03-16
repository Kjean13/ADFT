"""
Moteur de corrélation — Transformer les détections en compréhension.

La corrélation regroupe les détections individuelles en objets
d'investigation cohérents. Elle identifie les chaînes d'attaque
et les patterns de progression.
"""

from adft.correlation.engine import CorrelationEngine

__all__ = ["CorrelationEngine"]