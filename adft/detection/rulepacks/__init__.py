"""ADFT Rule Packs.

Un *rule pack* est une sélection cohérente de règles (15–25 typiquement)
avec un mapping MITRE propre et stable.

Pourquoi :
- figer une V1 reproductible
- permettre d'échanger/charger d'autres packs plus tard (V2, ransomware-only, etc.)
"""

from __future__ import annotations

from .v1 import RulePackV1

__all__ = ["RulePackV1"]
