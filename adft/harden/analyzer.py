
"""
Compat layer for tests/imports.

The hardening analyzer implementation lives in analyze.py.
This module keeps the public import path stable:
    from adft.harden.analyzer import HardeningAnalyzer
"""
from .analyze import HardeningAnalyzer  # noqa: F401