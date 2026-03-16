"""
╔══════════════════════════════════════════════════════════════════╗
║  ADFT — Module de Durcissement (Hardening Advisor)              ║
║                                                                  ║
║  Analyse les résultats de détection pour identifier :            ║
║    • Mauvaises configurations Active Directory                   ║
║    • Privilèges excessifs                                        ║
║    • Configurations risquées                                     ║
║                                                                  ║
║  Fournit :                                                       ║
║    - Recommandations de remédiation                             ║
║    - Scripts PowerShell de correction                            ║
║    - AUCUNE modification automatique de l'AD                    ║
╚══════════════════════════════════════════════════════════════════╝
"""

from adft.harden.analyze import HardeningAnalyzer
from adft.harden.advisor import RemediationAdvisor
from adft.harden.script_generator import PowerShellScriptGenerator

__all__ = [
    "HardeningAnalyzer",
    "RemediationAdvisor",
    "PowerShellScriptGenerator",
]