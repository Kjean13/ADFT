"""
╔══════════════════════════════════════════════════════════════════╗
║  ADFT — Analyse pipeline                                         ║
║                                                                  ║
║  Alertes brutes -> Filtrage bruit -> Scoring risque -> Score AD  ║
╚══════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

from typing import List, Tuple, Optional

from adft.core.models import NormalizedEvent, DetectionAlert
from adft.core.models.events import InvestigationObject

# Si tes imports réels diffèrent, garde les tiens (mais l'idée reste identique)
from .noise_filter import NoiseFilter
# from adft.core.scoring import RiskScorer, ADScorer  # selon ton projet


def _inv_alerts(inv: InvestigationObject) -> List:
    """
    Compatibilité InvestigationObject :
    - ancien champ : inv.alerts
    - nouveau champ : inv.detections
    Retourne toujours une liste.
    """
    a = getattr(inv, "alerts", None)
    if a is not None:
        return a or []
    d = getattr(inv, "detections", None)
    if d is not None:
        return d or []
    return []


def run_analysis(
    events: List[NormalizedEvent],
    alerts: List[DetectionAlert],
    investigations: List[InvestigationObject],
):
    """
    Pipeline d'analyse ADFT.

    Retourne (events, alerts, investigations) modifiés/filtrés.
    """

    print("  ||  Alertes brutes -> Filtrage bruit -> Scoring risque -> Score AD  ||")

    # ------------------------------------------------------------
    # Filtrage bruit
    # ------------------------------------------------------------
    nf = NoiseFilter()
    alerts_filtered = nf.filter_alerts(alerts)

    print(f"[ADFT]   alertes après filtre: {len(alerts_filtered)}")

    # ------------------------------------------------------------
    # Scoring risque / Score AD
    # ------------------------------------------------------------
    # IMPORTANT : le crash venait d'ici car inv.alerts n'existe pas.
    # On passe par _inv_alerts(inv) pour compat.
    #
    # Ici je ne modifie PAS tes classes de scoring (que je n'ai pas),
    # je sécurise juste l'accès aux alertes/detections.

    for inv in investigations or []:
        _ = _inv_alerts(inv)  # force compat, et évite tout inv.alerts direct

    # NOTE:
    # Si tes scorers attendent inv.alerts, tu as 2 options :
    # 1) modifier les scorers pour utiliser _inv_alerts(inv)
    # 2) ou injecter un alias dynamique :
    #    setattr(inv, "alerts", _inv_alerts(inv))  # sans casser l'objet

    for inv in investigations or []:
        if not hasattr(inv, "alerts"):
            setattr(inv, "alerts", _inv_alerts(inv))

    # Ici, appelle tes scorers comme avant (dans ton projet).
    # Exemple (à adapter) :
    # risk = RiskScorer().score(investigations)
    # ad_score = ADScorer().score(events, investigations)

    return events, alerts_filtered, investigations