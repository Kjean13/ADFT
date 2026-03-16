"""
Moteur de détection — Identification des menaces AD.

Architecture modulaire à base de règles :
  • Chaque règle est indépendante et autonome
  • Les règles sont mappées sur MITRE ATT&CK
  • Le moteur orchestre l'exécution de toutes les règles
  • Nouvelles règles ajoutables sans modification du moteur

Couverture initiale :
  • Élévation de privilèges
  • Abus Kerberos (Kerberoasting, AS-REP Roasting)
  • Authentification suspecte (brute force, pass-the-hash)
  • Anomalies d'activité administrateur
  • Indicateurs de compromission de comptes
"""

from adft.detection.engine import DetectionEngine

__all__ = ["DetectionEngine"]