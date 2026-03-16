"""
Couche d'ingestion — Chargement des donnees d'investigation.

Responsabilites :
  - Parser les fichiers EVTX (logs Windows natifs)
  - Parser les exports JSON / JSONL / NDJSON (SIEM, Winlogbeat, Elastic)
  - Parser les fichiers YAML / YML (exports structures, regles Sigma)
  - Parser les fichiers CSV / TSV (Splunk, QRadar, ArcSight, osquery)
  - Parser les fichiers CEF (Common Event Format — ArcSight, McAfee, Fortinet)
  - Parser les fichiers LEEF (Log Event Extended Format — IBM QRadar)
  - Parser les fichiers XML (Windows Event Forwarding, Nmap, Nessus)
  - Parser les fichiers Syslog (RFC 3164/5424 — pare-feux, routeurs, Linux)
  - Parser les tableaux Markdown (rapports d'investigation, documentation SOC)
  - Preparer les evenements bruts pour la normalisation

Architecture extensible : chaque format de log est gere
par un parseur dedie qui herite de BaseParser.
Pour ajouter un nouveau format, il suffit de creer
un nouveau parseur sans modifier le code existant.
"""

from adft.core.ingestion.loader import LogLoader

__all__ = ["LogLoader"]