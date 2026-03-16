"""
=========================================================
Règle de détection — Abus de PowerShell
=========================================================

PowerShell est un interpréteur puissant très utilisé par les administrateurs,
mais également par les attaquants pour exécuter du code malveillant ou
télécharger des charges utiles à distance. Cette règle vise à détecter
l'utilisation malintentionnée de PowerShell via des indicateurs courants :

  • utilisation du paramètre `-enc` ou `-encodedcommand` indiquant un
    script encodé Base64,
  • présence d'`Invoke-Expression`, `IEX`, `DownloadString`, ou `Invoke-WebRequest`
    dans la ligne de commande,
  • exécution de scripts en mémoire qui n'apparaissent pas sur disque.

L'événement 4688 (création de processus) ou l'ID 1 de Sysmon sont surveillés.
Une alerte est déclenchée lorsqu'un pattern suspect est détecté.

MITRE ATT&CK : T1059.001 — Command and Scripting Interpreter: PowerShell
"""

from __future__ import annotations

import re
from typing import List

from adft.core.models.events import Detection, NormalizedEvent, Severity
from adft.detection.rules.base_rule import BaseRule


class PowerShellAbuseRule(BaseRule):
    """
    Détecte les abus de PowerShell via des indicateurs dans la ligne de commande.

    Surveille les événements 4688 ou 1 et examine la commande exécutée
    lorsqu'elle implique PowerShell. Si des paramètres encodés ou des
    fonctions de téléchargement/exécution sont détectés, une alerte est générée.
    """

    rule_id = "EXEC-001"
    rule_name = "Abus de PowerShell détecté"
    description = "Détection de commandes PowerShell potentiellement malveillantes"
    severity = Severity.HIGH
    mitre_tactic = "Execution"
    mitre_technique = "Command and Scripting Interpreter: PowerShell"
    mitre_id = "T1059.001"

    _POWERSHELL_PAT = re.compile(r"powershell", re.I)
    _SUSPICIOUS_PATTERNS = [
        re.compile(r"-enc\w*", re.I),
        re.compile(r"-encodedcommand", re.I),
        re.compile(r"invoke-expression", re.I),
        re.compile(r"\bIEX\b", re.I),
        re.compile(r"downloadstring", re.I),
        re.compile(r"invoke-webrequest", re.I),
    ]

    def evaluate(self, events: List[NormalizedEvent]) -> List[Detection]:
        detections: List[Detection] = []
        for ev in events:
            # Focus sur les créations de processus (4688) ou Sysmon Event 1
            if ev.event_id not in (4688, 1):
                continue
            raw = getattr(ev, "raw_event", {}) or {}
            cmd = (raw.get("CommandLine") or raw.get("command_line") or raw.get("cmdline") or raw.get("message"))
            proc_name = (ev.process_name or raw.get("Image") or raw.get("ProcessName"))
            if not cmd and not proc_name:
                continue

            blob = f"{proc_name or ''} {cmd or ''}".lower()
            # Vérifier que c'est une invocation de powershell
            if not self._POWERSHELL_PAT.search(blob):
                continue
            # Chercher des indicateurs d'abus
            suspicious = False
            for pat in self._SUSPICIOUS_PATTERNS:
                if pat.search(blob):
                    suspicious = True
                    break
            if not suspicious:
                continue

            user = ev.user or ""
            host = ev.target_host or ev.source_host or ""
            desc = f"Commande PowerShell potentiellement malveillante exécutée : {cmd or proc_name}"
            entities = [e for e in [user, host] if e]
            detections.append(
                self.create_detection(
                    description=desc,
                    events=[ev],
                    entities=entities,
                    confidence=0.8,
                    severity_override=Severity.HIGH,
                )
            )

        return detections