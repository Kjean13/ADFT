"""
=========================================================
Règle de détection — Exécution de processus suspects
=========================================================

Cette règle vise à détecter l'exécution d'outils connus pour être
utilisés lors d'attaques AD ou de mouvements latéraux, tels que
Mimikatz, PsExec, ProcDump ou autres utilitaires d'extraction de
credentiels. Elle s'appuie sur les informations brutes du
processus (Image, CommandLine) et le champ `process_name` du
`NormalizedEvent` pour identifier des signatures connues.

L'objectif est de fournir une alerte immédiate lorsqu'un de ces
processus est lancé, même si aucune compromission ne peut être
établie avec certitude. Les analystes peuvent ensuite corréler
cette information avec d'autres détections pour confirmer un
comportement malveillant.

MITRE ATT&CK :
  • T1003 — OS Credential Dumping
  • T1569.002 — Service Execution (PsExec)
  • T1204 — User Execution
"""

from __future__ import annotations

import re
from typing import List

from adft.core.models.events import Detection, NormalizedEvent, Severity
from adft.detection.rules.base_rule import BaseRule


class SuspiciousProcessExecutionRule(BaseRule):
    """
    Détecte l'exécution de processus hautement suspects.

    Cette règle surveille les événements 4688 (création de
    processus) ou 1 (Sysmon) et cherche des signatures de
    programmes typiquement utilisés par des attaquants : Mimikatz,
    PsExec, ProcDump, WinRM, secretsdump, etc. Les noms et
    expressions régulières utilisés ci‑dessous ne sont pas
    exhaustifs mais couvrent les cas d'usage les plus courants.
    """

    rule_id = "PROC-001"
    rule_name = "Exécution de processus suspect"
    description = "Processus potentiellement malveillant détecté (Mimikatz/PsExec/ProcDump/WinRM)"
    severity = Severity.HIGH
    mitre_tactic = "Credential Access"
    mitre_technique = "OS Credential Dumping"
    mitre_id = "T1003"

    # Liste de motifs suspects (noms de fichiers ou fragments de commande)
    _PATTERNS = [
        re.compile(r"mimikatz", re.I),
        re.compile(r"psexec", re.I),
        re.compile(r"procdump", re.I),
        re.compile(r"secretsdump", re.I),
        re.compile(r"winrm", re.I),
        re.compile(r"lsass\.dmp", re.I),
    ]

    def evaluate(self, events: List[NormalizedEvent]) -> List[Detection]:
        detections: List[Detection] = []
        for ev in events:
            # Surveiller les créations de processus (4688) ou les événements Sysmon ID 1
            if ev.event_id not in (4688, 1):
                continue

            # Récupérer les informations brutes associées au processus
            raw = getattr(ev, "raw_event", {}) or {}
            # Extraire des champs fréquents dans les exports
            proc_name = ev.process_name or raw.get("Image") or raw.get("process") or raw.get("ProcessName")
            cmd_line = raw.get("CommandLine") or raw.get("command_line") or raw.get("cmdline") or raw.get("message")
            blob = " ".join(str(x) for x in (proc_name, cmd_line) if x)
            if not blob:
                continue

            matched = False
            for pat in self._PATTERNS:
                if pat.search(blob):
                    matched = True
                    break
            if not matched:
                continue

            # Générer une détection
            user = ev.user or ""
            host = ev.target_host or ev.source_host or ""
            desc = f"Processus suspect détecté : {blob.strip()}"
            entities = [e for e in [user, host] if e]
            detections.append(
                self.create_detection(
                    description=desc,
                    events=[ev],
                    entities=entities,
                    confidence=0.75,
                    severity_override=Severity.HIGH,
                )
            )

        return detections