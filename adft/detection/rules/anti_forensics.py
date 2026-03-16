"""Anti-forensics detection rules — T1070.001 / T1562.001.

AEV-001 : wevtutil/Clear-EventLog/auditpol → 4719 (audit policy change) + 1102.
AEV-002 : Désactivation de Defender, Sysmon ou EDR.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import List

from adft.core.models.events import Detection, NormalizedEvent, Severity
from adft.detection.rules.base_rule import BaseRule

# Commandes d'effacement de journaux
_LOG_CLEAR_COMMANDS = (
    "wevtutil",
    "clear-eventlog",
    "remove-eventlog",
    "auditpol",
    "clearev",
    "fsutil usn deletejournal",
)

# Politiques d'audit ciblées (auditpol /set /disable)
_AUDIT_DISABLE_PATTERNS = (
    "/set /subcategory",
    "/set /category",
    "disable",
    "no auditing",
    "0x0",
)

# Commandes de désactivation de sécurité
_SECURITY_DISABLE_COMMANDS = (
    # Windows Defender
    "set-mppreference",
    "add-mppreference",
    "disableav",
    "disablerealtimemonitoring",
    "disablebehaviormonitoring",
    "disableioavprotection",
    "disableintrusionpreventionsystem",
    "disableautomaticexclusions",
    "disablescanningdownloadedfilesandsamplesubmission",
    "signatureupdateinterval 0",
    # Sysmon
    "sysmon -u",
    "sysmon.exe -u",
    "sysmon64 -u",
    "sysmon64.exe -u",
    # sc stop
    "sc stop",
    "sc delete",
    "net stop",
    # Registry Defender disable
    "spynet\\reporting",
    "disableantispyware",
    "disableantivirus",
    # PowerShell bypass
    "bypass",
    "unrestricted",
)

# Noms de services/processus EDR/AV cibles
_SECURITY_TOOL_NAMES = (
    "windefend",
    "msmpeng",
    "mssense",
    "securityhealthservice",
    "sense",
    "sysmon",
    "sysmon64",
    "cb",
    "cbdefense",
    "carbonblack",
    "csagent",
    "cyserver",
    "cylancesvc",
    "xagt",
    "xagtnotif",
    "cortex",
    "traps",
    "cyoptics",
    "sophosssp",
    "savservice",
    "avgnt",
    "avastsvc",
    "mbamservice",
    "malwarebytes",
    "eset",
    "ekrn",
    "fsav",
    "fssm32",
    "kavfs",
    "klnagent",
)

_WINDOW_MINUTES = timedelta(minutes=15)


class AuditLogTamperingRule(BaseRule):
    """AEV-001 — Effacement de journaux / désactivation audit (4719, 1102, commandes)."""

    rule_id = "AEV-001"
    rule_name = "Effacement journaux / désactivation audit (T1070.001)"
    description = (
        "Détection d'effacement de journaux d'événements (1102/104) ou de "
        "modification de politique d'audit (4719) via wevtutil, auditpol ou "
        "Clear-EventLog — indicateur d'anti-forensics."
    )
    severity = Severity.CRITICAL
    mitre_tactic = "Defense Evasion"
    mitre_technique = "Indicator Removal: Clear Windows Event Logs"
    mitre_id = "T1070.001"

    def evaluate(self, events: List[NormalizedEvent]) -> List[Detection]:
        hits: list[NormalizedEvent] = []

        for ev in events:
            is_hit = False

            # 1102 / 104 = journaux effacés directement
            if ev.event_id in (1102, 104):
                is_hit = True

            # 4719 = modification de politique d'audit
            elif ev.event_id == 4719:
                raw = ev.raw_event or {}
                subcategory = (raw.get("SubcategoryGuid") or raw.get("SubcategoryGuid") or "").lower()
                audit_setting = (raw.get("AuditPolicyChanges") or raw.get("auditPolicyChanges") or "").lower()
                if "%%8448" in audit_setting or "no auditing" in audit_setting or subcategory:
                    is_hit = True

            # 4688/1 = processus wevtutil/auditpol/Clear-EventLog
            elif ev.event_id in (4688, 1):
                raw = ev.raw_event or {}
                cmd = (
                    raw.get("CommandLine")
                    or raw.get("commandLine")
                    or raw.get("ProcessCommandLine")
                    or ""
                ).lower()
                if any(c in cmd for c in _LOG_CLEAR_COMMANDS):
                    is_hit = True

            if is_hit:
                hits.append(ev)

        if not hits:
            return []

        hits_sorted = sorted(hits, key=lambda e: e.timestamp)
        actors = sorted({ev.user for ev in hits if ev.user})
        hosts = sorted({ev.source_host or ev.target_host for ev in hits if ev.source_host or ev.target_host})
        ids = sorted({ev.event_id for ev in hits})
        desc = (
            f"Anti-forensics : {len(hits)} événement(s) d'effacement/désactivation "
            f"audit (IDs {ids}) par {', '.join(actors[:3]) or 'inconnu'} "
            f"sur {', '.join(hosts[:3]) or 'inconnu'}."
        )
        return [
            self.create_detection(
                description=desc,
                events=hits_sorted[:200],
                entities=actors[:4] + hosts[:4],
                confidence=0.95,
            )
        ]


class SecurityToolDisableRule(BaseRule):
    """AEV-002 — Désactivation Defender / Sysmon / EDR (T1562.001)."""

    rule_id = "AEV-002"
    rule_name = "Désactivation Defender / Sysmon / EDR (T1562.001)"
    description = (
        "Détection de tentative de désactivation ou d'arrêt d'un outil de "
        "sécurité (Windows Defender, Sysmon, EDR) via PowerShell, sc, net stop "
        "ou modification du registre."
    )
    severity = Severity.CRITICAL
    mitre_tactic = "Defense Evasion"
    mitre_technique = "Impair Defenses: Disable or Modify Tools"
    mitre_id = "T1562.001"

    def evaluate(self, events: List[NormalizedEvent]) -> List[Detection]:
        hits_by_tool: dict[str, list[NormalizedEvent]] = defaultdict(list)

        for ev in events:
            if ev.event_id not in (4688, 1, 7036, 7045, 13):  # 13 = Sysmon RegSetValue
                continue

            raw = ev.raw_event or {}
            cmd = (
                raw.get("CommandLine")
                or raw.get("commandLine")
                or raw.get("ProcessCommandLine")
                or ""
            ).lower()
            image = (
                raw.get("NewProcessName")
                or raw.get("Image")
                or raw.get("image")
                or ev.process_name
                or ""
            ).lower()
            target_obj = (
                raw.get("TargetObject")   # Registry Sysmon 13
                or raw.get("targetObject")
                or raw.get("ServiceName")
                or raw.get("serviceName")
                or ""
            ).lower()

            combined = f"{cmd} {image} {target_obj}"

            # Vérifier les commandes de désactivation
            if not any(c in combined for c in _SECURITY_DISABLE_COMMANDS):
                # Vérifier les noms d'outils dans la commande (sc stop <outil>)
                if not any(t in combined for t in _SECURITY_TOOL_NAMES):
                    continue

            # Identifier l'outil ciblé
            tool_hit = "security tool"
            for t in _SECURITY_TOOL_NAMES:
                if t in combined:
                    tool_hit = t
                    break
            if "defender" in combined or "windefend" in combined or "msmpeng" in combined:
                tool_hit = "Windows Defender"
            elif "sysmon" in combined:
                tool_hit = "Sysmon"

            hits_by_tool[tool_hit].append(ev)

        detections: List[Detection] = []
        for tool, evs in hits_by_tool.items():
            actors = sorted({ev.user for ev in evs if ev.user})
            hosts = sorted({ev.source_host for ev in evs if ev.source_host})
            desc = (
                f"Désactivation de «{tool}» détectée : {len(evs)} événement(s) "
                f"par {', '.join(actors[:3]) or 'inconnu'} "
                f"sur {', '.join(hosts[:3]) or 'inconnu'}."
            )
            detections.append(
                self.create_detection(
                    description=desc,
                    events=sorted(evs, key=lambda e: e.timestamp)[:100],
                    entities=[tool] + actors[:3] + hosts[:3],
                    confidence=0.92,
                )
            )
        return detections
