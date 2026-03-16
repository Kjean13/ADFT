"""GPO abuse detection rules — T1484.001.

GPO-001 : Modification / création / suppression d'objet GPO (5136/5137/5141).
GPO-002 : Script déposé dans SYSVOL (Sysmon 11) — persistance via stratégie de groupe.
"""

from __future__ import annotations

from collections import defaultdict
from typing import List

from adft.core.models.events import Detection, NormalizedEvent, Severity
from adft.detection.rules.base_rule import BaseRule

# GUIDs DS d'objets GPO (attributs et classes AD liés aux stratégies)
_GPO_CLASS_GUIDS = {
    "f30e3bc2-9ff0-11d1-b603-0000f80367c1",  # groupPolicyContainer
    "bf967a7f-0de6-11d0-a285-00aa003049e2",  # organizationalUnit (cible GPO)
}

_GPO_ATTR_GUIDS = {
    "f30e3bc3-9ff0-11d1-b603-0000f80367c1",  # gPCFileSysPath
    "f30e3bc4-9ff0-11d1-b603-0000f80367c1",  # gPCMachineExtensionNames
    "f30e3bc5-9ff0-11d1-b603-0000f80367c1",  # gPCUserExtensionNames
    "7b6f3a08-3bca-11d2-a9cc-0000f875ae61",  # gPCFunctionalityVersion
    "d3d3d3d3-d3d3-d3d3-d3d3-d3d3d3d3d3d3",  # gPLink
}

_SYSVOL_PATTERNS = (
    r"\\sysvol\\",
    r"\\policies\\",
    r"C:\\Windows\\SYSVOL",
    r"SYSVOL",
)


class GPOModificationRule(BaseRule):
    """5136/5137/5141 : modification, création ou suppression d'objet GPO."""

    rule_id = "GPO-001"
    rule_name = "Modification GPO (5136/5137/5141)"
    description = (
        "Modification (5136), création (5137) ou suppression (5141) d'un objet "
        "GPO dans l'annuaire — possible altération de la stratégie de groupe "
        "(T1484.001)."
    )
    severity = Severity.HIGH
    mitre_tactic = "Defense Evasion / Privilege Escalation"
    mitre_technique = "Domain Policy Modification: Group Policy Modification"
    mitre_id = "T1484.001"

    _TARGET_IDS = {5136, 5137, 5141}

    def evaluate(self, events: List[NormalizedEvent]) -> List[Detection]:
        hits: List[NormalizedEvent] = []

        for ev in events:
            if ev.event_id not in self._TARGET_IDS:
                continue

            raw = ev.raw_event or {}

            # 5136 : vérifie que l'objet modifié est lié à une GPO
            if ev.event_id == 5136:
                obj_class = (
                    raw.get("ObjectClass")
                    or raw.get("objectClass")
                    or ""
                ).lower()
                obj_dn = (raw.get("ObjectDN") or raw.get("objectDN") or "").lower()
                attr_id = (
                    raw.get("AttributeLDAPDisplayName")
                    or raw.get("attributeLDAPDisplayName")
                    or ""
                ).lower()
                guid = (
                    raw.get("ClassGUID")
                    or raw.get("classGuid")
                    or raw.get("AttributeSyntaxOID")
                    or ""
                ).lower().strip("{}")

                is_gpo = (
                    "grouppolicycontainer" in obj_class
                    or "policies" in obj_dn
                    or "grouppolicies" in obj_dn
                    or guid in _GPO_CLASS_GUIDS
                    or guid in _GPO_ATTR_GUIDS
                    or attr_id in (
                        "gpcfilesyspath",
                        "gpcmachineextensionnames",
                        "gpcuserextensionnames",
                        "gplink",
                        "gpcoptions",
                        "gpcfunctionalityversion",
                    )
                )
                if not is_gpo:
                    continue

            hits.append(ev)

        if not hits:
            return []

        hits_sorted = sorted(hits, key=lambda e: e.timestamp)
        users = sorted({ev.user for ev in hits if ev.user})
        hosts = sorted({ev.source_host or ev.target_host for ev in hits if ev.source_host or ev.target_host})
        desc = (
            f"{len(hits)} événement(s) de modification GPO "
            f"(IDs {sorted({e.event_id for e in hits})}) "
            f"par {', '.join(users[:4]) or 'inconnu'} "
            f"depuis {', '.join(hosts[:3]) or 'inconnu'}."
        )
        return [
            self.create_detection(
                description=desc,
                events=hits_sorted[:200],
                entities=users[:6] + hosts[:4],
                confidence=0.85,
            )
        ]


class GPOSysvolScriptRule(BaseRule):
    """Sysmon 11 (FileCreate) dans SYSVOL — script GPO malveillant déposé."""

    rule_id = "GPO-002"
    rule_name = "Script SYSVOL (Sysmon 11 — T1484.001)"
    description = (
        "Création de fichier (Sysmon EventID 11) dans un chemin SYSVOL/Policies "
        "— attaquant déposant un script d'exécution via GPO."
    )
    severity = Severity.CRITICAL
    mitre_tactic = "Persistence / Defense Evasion"
    mitre_technique = "Domain Policy Modification: Group Policy Modification"
    mitre_id = "T1484.001"

    _SCRIPT_EXTENSIONS = {".bat", ".ps1", ".vbs", ".cmd", ".hta", ".js", ".wsf", ".exe", ".dll"}

    def evaluate(self, events: List[NormalizedEvent]) -> List[Detection]:
        hits: List[NormalizedEvent] = []

        for ev in events:
            if ev.event_id != 11:
                continue

            raw = ev.raw_event or {}
            target_filename = (
                raw.get("TargetFilename")
                or raw.get("targetFilename")
                or raw.get("FilePath")
                or ev.process_name
                or ""
            )

            tf_lower = target_filename.lower()
            in_sysvol = any(p.lower() in tf_lower for p in _SYSVOL_PATTERNS)
            if not in_sysvol:
                continue

            ext = "." + tf_lower.rsplit(".", 1)[-1] if "." in tf_lower else ""
            if ext not in self._SCRIPT_EXTENSIONS:
                continue

            hits.append(ev)

        if not hits:
            return []

        hits_sorted = sorted(hits, key=lambda e: e.timestamp)
        detections: List[Detection] = []
        by_process: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for ev in hits_sorted:
            key = ev.process_name or ev.user or "unknown"
            by_process[key].append(ev)

        for proc, evs in by_process.items():
            raw = evs[0].raw_event or {}
            path = raw.get("TargetFilename") or raw.get("targetFilename") or "SYSVOL path"
            desc = (
                f"Script déposé dans SYSVOL par «{proc}»: «{path}» "
                f"({len(evs)} fichier(s))."
            )
            detections.append(
                self.create_detection(
                    description=desc,
                    events=evs[:50],
                    entities=[proc, evs[0].source_host or ""],
                    confidence=0.9,
                )
            )
        return detections
