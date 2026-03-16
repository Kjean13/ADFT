"""DLL abuse detection rules — T1574.002 / T1574.001 / T1055.

DLL-001 : Sysmon 7 (ImageLoaded) depuis un chemin suspect — DLL sideloading.
DLL-002 : LOLBins — rundll32/regsvr32/mshta appelés avec des arguments suspects.
DLL-003 : Sysmon 8 (CreateRemoteThread) — injection de code dans processus distant.
"""

from __future__ import annotations

from collections import defaultdict
from typing import List

from adft.core.models.events import Detection, NormalizedEvent, Severity
from adft.detection.rules.base_rule import BaseRule

# Chemins légitimes pour les DLL système (whitelist partielle)
_LEGIT_DLL_PATHS = (
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\winsxs\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\programdata\\microsoft\\",
    "c:\\windows\\microsoft.net\\",
    "c:\\windows\\assembly\\",
)

# Chemins suspects (DLL sideloading courants)
_SUSPICIOUS_DLL_PATHS = (
    "\\appdata\\",
    "\\temp\\",
    "\\tmp\\",
    "\\downloads\\",
    "\\public\\",
    "\\users\\",
    "\\desktop\\",
    "\\recycle",
    "c:\\perflogs\\",
    "\\programdata\\",
)

# Extensions suspectes dans les chemins de DLL chargées
_SUSPICIOUS_EXTENSIONS = {".txt", ".dat", ".log", ".pdf", ".jpg", ".png"}

# Binaires LOLBin ciblés
_LOLBINS = {
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "msiexec.exe",
    "odbcconf.exe",
    "regasm.exe",
    "regsvcs.exe",
    "ieexec.exe",
    "xwizard.exe",
    "pcalua.exe",
    "msconfig.exe",
}

# Arguments LOLBin indiquant une exécution suspecte
_LOLBIN_SUSPICIOUS_ARGS = (
    "http://",
    "https://",
    "ftp://",
    "\\\\",  # UNC path
    "javascript:",
    "vbscript:",
    ".sct",
    ".hta",
    "scrobj.dll",
    "comsvcs",
    "/i:",
    "-sta",
    "shell32.dll",
    "advpack.dll",
    "ieadvpack.dll",
    "regsvr",
)

# Processus cibles légitimes pour CreateRemoteThread (faux positifs courants)
_LEGIT_INJECT_TARGETS = {
    "svchost.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
}


class DLLSideloadingRule(BaseRule):
    """DLL-001 — Sysmon 7: ImageLoaded depuis chemin suspect (DLL sideloading)."""

    rule_id = "DLL-001"
    rule_name = "DLL Sideloading — ImageLoaded chemin suspect (Sysmon 7)"
    description = (
        "Chargement de DLL (Sysmon EventID 7) depuis un chemin non-système "
        "— technique de DLL sideloading pour exécuter du code malveillant "
        "dans un processus légitime."
    )
    severity = Severity.HIGH
    mitre_tactic = "Persistence / Defense Evasion / Privilege Escalation"
    mitre_technique = "Hijack Execution Flow: DLL Side-Loading"
    mitre_id = "T1574.002"

    def evaluate(self, events: List[NormalizedEvent]) -> List[Detection]:
        hits_by_image: dict[str, list[NormalizedEvent]] = defaultdict(list)

        for ev in events:
            if ev.event_id != 7:
                continue

            raw = ev.raw_event or {}
            image_loaded = (
                raw.get("ImageLoaded")
                or raw.get("imageLoaded")
                or raw.get("Image")
                or ""
            ).lower()

            if not image_loaded:
                continue

            # Exclure les chemins légitimes
            if any(image_loaded.startswith(p) for p in _LEGIT_DLL_PATHS):
                continue

            # Confirmer chemin suspect
            is_suspicious = any(p in image_loaded for p in _SUSPICIOUS_DLL_PATHS)

            # Également suspecter les DLL sans extension .dll ou avec extension bizarre
            ext = "." + image_loaded.rsplit(".", 1)[-1] if "." in image_loaded else ""
            if ext in _SUSPICIOUS_EXTENSIONS:
                is_suspicious = True

            if not is_suspicious:
                continue

            process = (
                raw.get("Image")
                or raw.get("image")
                or ev.process_name
                or "unknown"
            )
            hits_by_image[image_loaded].append(ev)

        detections: List[Detection] = []
        for dll_path, evs in hits_by_image.items():
            processes = sorted({
                (ev.raw_event or {}).get("Image") or ev.process_name or "unknown"
                for ev in evs
            })
            hosts = sorted({ev.source_host for ev in evs if ev.source_host})
            desc = (
                f"DLL sideloading : «{dll_path}» chargée par "
                f"{', '.join(processes[:3])} ({len(evs)} fois) "
                f"sur {', '.join(hosts[:3]) or 'inconnu'}."
            )
            detections.append(
                self.create_detection(
                    description=desc,
                    events=sorted(evs, key=lambda e: e.timestamp)[:50],
                    entities=processes[:4] + hosts[:3],
                    confidence=0.75,
                )
            )
        return detections


class LOLBinExecutionRule(BaseRule):
    """DLL-002 — LOLBins: rundll32/regsvr32/mshta avec arguments suspects."""

    rule_id = "DLL-002"
    rule_name = "LOLBins Suspects — rundll32/regsvr32/mshta (T1574.001)"
    description = (
        "Exécution d'un binaire LOLBin (rundll32, regsvr32, mshta…) avec "
        "des arguments indiquant un chargement réseau, un script inline ou "
        "une technique de proxy execution."
    )
    severity = Severity.HIGH
    mitre_tactic = "Defense Evasion / Execution"
    mitre_technique = "Hijack Execution Flow: DLL Search Order Hijacking"
    mitre_id = "T1574.001"

    def evaluate(self, events: List[NormalizedEvent]) -> List[Detection]:
        hits: list[NormalizedEvent] = []

        for ev in events:
            if ev.event_id not in (4688, 1):  # 4688 natif, 1 Sysmon
                continue

            raw = ev.raw_event or {}
            cmd = (
                raw.get("CommandLine")
                or raw.get("commandLine")
                or raw.get("ProcessCommandLine")
                or ""
            ).lower()
            new_process = (
                raw.get("NewProcessName")
                or raw.get("Image")
                or raw.get("image")
                or ev.process_name
                or ""
            ).lower()

            # Vérifier LOLBin
            binary = new_process.rsplit("\\", 1)[-1] if "\\" in new_process else new_process
            if binary not in _LOLBINS:
                continue

            # Vérifier arguments suspects
            if not any(arg in cmd for arg in _LOLBIN_SUSPICIOUS_ARGS):
                continue

            hits.append(ev)

        if not hits:
            return []

        hits_sorted = sorted(hits, key=lambda e: e.timestamp)
        by_binary: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for ev in hits_sorted:
            raw = ev.raw_event or {}
            proc = (raw.get("NewProcessName") or raw.get("Image") or ev.process_name or "unknown").lower()
            binary = proc.rsplit("\\", 1)[-1] if "\\" in proc else proc
            by_binary[binary].append(ev)

        detections: List[Detection] = []
        for binary, evs in by_binary.items():
            hosts = sorted({ev.source_host for ev in evs if ev.source_host})
            cmds = list({
                (ev.raw_event or {}).get("CommandLine") or ""
                for ev in evs if (ev.raw_event or {}).get("CommandLine")
            })[:3]
            desc = (
                f"LOLBin suspect : «{binary}» exécuté {len(evs)} fois "
                f"sur {', '.join(hosts[:3]) or 'inconnu'}. "
                f"Exemples d'args: {' | '.join(cmds[:2])}"
            )
            detections.append(
                self.create_detection(
                    description=desc,
                    events=evs[:100],
                    entities=[binary] + hosts[:4],
                    confidence=0.80,
                )
            )
        return detections


class CreateRemoteThreadRule(BaseRule):
    """DLL-003 — Sysmon 8: CreateRemoteThread — injection de code."""

    rule_id = "DLL-003"
    rule_name = "CreateRemoteThread — Injection de code (Sysmon 8)"
    description = (
        "Création de thread distant (Sysmon EventID 8) dans un processus "
        "cible — technique d'injection de code DLL ou shellcode (T1055)."
    )
    severity = Severity.CRITICAL
    mitre_tactic = "Defense Evasion / Privilege Escalation"
    mitre_technique = "Process Injection"
    mitre_id = "T1055"

    def evaluate(self, events: List[NormalizedEvent]) -> List[Detection]:
        hits: list[NormalizedEvent] = []

        for ev in events:
            if ev.event_id != 8:
                continue

            raw = ev.raw_event or {}
            source_image = (
                raw.get("SourceImage")
                or raw.get("sourceImage")
                or ""
            ).lower()
            target_image = (
                raw.get("TargetImage")
                or raw.get("targetImage")
                or ""
            ).lower()

            target_binary = (
                target_image.rsplit("\\", 1)[-1] if "\\" in target_image else target_image
            )

            # Exclure les injections connues légitimes (AV, EDR, debuggers)
            if target_binary in _LEGIT_INJECT_TARGETS and (
                "\\windows\\system32\\" in source_image
                or "\\program files\\" in source_image
            ):
                continue

            hits.append(ev)

        if not hits:
            return []

        hits_sorted = sorted(hits, key=lambda e: e.timestamp)
        by_pair: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
        for ev in hits_sorted:
            raw = ev.raw_event or {}
            src = (raw.get("SourceImage") or "").lower().rsplit("\\", 1)[-1]
            tgt = (raw.get("TargetImage") or "").lower().rsplit("\\", 1)[-1]
            by_pair[(src, tgt)].append(ev)

        detections: List[Detection] = []
        for (src, tgt), evs in by_pair.items():
            hosts = sorted({ev.source_host for ev in evs if ev.source_host})
            desc = (
                f"CreateRemoteThread : «{src}» injecte dans «{tgt}» "
                f"({len(evs)} événement(s)) sur {', '.join(hosts[:3]) or 'inconnu'}."
            )
            detections.append(
                self.create_detection(
                    description=desc,
                    events=evs[:50],
                    entities=[src, tgt] + hosts[:3],
                    confidence=0.88,
                )
            )
        return detections
