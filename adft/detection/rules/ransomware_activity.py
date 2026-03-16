"""Ransomware behavior detection rules.

Ces règles couvrent des signaux classiques ransomware côté Windows/AD.
Elles sont volontairement *déterministes* et basées sur
les Event IDs / champs bruts les plus fréquents.

Règles incluses (v1):
- 4663 burst: activité d'accès fichiers anormale (souvent encryption)
- Shadow copy deletion: vssadmin / wmics shadowcopy delete
- AV/EDR stop attempts: sc stop / net stop sur services AV connus

NOTE: ces règles sont heuristiques. Elles ne remplacent pas un EDR,
mais sont très utiles en démo SOC / DFIR.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta
from typing import List

from adft.core.models.events import Detection, NormalizedEvent, Severity
from adft.detection.rules.base_rule import BaseRule


_SUSPICIOUS_EXTENSIONS = {
    ".wncry",
    ".wannacry",
    ".lockbit",
    ".encrypted",
    ".encrypt",
    ".crypt",
    ".blackcat",
    ".alphp",
    ".ryuk",
    ".conti",
}

_AV_SERVICE_HINTS = [
    "windefend",
    "defender",
    "sense",
    "wdnissvc",
    "symantec",
    "sep",
    "mcafee",
    "crowdstrike",
    "csagent",
    "falcon",
    "carbonblack",
    "cb",
    "kaspersky",
    "eset",
]


def _raw(ev: NormalizedEvent) -> dict:
    return getattr(ev, "raw_event", None) or {}


def _get_object_name(raw: dict) -> str:
    # 4663: ObjectName dans EventData
    ed = raw.get("EventData") or {}
    if isinstance(ed, dict):
        for k in ("ObjectName", "ObjectName ", "Object", "FileName", "TargetFilename"):
            v = ed.get(k)
            if v:
                return str(v)
    # fallback message
    msg = raw.get("message") or raw.get("Message")
    return str(msg or "")


class FileEncryptionBurstRule(BaseRule):
    """4663 burst -> indicative encryption / mass modification."""

    rule_id = "RANS-4663"
    rule_name = "Burst accès fichiers (suspicion chiffrement)"
    description = "Burst 4663 sur un hôte (accès fichiers massif) compatible avec activité ransomware."
    severity = Severity.CRITICAL
    mitre_tactic = "Impact"
    mitre_technique = "Data Encrypted for Impact"
    mitre_id = "T1486"

    def evaluate(self, events: List[NormalizedEvent]) -> List[Detection]:
        # regroupe par host sur fenêtre glissante (simple)
        by_host: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for ev in events:
            if ev.event_id != 4663:
                continue
            host = ev.target_host or ev.source_host or ""
            if not host:
                continue
            by_host[host].append(ev)

        detections: List[Detection] = []
        for host, evs in by_host.items():
            if len(evs) < 80:  # seuil (démos)
                continue

            # fenêtre (évite faux positifs sur longues périodes)
            evs_sorted = sorted(evs, key=lambda e: e.timestamp)
            window = timedelta(minutes=10)
            start = evs_sorted[0].timestamp
            end = evs_sorted[-1].timestamp
            if (end - start) > timedelta(hours=2):
                # trop étalé = probablement bruit
                continue

            suspicious_ext = set()
            sample_files = []
            for ev in evs_sorted[:400]:
                obj = _get_object_name(_raw(ev)).lower()
                for ext in _SUSPICIOUS_EXTENSIONS:
                    if ext in obj:
                        suspicious_ext.add(ext)
                if obj and len(sample_files) < 5:
                    sample_files.append(obj)

            desc = (
                f"Activité 4663 massive sur {host} (count={len(evs_sorted)})"
            )
            if suspicious_ext:
                desc += f" | extensions suspectes: {', '.join(sorted(suspicious_ext))}"
            if sample_files:
                desc += f" | exemples: {', '.join(sample_files[:3])}"

            detections.append(
                self.create_detection(
                    description=desc,
                    events=evs_sorted[:200],
                    entities=[host],
                    confidence=0.85 if suspicious_ext else 0.7,
                )
            )

        return detections


class ShadowCopyDeletionRule(BaseRule):
    """Détection suppression VSS (vssadmin/wmic)."""

    rule_id = "RANS-VSS"
    rule_name = "Suppression Shadow Copies (VSS)"
    description = "Suppression des Shadow Copies (VSS) via vssadmin/wmic - indicateur ransomware."
    severity = Severity.HIGH
    mitre_tactic = "Impact"
    mitre_technique = "Inhibit System Recovery"
    mitre_id = "T1490"

    _PAT = re.compile(r"\b(vssadmin|wmic)\b.*\b(delete|shadowcopy|shadows)\b", re.I)

    def evaluate(self, events: List[NormalizedEvent]) -> List[Detection]:
        hits: List[NormalizedEvent] = []
        for ev in events:
            if ev.event_id not in (4688, 1):
                continue
            raw = _raw(ev)
            img = (raw.get("Image") or raw.get("process") or raw.get("ProcessName") or "")
            cmd = (raw.get("CommandLine") or raw.get("command_line") or raw.get("cmdline") or "")
            blob = f"{img} {cmd} {raw.get('message','')}"
            if self._PAT.search(blob):
                hits.append(ev)

        if not hits:
            return []

        # 1 détection globale (pour démo)
        host = hits[0].target_host or hits[0].source_host or ""
        desc = "Suppression de Shadow Copies détectée (vssadmin/wmic)."
        return [self.create_detection(desc, hits[:50], entities=[host] if host else [], confidence=0.8)]


class AVStopAttemptRule(BaseRule):
    """Tentatives d'arrêt de services AV/EDR (sc stop / net stop)."""

    rule_id = "RANS-AVSTOP"
    rule_name = "Tentative arrêt AV/EDR"
    description = "Tentatives d'arrêt de services AV/EDR via sc/net stop - défense évasion pré-ransomware."
    severity = Severity.HIGH
    mitre_tactic = "Defense Evasion"
    mitre_technique = "Disable or Modify Tools"
    mitre_id = "T1562.001"

    def evaluate(self, events: List[NormalizedEvent]) -> List[Detection]:
        hits: List[NormalizedEvent] = []
        for ev in events:
            if ev.event_id not in (4688, 1):
                continue
            raw = _raw(ev)
            cmd = (raw.get("CommandLine") or raw.get("command_line") or "")
            if not cmd:
                cmd = str(raw.get("message") or "")
            c = cmd.lower()
            if ("sc stop" in c) or ("net stop" in c):
                if any(h in c for h in _AV_SERVICE_HINTS):
                    hits.append(ev)

        if not hits:
            return []

        host = hits[0].target_host or hits[0].source_host or ""
        desc = "Tentatives d'arrêt AV/EDR détectées (sc stop / net stop)."
        return [self.create_detection(desc, hits[:50], entities=[host] if host else [], confidence=0.75)]
