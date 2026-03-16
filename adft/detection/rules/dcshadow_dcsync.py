"""DCShadow et DCSync avancé — T1207 / T1003.006.

DC-001 : DCShadow — faux contrôleur de domaine (4742 SPN + 4929 + 5805 Netlogon).
DC-002 : DCSync avancé — 4662 avec GUIDs de réplication AD spécifiques.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import List

from adft.core.models.events import Detection, NormalizedEvent, Severity
from adft.detection.rules.base_rule import BaseRule

# GUIDs des droits de réplication AD (présents dans 4662 Properties)
_REPLICATION_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
    "89e95b76-444d-4c62-991a-0facbeda640c",  # DS-Replication-Get-Changes-In-Filtered-Set
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Synchronize
    "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Manage-Topology
}

# SPNs caractéristiques d'un faux DC (DCShadow)
_DCSHADOW_SPN_PATTERNS = (
    "gcs/",
    "e3514235-",  # GUID-based SPN for AD replication
    "ldap/",
)

# Seuil de temps pour corréler les signaux DCShadow (fenêtre glissante)
_DCSHADOW_WINDOW = timedelta(minutes=30)


class DCShadowRule(BaseRule):
    """DC-001 — DCShadow: faux DC injecté via SPN (4742 + 4929/5805)."""

    rule_id = "DC-001"
    rule_name = "DCShadow — Faux contrôleur de domaine (T1207)"
    description = (
        "Combinaison de signaux DCShadow : modification de compte ordinateur "
        "avec SPN de réplication (4742), suppression de contexte de nommage "
        "de source AD (4929) et/ou échec session Netlogon (5805)."
    )
    severity = Severity.CRITICAL
    mitre_tactic = "Defense Evasion"
    mitre_technique = "Rogue Domain Controller"
    mitre_id = "T1207"

    def evaluate(self, events: List[NormalizedEvent]) -> List[Detection]:
        # Catégoriser les événements
        evts_4742: list[NormalizedEvent] = []
        evts_4929: list[NormalizedEvent] = []
        evts_5805: list[NormalizedEvent] = []

        for ev in events:
            if ev.event_id == 4742:
                raw = ev.raw_event or {}
                spn = (
                    raw.get("ServicePrincipalNames")
                    or raw.get("servicePrincipalNames")
                    or raw.get("NewSpnList")
                    or ""
                )
                spn_lower = str(spn).lower()
                if any(p in spn_lower for p in _DCSHADOW_SPN_PATTERNS):
                    evts_4742.append(ev)
            elif ev.event_id == 4929:
                evts_4929.append(ev)
            elif ev.event_id == 5805:
                evts_5805.append(ev)

        # Signal fort : 4742 SPN + au moins un indicateur secondaire
        detections: List[Detection] = []

        if evts_4742:
            companions = evts_4929 + evts_5805
            if companions:
                all_evts = sorted(evts_4742 + companions, key=lambda e: e.timestamp)
                # Vérifier corrélation temporelle
                correlated = self._correlate_temporal(all_evts)
                if correlated:
                    hosts = sorted({ev.source_host or ev.target_host for ev in correlated if ev.source_host or ev.target_host})
                    desc = (
                        f"DCShadow possible : {len(evts_4742)} modification(s) de compte ordinateur "
                        f"avec SPN de réplication + {len(evts_4929)} suppression(s) de contexte + "
                        f"{len(evts_5805)} échec(s) Netlogon sur: {', '.join(hosts[:4]) or 'inconnu'}."
                    )
                    detections.append(
                        self.create_detection(
                            description=desc,
                            events=correlated[:100],
                            entities=hosts[:6],
                            confidence=0.90,
                        )
                    )
            else:
                # 4742 SPN seul : signal moyen
                hosts = sorted({ev.target_host or ev.source_host for ev in evts_4742 if ev.target_host or ev.source_host})
                desc = (
                    f"Modification SPN de réplication sur {len(evts_4742)} compte(s) ordinateur (4742) "
                    f"— possible préparation DCShadow. Hôtes: {', '.join(hosts[:4]) or 'inconnu'}."
                )
                detections.append(
                    self.create_detection(
                        description=desc,
                        events=sorted(evts_4742, key=lambda e: e.timestamp)[:100],
                        entities=hosts[:6],
                        confidence=0.65,
                    )
                )

        return detections

    @staticmethod
    def _correlate_temporal(events: list[NormalizedEvent]) -> list[NormalizedEvent]:
        """Retourne les événements qui se chevauchent dans la fenêtre glissante."""
        if len(events) < 2:
            return events
        first = events[0].timestamp
        last = events[-1].timestamp
        if (last - first) <= _DCSHADOW_WINDOW:
            return events
        # Fenêtre glissante : trouver le cluster le plus dense
        best_cluster: list[NormalizedEvent] = []
        for i, ev in enumerate(events):
            cluster = [e for e in events if abs((e.timestamp - ev.timestamp).total_seconds()) <= _DCSHADOW_WINDOW.total_seconds()]
            if len(cluster) > len(best_cluster):
                best_cluster = cluster
        return best_cluster


class DCSyncAdvancedRule(BaseRule):
    """DC-002 — DCSync avancé: 4662 avec GUIDs de réplication AD."""

    rule_id = "DC-002"
    rule_name = "DCSync avancé — GUIDs réplication 4662 (T1003.006)"
    description = (
        "Event 4662 (opération sur objet AD) avec les GUIDs de droits de "
        "réplication DS-Replication-Get-Changes/All — indicateur fort de DCSync "
        "(extraction des secrets NTDS)."
    )
    severity = Severity.CRITICAL
    mitre_tactic = "Credential Access"
    mitre_technique = "OS Credential Dumping: DCSync"
    mitre_id = "T1003.006"

    def evaluate(self, events: List[NormalizedEvent]) -> List[Detection]:
        hits_by_user: dict[str, list[NormalizedEvent]] = defaultdict(list)

        for ev in events:
            if ev.event_id != 4662:
                continue

            raw = ev.raw_event or {}
            properties = (
                raw.get("Properties")
                or raw.get("properties")
                or raw.get("AccessMask")
                or ""
            )
            prop_lower = str(properties).lower()

            if not any(g in prop_lower for g in _REPLICATION_GUIDS):
                continue

            # Exclure les comptes système légitimes (MSOL_, AZUREAD_)
            user = ev.user or ""
            if user.startswith("$") or user.upper() in ("MSOL_", "AZUREAD_SYNC"):
                continue

            hits_by_user[user].append(ev)

        detections: List[Detection] = []
        for user, evs in hits_by_user.items():
            hosts = sorted({ev.source_host or ev.target_host for ev in evs if ev.source_host or ev.target_host})
            desc = (
                f"DCSync détecté : {len(evs)} requête(s) de réplication AD (4662 "
                f"avec GUIDs DS-Replication) par «{user or 'inconnu'}» "
                f"depuis {', '.join(hosts[:3]) or 'inconnu'}."
            )
            detections.append(
                self.create_detection(
                    description=desc,
                    events=sorted(evs, key=lambda e: e.timestamp)[:100],
                    entities=[user] + hosts[:4],
                    confidence=0.95,
                )
            )

        return detections
