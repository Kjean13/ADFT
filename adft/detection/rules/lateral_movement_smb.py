"""Lateral movement detection rules (SMB propagation heuristics)."""

from __future__ import annotations

from collections import defaultdict
from typing import List

from adft.core.models.events import Detection, NormalizedEvent, Severity
from adft.detection.rules.base_rule import BaseRule


class SMBPropagationRule(BaseRule):
    """4624 LogonType=3 depuis même IP sur plusieurs hôtes -> propagation SMB."""

    rule_id = "LM-4624-SMB"
    rule_name = "Propagation SMB (4624 type 3 multi-hôtes)"
    description = "4624 (LogonType=3) depuis une même IP sur plusieurs hôtes: suspicion propagation / mouvement latéral SMB."
    severity = Severity.HIGH
    mitre_tactic = "Lateral Movement"
    mitre_technique = "Remote Services"
    mitre_id = "T1021.002"  # SMB/Windows Admin Shares

    def evaluate(self, events: List[NormalizedEvent]) -> List[Detection]:
        # key = source_ip, value = set(target_hosts)
        hosts_by_ip: dict[str, set[str]] = defaultdict(set)
        evs_by_ip: dict[str, list[NormalizedEvent]] = defaultdict(list)

        for ev in events:
            if ev.event_id != 4624:
                continue
            # logon type 3 = network (souvent SMB)
            # Priorité : attribut normalisé > raw_event fallback
            lt_raw = getattr(ev, "logon_type", None)
            if lt_raw is None:
                lt_raw = ev.raw_event.get("LogonType") or ev.raw_event.get("logon_type")
            lt = str(lt_raw or "").strip()
            if lt != "3":
                continue

            ip = getattr(ev, "ip_address", None) or ev.raw_event.get("IpAddress") or ""
            host = ev.target_host or ev.source_host or ""
            if not ip or not host:
                continue

            hosts_by_ip[ip].add(host)
            evs_by_ip[ip].append(ev)

        detections: List[Detection] = []
        for ip, hosts in hosts_by_ip.items():
            # seuil: au moins 3 hôtes distincts
            if len(hosts) < 3:
                continue

            evs = sorted(evs_by_ip[ip], key=lambda e: e.timestamp)
            desc = f"Logons réseau (4624 type 3) depuis {ip} vers {len(hosts)} hôtes: {', '.join(sorted(list(hosts))[:6])}"
            detections.append(
                self.create_detection(
                    description=desc,
                    events=evs[:200],
                    entities=[ip] + sorted(list(hosts))[:8],
                    confidence=0.75,
                )
            )

        return detections
