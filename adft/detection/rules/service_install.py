"""Service installation / persistence rules."""

from __future__ import annotations

import re
from typing import List

from adft.core.models.events import Detection, NormalizedEvent, Severity
from adft.detection.rules.base_rule import BaseRule


class SuspiciousServiceInstalledRule(BaseRule):
    """7045 (System) ou 4697 (Security) -> service installé."""

    rule_id = "PERS-7045"
    rule_name = "Service installé (suspect)"
    description = "Installation d'un service Windows (EventID 7045/4697). Peut indiquer persistance / remote service creation."
    severity = Severity.HIGH
    mitre_tactic = "Persistence"
    mitre_technique = "Create or Modify System Process"
    mitre_id = "T1543.003"  # Windows Service

    _SVC_NAME_PAT = re.compile(r"(mssecsvc|psexec|remcom|paexec|cobalt|beacon|meterpreter)", re.I)

    def evaluate(self, events: List[NormalizedEvent]) -> List[Detection]:
        hits: List[NormalizedEvent] = []
        for ev in events:
            if ev.event_id not in (7045, 4697):
                continue
            raw = getattr(ev, "raw_event", None) or {}
            ed = raw.get("EventData") or {}
            # 7045: ServiceName/ImagePath souvent dans EventData
            service_name = ""
            image_path = ""
            if isinstance(ed, dict):
                service_name = str(ed.get("ServiceName") or ed.get("Service Name") or "")
                image_path = str(ed.get("ImagePath") or ed.get("Image Path") or "")
            blob = f"{service_name} {image_path} {raw.get('message','')}"
            # on garde tout, mais on boost confidence si nom/path suspect
            if blob.strip():
                hits.append(ev)

        if not hits:
            return []

        # une détection par événement (lisible)
        detections: List[Detection] = []
        for ev in hits[:50]:
            raw = getattr(ev, "raw_event", None) or {}
            ed = raw.get("EventData") or {}
            service_name = ""
            image_path = ""
            if isinstance(ed, dict):
                service_name = str(ed.get("ServiceName") or "")
                image_path = str(ed.get("ImagePath") or "")
            host = ev.target_host or ev.source_host or ""
            conf = 0.65
            if self._SVC_NAME_PAT.search(f"{service_name} {image_path}"):
                conf = 0.85
            desc = "Service installé"
            if service_name:
                desc += f" | name={service_name}"
            if image_path:
                desc += f" | path={image_path}"
            if host:
                desc += f" | host={host}"
            detections.append(self.create_detection(desc, [ev], entities=[host] if host else [], confidence=conf))

        return detections
