
from __future__ import annotations

from typing import Any, Dict, List


def _get(d: Dict[str, Any], *keys, default=None):
    for k in keys:
        if k in d and d.get(k) not in (None, "", []):
            return d.get(k)
    return default


def build_attack_story(events: List[Dict[str, Any]]) -> List[str]:
    """Construit une narration courte et déterministe.

    Entrée attendue: liste de dict (NormalizedEvent -> to_dict/asdict).
    """
    story: List[str] = []

    for e in events or []:
        eid = _get(e, "event_id", "eventid")
        if eid == 4625:
            user = _get(e, "user")
            story.append(f"Tentative d'authentification échouée ({user or 'user inconnu'})")
        elif eid == 4624:
            user = _get(e, "user")
            story.append(f"Authentification réussie ({user or 'user inconnu'})")
        elif eid == 4672:
            user = _get(e, "user")
            story.append(f"Privilèges spéciaux accordés ({user or 'user inconnu'})")
        elif eid == 4688:
            proc = _get(e, "process", "new_process", "image")
            story.append(f"Exécution de processus ({proc or 'process inconnu'})")
        elif eid == 4769:
            svc = _get(e, "service", "spn")
            story.append(f"Requête de ticket Kerberos (service={svc or 'inconnu'})")
        elif eid in (5140, 5145):
            share = _get(e, "share", "share_name")
            story.append(f"Accès à un partage réseau ({share or 'partage inconnu'})")

    # unique (conserve order)
    uniq: List[str] = []
    seen = set()
    for s in story:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq
