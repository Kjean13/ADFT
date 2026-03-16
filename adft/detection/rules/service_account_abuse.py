"""Service account abuse detection rules — T1078.002 / T1558.003.

SVC-001 : Logon interactif (type 2) d'un compte de service.
SVC-002 : Kerberoasting ciblant un compte de service (4769 + RC4 + écrémage).
SVC-003 : Changement de mot de passe d'un compte de service (4723/4724).
"""

from __future__ import annotations

from collections import defaultdict
from typing import List

from adft.core.models.events import Detection, NormalizedEvent, Severity
from adft.detection.rules.base_rule import BaseRule

# Préfixes/suffixes courants des comptes de service dans les environnements AD
_SVC_PREFIXES = ("svc_", "svc-", "service_", "srv_", "sa_", "app_", "_svc")
_SVC_SUFFIXES = ("_svc", "_service", "_app", "_sa", "$")

# Comptes systèmes exclus (SYSTEM, NETWORK SERVICE…)
_SYSTEM_ACCOUNTS = {
    "system",
    "network service",
    "local service",
    "anonymous logon",
    "iusr",
    "iwam_",
    "aspnet",
    "-",
    "",
}

# Chiffrement RC4 (ticket Kerberos faible = cible Kerberoasting)
_RC4_ENCRYPTION_TYPES = {
    "0x17",  # rc4-hmac
    "23",    # rc4-hmac (décimal)
    "rc4",
    "rc4-hmac",
    "rc4_hmac",
}

# Seuil pour détecter écrémage massif (plusieurs comptes en peu de temps)
_KERBEROASTING_BURST_THRESHOLD = 3


def _is_service_account(username: str) -> bool:
    """Heuristique pour identifier un compte de service AD."""
    if not username:
        return False
    u = username.lower().strip()
    if u in _SYSTEM_ACCOUNTS:
        return False
    if any(u.startswith(p) for p in _SVC_PREFIXES):
        return True
    if any(u.endswith(s) for s in _SVC_SUFFIXES):
        return True
    return False


class ServiceAccountInteractiveLogonRule(BaseRule):
    """SVC-001 — Logon interactif (type 2) d'un compte de service."""

    rule_id = "SVC-001"
    rule_name = "Logon interactif compte de service (4624 type 2)"
    description = (
        "Connexion interactive (LogonType=2) d'un compte de service "
        "— comportement anormal pouvant indiquer une compromission ou "
        "une utilisation abusive des credentials de service."
    )
    severity = Severity.HIGH
    mitre_tactic = "Privilege Escalation / Lateral Movement"
    mitre_technique = "Valid Accounts: Domain Accounts"
    mitre_id = "T1078.002"

    def evaluate(self, events: List[NormalizedEvent]) -> List[Detection]:
        hits_by_user: dict[str, list[NormalizedEvent]] = defaultdict(list)

        for ev in events:
            if ev.event_id != 4624:
                continue

            lt_raw = getattr(ev, "logon_type", None)
            if lt_raw is None:
                lt_raw = (ev.raw_event or {}).get("LogonType") or (ev.raw_event or {}).get("logon_type")
            try:
                lt = int(str(lt_raw or "0").strip())
            except ValueError:
                lt = 0

            if lt != 2:  # Logon interactif uniquement
                continue

            user = ev.user or (ev.raw_event or {}).get("TargetUserName") or ""
            if not _is_service_account(user):
                continue

            hits_by_user[user].append(ev)

        detections: List[Detection] = []
        for user, evs in hits_by_user.items():
            hosts = sorted({ev.source_host or ev.target_host for ev in evs if ev.source_host or ev.target_host})
            desc = (
                f"Logon interactif du compte de service «{user}» "
                f"sur {', '.join(hosts[:4]) or 'inconnu'} ({len(evs)} fois) — "
                "comportement anormal."
            )
            detections.append(
                self.create_detection(
                    description=desc,
                    events=sorted(evs, key=lambda e: e.timestamp)[:100],
                    entities=[user] + hosts[:4],
                    confidence=0.80,
                )
            )
        return detections


class KerberoastingServiceAccountRule(BaseRule):
    """SVC-002 — Kerberoasting: 4769 RC4 ciblant des comptes de service."""

    rule_id = "SVC-002"
    rule_name = "Kerberoasting comptes de service — RC4 (4769)"
    description = (
        "Demande de ticket TGS (4769) avec chiffrement RC4 (0x17) pour "
        "un ou plusieurs comptes de service — indicateur de Kerberoasting "
        "visant à cracker le hash offline."
    )
    severity = Severity.CRITICAL
    mitre_tactic = "Credential Access"
    mitre_technique = "Steal or Forge Kerberos Tickets: Kerberoasting"
    mitre_id = "T1558.003"

    def evaluate(self, events: List[NormalizedEvent]) -> List[Detection]:
        hits_by_requester: dict[str, list[NormalizedEvent]] = defaultdict(list)

        for ev in events:
            if ev.event_id != 4769:
                continue

            raw = ev.raw_event or {}
            enc_type = (
                getattr(ev, "ticket_encryption", None)
                or raw.get("TicketEncryptionType")
                or raw.get("ticketEncryptionType")
                or ""
            ).lower().strip()

            if enc_type not in _RC4_ENCRYPTION_TYPES:
                continue

            service = (
                getattr(ev, "service_name", None)
                or raw.get("ServiceName")
                or raw.get("serviceName")
                or ""
            )

            # Filtrer les services système ($krbtgt, CIFS$, etc. non-SPN-based)
            if not service or service.lower() in ("krbtgt", "krbtgt/", ""):
                continue

            requester = ev.user or raw.get("SubjectUserName") or "unknown"
            hits_by_requester[requester].append(ev)

        detections: List[Detection] = []
        for requester, evs in hits_by_requester.items():
            svcs = sorted({
                (ev.raw_event or {}).get("ServiceName") or (ev.raw_event or {}).get("serviceName") or ""
                for ev in evs
            })
            hosts = sorted({ev.source_host for ev in evs if ev.source_host})
            severity = Severity.CRITICAL if len(svcs) >= _KERBEROASTING_BURST_THRESHOLD else Severity.HIGH
            desc = (
                f"Kerberoasting : «{requester}» a demandé {len(evs)} ticket(s) RC4 "
                f"pour {len(svcs)} service(s): {', '.join(svcs[:5])}. "
                f"Source: {', '.join(hosts[:3]) or 'inconnu'}."
            )
            detections.append(
                self.create_detection(
                    description=desc,
                    events=sorted(evs, key=lambda e: e.timestamp)[:100],
                    entities=[requester] + svcs[:5] + hosts[:3],
                    confidence=0.90,
                    severity_override=severity,
                )
            )
        return detections


class ServiceAccountPasswordChangeRule(BaseRule):
    """SVC-003 — Changement de mot de passe d'un compte de service (4723/4724)."""

    rule_id = "SVC-003"
    rule_name = "Changement MDP compte de service (4723/4724)"
    description = (
        "Tentative de changement (4723) ou réinitialisation (4724) de mot de "
        "passe d'un compte de service — peut indiquer une prise de contrôle "
        "ou une altération de credentials."
    )
    severity = Severity.HIGH
    mitre_tactic = "Persistence / Credential Access"
    mitre_technique = "Valid Accounts: Domain Accounts"
    mitre_id = "T1078.002"

    def evaluate(self, events: List[NormalizedEvent]) -> List[Detection]:
        hits_by_target: dict[str, list[NormalizedEvent]] = defaultdict(list)

        for ev in events:
            if ev.event_id not in (4723, 4724):
                continue

            raw = ev.raw_event or {}
            target_user = (
                getattr(ev, "target_user", None)
                or raw.get("TargetUserName")
                or raw.get("targetUserName")
                or ev.user
                or ""
            )

            if not _is_service_account(target_user):
                continue

            hits_by_target[target_user].append(ev)

        detections: List[Detection] = []
        for target, evs in hits_by_target.items():
            actors = sorted({
                (ev.raw_event or {}).get("SubjectUserName") or ev.user or "inconnu"
                for ev in evs
            })
            hosts = sorted({ev.source_host or ev.target_host for ev in evs if ev.source_host or ev.target_host})
            event_ids = sorted({ev.event_id for ev in evs})
            desc = (
                f"Mot de passe du compte de service «{target}» modifié "
                f"(EventIDs {event_ids}) par {', '.join(actors[:3])} "
                f"depuis {', '.join(hosts[:3]) or 'inconnu'}."
            )
            detections.append(
                self.create_detection(
                    description=desc,
                    events=sorted(evs, key=lambda e: e.timestamp)[:50],
                    entities=[target] + actors[:3] + hosts[:3],
                    confidence=0.85,
                )
            )
        return detections
