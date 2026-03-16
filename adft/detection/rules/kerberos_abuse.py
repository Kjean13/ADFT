"""
=========================================================
Règles de détection — Abus du protocole Kerberos
=========================================================

Kerberos est LE protocole d'authentification d'Active Directory.
Les attaquants l'exploitent de multiples façons :

┌─────────────────────┬──────────────────────────────────────┐
│ Attaque             │ Principe                             │
├─────────────────────┼──────────────────────────────────────┤
│ Kerberoasting       │ Demander des TGS avec chiffrement    │
│                     │ RC4 pour les craquer hors-ligne       │
├─────────────────────┼──────────────────────────────────────┤
│ AS-REP Roasting     │ Exploiter les comptes sans            │
│                     │ pré-authentification requise           │
├─────────────────────┼──────────────────────────────────────┤
│ Golden Ticket       │ Forger un TGT avec le hash du         │
│                     │ compte krbtgt                          │
├─────────────────────┼──────────────────────────────────────┤
│ Silver Ticket       │ Forger un TGS pour un service         │
│                     │ spécifique                             │
└─────────────────────┴──────────────────────────────────────┘

Événements Windows clés :
  4768 (AS-REQ)  : Demande de TGT
  4769 (TGS-REQ) : Demande de ticket de service
  4771           : Échec de pré-authentification
"""

from __future__ import annotations

from collections import defaultdict

from adft.core.models.events import Detection, NormalizedEvent, Severity
from adft.detection.rules.base_rule import BaseRule


class KerberoastingRule(BaseRule):
    """
    Détecte les tentatives de Kerberoasting.

    Le Kerberoasting consiste à demander des tickets de service (TGS)
    chiffrés en RC4 pour des comptes avec SPN, puis à tenter de
    craquer le mot de passe hors-ligne.

    Indicateur : événement 4769 avec chiffrement RC4 (type 0x17).

    Le chiffrement RC4 est faible et ne devrait plus être utilisé
    dans un AD moderne. Sa présence dans une requête TGS est
    un signal fort de Kerberoasting.

    MITRE ATT&CK : T1558.003 — Kerberoasting
    """

    rule_id = "KERB-001"
    rule_name = "Kerberoasting détecté"
    description = "Requête TGS avec chiffrement RC4 — indicateur de Kerberoasting"
    severity = Severity.HIGH
    mitre_tactic = "Credential Access"
    mitre_technique = "Kerberoasting"
    mitre_id = "T1558.003"

    def evaluate(self, events: list[NormalizedEvent]) -> list[Detection]:
        """
        Analyse les requêtes TGS (4769) à la recherche de
        chiffrement RC4 (0x17), caractéristique du Kerberoasting.

        Un Kerberoasting massif se manifeste par de nombreuses
        requêtes TGS-RC4 depuis un même compte en peu de temps.
        """
        detections: list[Detection] = []

        # Filtrer les événements TGS-REQ
        tgs_events = [e for e in events if e.event_id == 4769]

        # Regrouper par utilisateur pour détecter les rafales
        user_rc4_requests: defaultdict[str, list[NormalizedEvent]] = defaultdict(list)

        for event in tgs_events:
            # 0x17 = RC4-HMAC — chiffrement faible, signal de Kerberoasting
            if event.ticket_encryption in ("0x17", "0x18", "23", "24"):
                user_rc4_requests[event.user].append(event)

        for user, rc4_events in user_rc4_requests.items():
            if not user:
                continue

            # Plusieurs requêtes RC4 = Kerberoasting probable
            # Une seule requête peut être légitime (ancienne appli)
            confidence = min(0.5 + len(rc4_events) * 0.1, 0.95)
            severity = (
                Severity.CRITICAL if len(rc4_events) >= 5
                else Severity.HIGH
            )

            services = [e.service_name for e in rc4_events if e.service_name]
            services_str = ", ".join(set(services)) or "inconnus"

            detection = self.create_detection(
                description=(
                    f"Kerberoasting : {len(rc4_events)} requête(s) TGS avec "
                    f"chiffrement RC4 par '{user}' ciblant les services : "
                    f"{services_str}"
                ),
                events=rc4_events,
                entities=[user] + list(set(services)),
                confidence=confidence,
                severity_override=severity,
            )
            detections.append(detection)

        return detections


class ASREPRoastingRule(BaseRule):
    """
    Détecte les tentatives d'AS-REP Roasting.

    L'AS-REP Roasting cible les comptes dont l'attribut
    "Ne pas exiger la pré-authentification Kerberos" est activé.

    Pour ces comptes, le KDC retourne un AS-REP chiffré avec
    le hash du mot de passe de l'utilisateur — sans vérification
    préalable. L'attaquant peut alors craquer ce hash hors-ligne.

    Indicateur : événement 4768 avec résultat de pré-auth
    indiquant l'absence de pré-authentification.

    MITRE ATT&CK : T1558.004 — AS-REP Roasting
    """

    rule_id = "KERB-002"
    rule_name = "AS-REP Roasting détecté"
    description = "Demande TGT sans pré-authentification — AS-REP Roasting"
    severity = Severity.HIGH
    mitre_tactic = "Credential Access"
    mitre_technique = "AS-REP Roasting"
    mitre_id = "T1558.004"

    def evaluate(self, events: list[NormalizedEvent]) -> list[Detection]:
        """
        Analyse les demandes TGT (4768) pour identifier les requêtes
        sans pré-authentification, caractéristiques de l'AS-REP Roasting.
        """
        detections: list[Detection] = []

        tgt_events = [e for e in events if e.event_id == 4768]

        for event in tgt_events:
            # Détection basée sur le chiffrement RC4 dans les TGT
            # et l'absence de pré-authentification
            is_rc4 = event.ticket_encryption in ("0x17", "0x18", "23", "24")
            # Le code de pré-auth 0 indique pas de pré-auth
            no_preauth = event.status in ("0x0", "0")

            if is_rc4 and no_preauth and event.user:
                detection = self.create_detection(
                    description=(
                        f"AS-REP Roasting : demande TGT sans pré-authentification "
                        f"pour le compte '{event.user}' avec chiffrement RC4"
                    ),
                    events=[event],
                    entities=[event.user],
                    confidence=0.80,
                )
                detections.append(detection)

        return detections


class GoldenTicketRule(BaseRule):
    """
    Détecte les indicateurs de Golden Ticket.

    Un Golden Ticket est un TGT forgé par l'attaquant à l'aide
    du hash du compte krbtgt. Il donne un accès illimité au
    domaine AD pendant la durée de validité du ticket.

    Indicateurs :
      • TGS (4769) pour des services krbtgt inhabituels
      • Incohérences dans les métadonnées de tickets

    MITRE ATT&CK : T1558.001 — Golden Ticket
    """

    rule_id = "KERB-003"
    rule_name = "Indicateur de Golden Ticket"
    description = "Activité suspecte liée au compte krbtgt — possible Golden Ticket"
    severity = Severity.CRITICAL
    mitre_tactic = "Credential Access"
    mitre_technique = "Golden Ticket"
    mitre_id = "T1558.001"

    def evaluate(self, events: list[NormalizedEvent]) -> list[Detection]:
        """
        Recherche les anomalies de tickets liées au compte krbtgt.

        Un Golden Ticket se manifeste souvent par des requêtes TGS
        avec des caractéristiques inhabituelles (durée de vie
        excessive, source inhabituelle).
        """
        detections: list[Detection] = []

        tgs_events = [e for e in events if e.event_id == 4769]

        for event in tgs_events:
            # Requête TGS ciblant krbtgt — très inhabituel en production
            if event.service_name and "krbtgt" in event.service_name.lower():
                detection = self.create_detection(
                    description=(
                        f"Activité Golden Ticket suspectée : requête TGS ciblant "
                        f"le service krbtgt par '{event.user}' depuis "
                        f"'{event.source_host}'"
                    ),
                    events=[event],
                    entities=[event.user, event.source_host],
                    confidence=0.75,
                )
                detections.append(detection)

        return detections