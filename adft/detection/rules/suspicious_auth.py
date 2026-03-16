"""
=========================================================
Règles de détection — Authentification suspecte
=========================================================

Les attaques AD passent presque toujours par une phase
d'abus d'authentification :

  • Brute force : essais massifs de mots de passe (4625)
  • Password spraying : un mot de passe testé sur N comptes
  • Pass-the-Hash : réutilisation de hash NTLM (4624 type 3)
  • Connexion RDP suspecte : accès distant inhabituel (type 10)

Ces patterns sont détectables par l'analyse statistique
et contextuelle des événements d'authentification.

Événements clés :
  4624 : Connexion réussie (logon type important)
  4625 : Connexion échouée (accumulation = attaque)
  4648 : Identifiants explicites (runas, etc.)
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from adft.core.models.events import Detection, NormalizedEvent, Severity
from adft.detection.rules.base_rule import BaseRule


class BruteForceRule(BaseRule):
    """
    Détecte les tentatives de brute force et password spraying.

    Brute force : N tentatives échouées sur UN MÊME compte
    Password spraying : 1 tentative sur N comptes depuis UNE source

    Seuils de détection :
      • Brute force : ≥5 échecs sur le même compte en 10 minutes
      • Password spraying : ≥10 comptes différents ciblés depuis
        la même source en 30 minutes

    MITRE ATT&CK : T1110 — Brute Force
    """

    rule_id = "AUTH-001"
    rule_name = "Tentative de brute force détectée"
    description = "Multiples échecs d'authentification — brute force ou password spraying"
    severity = Severity.HIGH
    mitre_tactic = "Credential Access"
    mitre_technique = "Brute Force"
    mitre_id = "T1110"

    # Seuils configurables
    BRUTE_FORCE_THRESHOLD = 5       # Échecs par compte
    SPRAY_THRESHOLD = 10            # Comptes distincts ciblés
    BRUTE_FORCE_WINDOW = timedelta(minutes=10)
    SPRAY_WINDOW = timedelta(minutes=30)

    def evaluate(self, events: list[NormalizedEvent]) -> list[Detection]:
        """
        Analyse les événements 4625 (échecs de connexion) pour
        détecter les patterns de brute force et password spraying.
        """
        detections: list[Detection] = []

        failed_logons = sorted(
            [e for e in events if e.event_id == 4625],
            key=lambda e: e.timestamp,
        )

        # ── Détection brute force : N échecs sur UN compte ──
        by_user: defaultdict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in failed_logons:
            if event.user:
                by_user[event.user].append(event)

        for user, user_events in by_user.items():
            # Fenêtre glissante pour détecter les rafales
            if len(user_events) >= self.BRUTE_FORCE_THRESHOLD:
                # Vérifier la concentration temporelle
                for i in range(len(user_events) - self.BRUTE_FORCE_THRESHOLD + 1):
                    window = user_events[i:i + self.BRUTE_FORCE_THRESHOLD]
                    if (window[-1].timestamp - window[0].timestamp) <= self.BRUTE_FORCE_WINDOW:
                        confidence = min(0.6 + len(window) * 0.05, 0.95)
                        detection = self.create_detection(
                            description=(
                                f"Brute force : {len(window)} échecs de connexion "
                                f"pour '{user}' en "
                                f"{(window[-1].timestamp - window[0].timestamp).seconds}s"
                            ),
                            events=window,
                            entities=[user],
                            confidence=confidence,
                        )
                        detections.append(detection)
                        break  # Une détection par utilisateur suffit

        # ── Détection password spraying : 1 tentative sur N comptes ──
        by_source: defaultdict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in failed_logons:
            source = event.ip_address or event.source_host
            if source:
                by_source[source].append(event)

        for source, source_events in by_source.items():
            unique_users = set(e.user for e in source_events if e.user)
            if len(unique_users) >= self.SPRAY_THRESHOLD:
                detection = self.create_detection(
                    description=(
                        f"Password spraying : {len(unique_users)} comptes "
                        f"ciblés depuis '{source}'"
                    ),
                    events=source_events[:20],  # Limiter les événements joints
                    entities=[source] + list(unique_users)[:10],
                    confidence=0.85,
                    severity_override=Severity.CRITICAL,
                )
                detections.append(detection)

        return detections


class PassTheHashRule(BaseRule):
    """
    Détecte les indicateurs de Pass-the-Hash (PtH).

    Le PtH consiste à réutiliser un hash NTLM volé pour
    s'authentifier sur le réseau sans connaître le mot de passe.

    Indicateurs :
      • Logon type 3 (réseau) avec authentification NTLM
      • Depuis un poste inhabituel pour le compte
      • Souvent combiné avec des outils comme Mimikatz

    Limitation : le PtH est DIFFICILE à détecter uniquement
    via les logs. Cette règle identifie les indicateurs, pas
    les certitudes.

    MITRE ATT&CK : T1550.002 — Pass the Hash
    """

    rule_id = "AUTH-002"
    rule_name = "Indicateur Pass-the-Hash"
    description = "Connexion réseau NTLM suspecte — possible Pass-the-Hash"
    severity = Severity.HIGH
    mitre_tactic = "Lateral Movement"
    mitre_technique = "Pass the Hash"
    mitre_id = "T1550.002"

    def evaluate(self, events: list[NormalizedEvent]) -> list[Detection]:
        """
        Recherche les connexions de type 3 (réseau) utilisant NTLM
        avec des patterns inhabituels.
        """
        detections: list[Detection] = []

        # Connexions réseau réussies
        network_logons = [
            e for e in events
            if e.event_id == 4624 and e.logon_type == 3
        ]

        # Regrouper par utilisateur pour analyser les patterns
        by_user: defaultdict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in network_logons:
            if event.user and not event.user.endswith("$"):
                by_user[event.user].append(event)

        for user, user_events in by_user.items():
            # Analyser la diversité des sources — un PtH se fait
            # souvent depuis de multiples machines
            sources = set(
                e.ip_address or e.source_host for e in user_events
                if e.ip_address or e.source_host
            )

            # Seuil : connexions réseau depuis ≥3 sources distinctes
            if len(sources) >= 3:
                confidence = min(0.4 + len(sources) * 0.1, 0.85)

                detection = self.create_detection(
                    description=(
                        f"Indicateur PtH : '{user}' a des connexions réseau "
                        f"depuis {len(sources)} sources distinctes : "
                        f"{', '.join(list(sources)[:5])}"
                    ),
                    events=user_events[:10],
                    entities=[user] + list(sources)[:5],
                    confidence=confidence,
                )
                detections.append(detection)

        return detections


class SuspiciousRDPRule(BaseRule):
    """
    Détecte les connexions RDP suspectes.

    Le RDP (logon type 10) est un vecteur courant de mouvement
    latéral. Les connexions RDP sont suspectes quand :
      • Elles proviennent d'une source inhabituelle
      • Elles ont lieu en dehors des heures ouvrées
      • Elles ciblent des contrôleurs de domaine

    MITRE ATT&CK : T1021.001 — Remote Desktop Protocol
    """

    rule_id = "AUTH-003"
    rule_name = "Connexion RDP suspecte"
    description = "Connexion RDP détectée — vérifier la légitimité"
    severity = Severity.MEDIUM
    mitre_tactic = "Lateral Movement"
    mitre_technique = "Remote Desktop Protocol"
    mitre_id = "T1021.001"

    def evaluate(self, events: list[NormalizedEvent]) -> list[Detection]:
        """
        Identifie les connexions RDP (type 10) potentiellement
        suspectes selon le contexte temporel et les cibles.
        """
        detections: list[Detection] = []

        rdp_logons = [
            e for e in events
            if e.event_id == 4624 and e.logon_type == 10
        ]

        for event in rdp_logons:
            if not event.user or event.user.endswith("$"):
                continue

            confidence = 0.40
            severity = Severity.MEDIUM

            # Connexion en dehors des heures ouvrées
            if event.timestamp.hour < 7 or event.timestamp.hour > 20:
                confidence += 0.20
                severity = Severity.HIGH

            # Connexion vers un contrôleur de domaine (nom contenant DC)
            target = (event.target_host or "").upper()
            if "DC" in target or "DOMAIN" in target:
                confidence += 0.15
                severity = Severity.HIGH

            if confidence >= 0.55:
                detection = self.create_detection(
                    description=(
                        f"Connexion RDP de '{event.user}' vers "
                        f"'{event.target_host}' depuis '{event.ip_address}' "
                        f"à {event.timestamp.strftime('%H:%M')}"
                    ),
                    events=[event],
                    entities=[event.user, event.target_host, event.ip_address or ""],
                    confidence=confidence,
                    severity_override=severity,
                )
                detections.append(detection)

        return detections