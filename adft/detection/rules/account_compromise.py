"""
=========================================================
Règles de détection — Indicateurs de compromission de comptes
=========================================================

Ces règles détectent les signes qu'un attaquant tente
de masquer sa présence ou de maintenir son accès :

  • Effacement des journaux d'audit (1102)
  • Installation de services suspects (4697)
  • Authentification NTLM échouée massivement (4776)
  • Pré-authentification Kerberos échouée (4771)

L'effacement des logs est considéré comme le signal
le plus CRITIQUE : un attaquant qui efface les logs
tente de détruire les preuves de son intrusion.
"""

from __future__ import annotations

from adft.core.models.events import Detection, NormalizedEvent, Severity
from adft.detection.rules.base_rule import BaseRule


class AuditLogClearedRule(BaseRule):
    """
    Détecte l'effacement du journal d'audit de sécurité (1102).

    L'événement 1102 est généré quand le journal de sécurité
    Windows est vidé. C'est un acte RARE et GRAVE :

      • En production, les logs de sécurité ne sont JAMAIS
        effacés manuellement
      • Un attaquant efface les logs pour masquer ses traces
      • Même une suppression "accidentelle" doit être investiguée

    C'est souvent le dernier acte d'un attaquant dans sa
    phase de "defense evasion".

    MITRE ATT&CK : T1070.001 — Clear Windows Event Logs
    """

    rule_id = "COMP-001"
    rule_name = "Journal d'audit effacé"
    description = "Le journal de sécurité Windows a été vidé — destruction de preuves"
    severity = Severity.CRITICAL
    mitre_tactic = "Defense Evasion"
    mitre_technique = "Clear Windows Event Logs"
    mitre_id = "T1070.001"

    def evaluate(self, events: list[NormalizedEvent]) -> list[Detection]:
        """
        Recherche les événements 1102 (audit log cleared).
        Chaque occurrence génère une détection CRITIQUE.
        """
        detections: list[Detection] = []

        log_cleared = [e for e in events if e.event_id == 1102]

        for event in log_cleared:
            detection = self.create_detection(
                description=(
                    f"⚠️ JOURNAL D'AUDIT EFFACÉ par '{event.user}' "
                    f"sur '{event.target_host}' à "
                    f"{event.timestamp.strftime('%Y-%m-%d %H:%M:%S')} — "
                    f"possible destruction de preuves"
                ),
                events=[event],
                entities=[event.user, event.target_host],
                confidence=0.95,
            )
            detections.append(detection)

        return detections


class SuspiciousServiceInstallRule(BaseRule):
    """
    Détecte l'installation de services suspects (4697).

    Les attaquants installent souvent des services pour :
      • Exécuter du code avec les privilèges SYSTEM
      • Maintenir la persistance après un redémarrage
      • Exécuter des outils de post-exploitation

    Exemples de services malveillants courants :
      • Services avec des chemins temporaires (\\Temp\\, \\AppData\\)
      • Services avec des noms aléatoires
      • Services exécutant PowerShell ou cmd.exe

    MITRE ATT&CK : T1543.003 — Windows Service
    """

    rule_id = "COMP-002"
    rule_name = "Installation de service suspecte"
    description = "Nouveau service installé — vérifier la légitimité"
    severity = Severity.HIGH
    mitre_tactic = "Persistence"
    mitre_technique = "Windows Service"
    mitre_id = "T1543.003"

    # Indicateurs de services malveillants
    SUSPICIOUS_PATHS = [
        "\\temp\\", "\\tmp\\", "\\appdata\\", "\\public\\",
        "\\downloads\\", "powershell", "cmd.exe", "rundll32",
        "regsvr32", "mshta", "wscript", "cscript",
    ]

    def evaluate(self, events: list[NormalizedEvent]) -> list[Detection]:
        """
        Analyse les événements 4697 (service installé) et
        évalue le niveau de suspicion du service.
        """
        detections: list[Detection] = []

        service_events = [e for e in events if e.event_id == 4697]

        for event in service_events:
            process = (event.process_name or "").lower()
            confidence = 0.50

            # Vérifier si le chemin du service contient des indicateurs suspects
            for suspicious in self.SUSPICIOUS_PATHS:
                if suspicious in process:
                    confidence += 0.15
                    break

            detection = self.create_detection(
                description=(
                    f"Service installé par '{event.user}' sur "
                    f"'{event.target_host}' : {event.process_name or 'inconnu'}"
                ),
                events=[event],
                entities=[event.user, event.target_host],
                confidence=min(confidence, 0.95),
            )
            detections.append(detection)

        return detections


class KerberosPreAuthFailureRule(BaseRule):
    """
    Détecte les échecs massifs de pré-authentification Kerberos (4771).

    Les échecs de pré-auth peuvent indiquer :
      • Une tentative de brute force Kerberos
      • Des identifiants expirés ou incorrects
      • Un AS-REP Roasting en cours

    Le seuil est de ≥5 échecs pour un même compte.

    MITRE ATT&CK : T1110.001 — Password Guessing
    """

    rule_id = "COMP-003"
    rule_name = "Échecs pré-authentification Kerberos"
    description = "Multiples échecs de pré-authentification Kerberos"
    severity = Severity.MEDIUM
    mitre_tactic = "Credential Access"
    mitre_technique = "Password Guessing"
    mitre_id = "T1110.001"

    THRESHOLD = 5

    def evaluate(self, events: list[NormalizedEvent]) -> list[Detection]:
        """
        Compte les échecs de pré-auth (4771) par utilisateur
        et détecte les accumulations suspectes.
        """
        detections: list[Detection] = []

        preauth_failures = [e for e in events if e.event_id == 4771]

        from collections import defaultdict
        by_user: defaultdict[str, list[NormalizedEvent]] = defaultdict(list)

        for event in preauth_failures:
            if event.user:
                by_user[event.user].append(event)

        for user, user_events in by_user.items():
            if len(user_events) >= self.THRESHOLD:
                detection = self.create_detection(
                    description=(
                        f"Échecs pré-auth Kerberos : {len(user_events)} "
                        f"échecs pour '{user}'"
                    ),
                    events=user_events[:20],
                    entities=[user],
                    confidence=min(0.5 + len(user_events) * 0.05, 0.90),
                )
                detections.append(detection)

        return detections