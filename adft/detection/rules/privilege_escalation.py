"""
=========================================================
Règles de détection — Élévation de privilèges
=========================================================

L'élévation de privilèges est une étape CRITIQUE dans
toute attaque AD. L'attaquant cherche à passer d'un
compte standard à un compte administrateur du domaine.

Vecteurs courants :
  • Ajout direct à un groupe privilégié (Domain Admins, etc.)
  • Création d'un compte backdoor avec privilèges élevés
  • Exploitation de délégations Kerberos
  • Abus de GPO (Group Policy Objects)

Événements Windows surveillés :
  4728 : Ajout à un groupe global de sécurité
  4732 : Ajout à un groupe local de sécurité
  4756 : Ajout à un groupe universel de sécurité
  4672 : Attribution de privilèges spéciaux
  4720 : Création de compte utilisateur
"""

from __future__ import annotations

from adft.core.models.events import Detection, NormalizedEvent, Severity
from adft.detection.rules.base_rule import BaseRule


# Groupes Active Directory à hauts privilèges
# L'ajout d'un membre à ces groupes est TOUJOURS significatif
PRIVILEGED_GROUPS: set[str] = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "account operators",
    "backup operators",
    "server operators",
    "print operators",
    "dnsadmins",
    "group policy creator owners",
    "admins du domaine",       # Nom français
    "administrateurs",         # Nom français
}


class PrivilegedGroupModificationRule(BaseRule):
    """
    Détecte les ajouts de membres à des groupes privilégiés AD.

    C'est l'une des détections les plus CRITIQUES :
    l'ajout d'un compte à "Domain Admins" ou "Enterprise Admins"
    peut signifier qu'un attaquant a obtenu le contrôle du domaine.

    En environnement sain, ces modifications sont RARES et
    doivent être corrélées avec des demandes de changement (RFC).

    MITRE ATT&CK : T1098 — Account Manipulation
    """

    rule_id = "PRIV-001"
    rule_name = "Modification de groupe privilégié"
    description = "Membre ajouté à un groupe de sécurité à hauts privilèges"
    severity = Severity.CRITICAL
    mitre_tactic = "Privilege Escalation"
    mitre_technique = "Account Manipulation"
    mitre_id = "T1098"

    def evaluate(self, events: list[NormalizedEvent]) -> list[Detection]:
        """
        Recherche les événements 4728/4732/4756 ciblant
        des groupes à hauts privilèges.
        """
        detections: list[Detection] = []

        # Événements d'ajout à un groupe de sécurité
        group_events = [
            e for e in events if e.event_id in (4728, 4732, 4756)
        ]

        for event in group_events:
            group = (event.group_name or "").lower()

            # Vérifier si le groupe est dans la liste des groupes critiques
            if any(priv_group in group for priv_group in PRIVILEGED_GROUPS):
                detection = self.create_detection(
                    description=(
                        f"Élévation de privilèges : '{event.target_user}' "
                        f"ajouté au groupe '{event.group_name}' "
                        f"par '{event.user}' sur '{event.target_host}'"
                    ),
                    events=[event],
                    entities=[
                        event.user,
                        event.target_user or "",
                        event.group_name or "",
                    ],
                    confidence=0.90,
                )
                detections.append(detection)

        return detections


class SpecialPrivilegeAssignmentRule(BaseRule):
    """
    Détecte l'attribution de privilèges spéciaux lors d'un logon.

    L'événement 4672 est généré quand un utilisateur se connecte
    avec des privilèges administrateur (SeDebugPrivilege,
    SeBackupPrivilege, etc.).

    En soi, cet événement est normal pour les vrais admins.
    Il devient suspect quand :
      • Un compte non-admin obtient ces privilèges
      • Les connexions admin se multiplient inhabituellement
      • La source de connexion est inhabituelle

    MITRE ATT&CK : T1078 — Valid Accounts
    """

    rule_id = "PRIV-002"
    rule_name = "Privilèges spéciaux assignés"
    description = "Connexion avec privilèges administrateur détectée"
    severity = Severity.MEDIUM
    mitre_tactic = "Privilege Escalation"
    mitre_technique = "Valid Accounts"
    mitre_id = "T1078"

    def evaluate(self, events: list[NormalizedEvent]) -> list[Detection]:
        """
        Identifie les attributions de privilèges spéciaux (4672)
        en se concentrant sur les cas inhabituels.
        """
        detections: list[Detection] = []

        priv_events = [e for e in events if e.event_id == 4672]

        # Comptes système à ignorer — ces logons sont normaux
        system_accounts = {
            "system", "local service", "network service",
            "dwm-1", "dwm-2", "umfd-0", "umfd-1",
        }

        for event in priv_events:
            user_lower = event.user.lower()

            # Ignorer les comptes système Windows
            if user_lower in system_accounts or user_lower.endswith("$"):
                continue

            detection = self.create_detection(
                description=(
                    f"Privilèges spéciaux assignés à '{event.user}' "
                    f"lors d'une connexion depuis '{event.source_host}'"
                ),
                events=[event],
                entities=[event.user, event.source_host],
                confidence=0.50,
                severity_override=Severity.MEDIUM,
            )
            detections.append(detection)

        return detections


class SuspiciousAccountCreationRule(BaseRule):
    """
    Détecte la création de comptes utilisateur suspects.

    Les attaquants créent parfois des comptes "backdoor" pour
    maintenir leur accès au domaine. Ces créations sont
    suspectes quand :
      • Le compte est créé en dehors des heures ouvrées
      • Le nom du compte imite un compte système
      • Le compte est immédiatement ajouté à un groupe admin

    MITRE ATT&CK : T1136.002 — Create Account: Domain Account
    """

    rule_id = "PRIV-003"
    rule_name = "Création de compte suspecte"
    description = "Nouveau compte utilisateur créé dans le domaine"
    severity = Severity.MEDIUM
    mitre_tactic = "Persistence"
    mitre_technique = "Create Account"
    mitre_id = "T1136.002"

    def evaluate(self, events: list[NormalizedEvent]) -> list[Detection]:
        """
        Détecte les créations de comptes (4720) et évalue
        leur niveau de suspicion.
        """
        detections: list[Detection] = []

        creation_events = [e for e in events if e.event_id == 4720]

        for event in creation_events:
            if not event.user:
                continue

            # Évaluer la suspicion de la création
            confidence = 0.50
            severity = Severity.MEDIUM

            # Créations en dehors des heures ouvrées (avant 7h ou après 20h)
            if event.timestamp.hour < 7 or event.timestamp.hour > 20:
                confidence += 0.15
                severity = Severity.HIGH

            # Noms imitant des comptes système
            suspicious_names = ["svc", "admin", "backup", "system", "sql"]
            target = (event.target_user or "").lower()
            if any(name in target for name in suspicious_names):
                confidence += 0.10

            detection = self.create_detection(
                description=(
                    f"Compte '{event.target_user}' créé par '{event.user}' "
                    f"sur '{event.target_host}' à {event.timestamp.strftime('%H:%M')}"
                ),
                events=[event],
                entities=[event.user, event.target_user or ""],
                confidence=min(confidence, 0.95),
                severity_override=severity,
            )
            detections.append(detection)

        return detections