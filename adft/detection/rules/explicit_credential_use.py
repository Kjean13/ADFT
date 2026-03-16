"""
=========================================================
Règle de détection — Utilisation d'identifiants explicites
=========================================================

Cette règle identifie les événements d'authentification où des
identifiants explicites sont fournis (EventID 4648). Ces
événements peuvent apparaître lors de l'utilisation de la commande
`runas` ou de scripts qui passent des informations d'identification
directement sur la ligne de commande. Bien qu'il existe des cas
légitimes, l'apparition d'événements 4648 est suffisamment rare
pour justifier une revue de sécurité, en particulier si la
connexion provient d'une machine ou d'un compte inhabituel.

MITRE ATT&CK : T1550 — Use Alternate Authentication Material
"""

from __future__ import annotations

from adft.core.models.events import Detection, NormalizedEvent, Severity
from adft.detection.rules.base_rule import BaseRule


class ExplicitCredentialUseRule(BaseRule):
    """
    Détecte l'utilisation d'identifiants explicites (EventID 4648).

    L'événement 4648 est généré lorsqu'un processus tente
    d'authentifier un compte en fournissant explicitement des
    identifiants. Cet événement est rare dans les activités
    quotidiennes ; sa présence peut indiquer un usage de `runas`,
    l'exécution d'un script automatisé ou, dans le pire des cas,
    une tentative d'abus d'identifiants volés.

    Cette règle signale chaque occurrence de 4648 avec une
    sévérité moyenne. Les analystes doivent examiner la
    légitimité de ces opérations.
    """

    rule_id = "AUTH-004"
    rule_name = "Utilisation d'identifiants explicites"
    description = "Tentative d'authentification avec identifiants explicites détectée"
    severity = Severity.MEDIUM
    mitre_tactic = "Credential Access"
    mitre_technique = "Use Alternate Authentication Material"
    mitre_id = "T1550"

    def evaluate(self, events: list[NormalizedEvent]) -> list[Detection]:
        """
        Identifie les événements 4648 et génère une détection
        pour chacun. Aucune corrélation temporelle n'est
        effectuée car la simple apparition de cet événement est
        notable. Les analystes peuvent recourir à la corrélation
        ultérieure pour déterminer la sévérité finale.

        Args:
            events: Liste complète des événements normalisés.

        Returns:
            Liste des détections générées.
        """
        detections: list[Detection] = []
        for ev in events:
            if ev.event_id != 4648:
                continue

            # Créer une détection pour chaque événement 4648.
            description = (
                f"Authentification explicite : l'utilisateur '{ev.user}' a "
                f"présenté des identifiants explicites vers "
                f"'{ev.target_host or ev.source_host}'"
            )
            entities: list[str] = []
            if ev.user:
                entities.append(ev.user)
            if ev.target_host:
                entities.append(ev.target_host)
            elif ev.source_host:
                entities.append(ev.source_host)
            if ev.ip_address:
                entities.append(ev.ip_address)

            det = self.create_detection(
                description=description,
                events=[ev],
                entities=entities,
                confidence=0.5,
                severity_override=Severity.MEDIUM,
            )
            detections.append(det)

        return detections