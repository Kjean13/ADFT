"""
=========================================================
Règle de détection abstraite — Contrat pour toutes les règles
=========================================================

Chaque règle de détection ADFT hérite de BaseRule et implémente
la méthode evaluate(). Cette architecture garantit :

  • L'indépendance des règles entre elles
  • L'extensibilité du système (ajout de règles sans risque)
  • La traçabilité via le mapping MITRE ATT&CK

Anatomie d'une règle :
  1. Métadonnées : ID, nom, sévérité, mapping MITRE
  2. Logique d'évaluation : analyse des événements normalisés
  3. Génération de détections : résultats structurés

Le moteur de détection exécute chaque règle de manière
indépendante sur la liste complète des événements normalisés.
"""

from __future__ import annotations

import uuid
import hashlib
from abc import ABC, abstractmethod
from datetime import datetime
from typing import ClassVar

from adft.core.models.events import (
    Detection,
    NormalizedEvent,
    Severity,
)


class BaseRule(ABC):
    """
    Classe abstraite pour les règles de détection AD.

    Chaque règle doit définir :
      • rule_id         : Identifiant unique (ex: "KERB-001")
      • rule_name       : Nom lisible (ex: "Kerberoasting Détecté")
      • description     : Description de la menace
      • severity        : Niveau de sévérité par défaut
      • mitre_tactic    : Tactique MITRE ATT&CK
      • mitre_technique : Technique MITRE ATT&CK
      • mitre_id        : Identifiant MITRE (ex: "T1558.003")

    Et implémenter :
      • evaluate()      : Logique d'analyse des événements
    """

    # Métadonnées de la règle — à surcharger dans chaque sous-classe
    rule_id: ClassVar[str] = ""
    rule_name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    severity: ClassVar[Severity] = Severity.MEDIUM
    mitre_tactic: ClassVar[str] = ""
    mitre_technique: ClassVar[str] = ""
    mitre_id: ClassVar[str] = ""

    @abstractmethod
    def evaluate(
        self, events: list[NormalizedEvent]
    ) -> list[Detection]:
        """
        Évalue la règle sur une liste d'événements normalisés.

        C'est la méthode CŒUR de chaque règle. Elle analyse
        les événements et génère des détections pour tout
        pattern suspect identifié.

        Args:
            events: Liste complète des événements normalisés.

        Returns:
            Liste des détections générées (peut être vide).
        """
        ...


    @staticmethod
    def _stable_detection_id(
        rule_id: str,
        timestamp: datetime,
        description: str,
        entities: list[str],
    ) -> str:
        """Generate a deterministic ID for a detection.

        We avoid uuid4() so repeated runs on the same input logs produce
        stable IDs (useful for diffing, tests, and SOC case tracking).
        """
        ts = timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp)
        ent = ",".join(sorted({str(e) for e in (entities or []) if e}))
        payload = "|".join([rule_id or "", ts, description or "", ent])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def create_detection(
        self,
        description: str,
        events: list[NormalizedEvent],
        entities: list[str],
        confidence: float = 0.7,
        severity_override: Severity | None = None,
    ) -> Detection:
        """
        Fabrique une détection avec les métadonnées de la règle.

        Méthode utilitaire pour simplifier la création de
        détections dans les sous-classes.

        Args:
            description: Description spécifique de cette détection.
            events: Événements déclencheurs.
            entities: Entités impliquées (users, hosts).
            confidence: Niveau de confiance [0.0 - 1.0].
            severity_override: Sévérité spécifique (sinon celle de la règle).

        Returns:
            Détection structurée et prête à être corrélée.
        """

        # ------------------------------------------------------------
        # AUTO-ENTITY: enrich entities from triggering events
        # ------------------------------------------------------------
        ent_set = set([e for e in (entities or []) if e])
        for ev in events or []:
            # NormalizedEvent attributes
            for val in (
                getattr(ev, "user", None),
                getattr(ev, "source_host", None),
                getattr(ev, "target_host", None),
                getattr(ev, "ip_address", None),
            ):
                if val:
                    ent_set.add(str(val))
        entities = sorted(ent_set)
        # Le timestamp de la détection est celui du premier événement
        timestamp = min(e.timestamp for e in events) if events else datetime.now()

        return Detection(
            id=self._stable_detection_id(self.rule_id, timestamp, description, entities),
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=description,
            severity=severity_override or self.severity,
            mitre_tactic=self.mitre_tactic,
            mitre_technique=self.mitre_technique,
            mitre_id=self.mitre_id,
            events=events,
            timestamp=timestamp,
            entities=[e for e in entities if e],  # Filtrer les vides
            confidence=confidence,
        )