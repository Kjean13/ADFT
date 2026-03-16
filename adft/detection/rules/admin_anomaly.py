"""
=========================================================
Règles de détection — Anomalies d'activité administrateur
=========================================================

Les comptes administrateurs AD sont les cibles prioritaires
des attaquants. Les anomalies dans leur utilisation sont
des signaux d'alerte importants :

  • Activité admin en dehors des heures ouvrées
  • Connexions admin depuis des postes inhabituels
  • Usage simultané de multiples comptes admin
  • Logon admin interactif sur un serveur

Ces anomalies ne sont pas forcément des attaques,
mais nécessitent toujours une vérification.
"""

from __future__ import annotations

from collections import defaultdict

from adft.core.models.events import Detection, NormalizedEvent, Severity
from adft.detection.rules.base_rule import BaseRule


class AdminAfterHoursRule(BaseRule):
    """
    Détecte les connexions administrateur en dehors des heures ouvrées.

    Les vrais administrateurs travaillent généralement pendant
    les heures de bureau. Une activité admin à 3h du matin
    est soit une urgence documentée, soit un attaquant.

    Horaires considérés comme suspects : avant 6h et après 22h.
    Week-end : toute activité admin est signalée.

    MITRE ATT&CK : T1078 — Valid Accounts
    """

    rule_id = "ADMIN-001"
    rule_name = "Activité administrateur hors horaires"
    description = "Connexion avec privilèges admin en dehors des heures ouvrées"
    severity = Severity.MEDIUM
    mitre_tactic = "Persistence"
    mitre_technique = "Valid Accounts"
    mitre_id = "T1078"

    def evaluate(self, events: list[NormalizedEvent]) -> list[Detection]:
        """
        Croise les événements 4672 (logon admin) avec l'analyse
        temporelle pour identifier les activités hors horaires.
        """
        detections: list[Detection] = []

        admin_logons = [e for e in events if e.event_id == 4672]

        # Ignorer les comptes machine et système
        system_accounts = {
            "system", "local service", "network service",
        }

        for event in admin_logons:
            user_lower = event.user.lower()
            if user_lower in system_accounts or user_lower.endswith("$"):
                continue

            # Vérification horaire
            hour = event.timestamp.hour
            weekday = event.timestamp.weekday()  # 0=lundi, 6=dimanche

            is_after_hours = hour < 6 or hour > 22
            is_weekend = weekday >= 5

            if is_after_hours or is_weekend:
                period = "week-end" if is_weekend else "heures creuses"
                confidence = 0.65 if is_after_hours else 0.55

                detection = self.create_detection(
                    description=(
                        f"Activité admin hors horaires : '{event.user}' "
                        f"connecté à {event.timestamp.strftime('%H:%M')} "
                        f"({period}) sur '{event.target_host}'"
                    ),
                    events=[event],
                    entities=[event.user, event.target_host],
                    confidence=confidence,
                    severity_override=(
                        Severity.HIGH if is_after_hours and is_weekend
                        else Severity.MEDIUM
                    ),
                )
                detections.append(detection)

        return detections


class MultipleAdminSourcesRule(BaseRule):
    """
    Détecte l'utilisation de comptes admin depuis des sources multiples.

    Un administrateur légitime se connecte généralement depuis
    1-2 postes fixes (station admin + PAW). Un attaquant utilisant
    des identifiants volés se connectera depuis des postes
    variés au fil de son mouvement latéral.

    Seuil : ≥3 sources distinctes pour un même compte admin.

    MITRE ATT&CK : T1078 — Valid Accounts
    """

    rule_id = "ADMIN-002"
    rule_name = "Compte admin multi-sources"
    description = "Compte administrateur utilisé depuis de multiples sources"
    severity = Severity.HIGH
    mitre_tactic = "Lateral Movement"
    mitre_technique = "Valid Accounts"
    mitre_id = "T1078"

    def evaluate(self, events: list[NormalizedEvent]) -> list[Detection]:
        """
        Analyse la diversité des sources de connexion pour
        chaque compte admin identifié.
        """
        detections: list[Detection] = []

        # Identifier les comptes admin via les événements 4672
        admin_users: set[str] = set()
        for event in events:
            if event.event_id == 4672 and event.user:
                user_lower = event.user.lower()
                if not user_lower.endswith("$") and user_lower not in (
                    "system", "local service", "network service"
                ):
                    admin_users.add(event.user)

        # Analyser les connexions de ces comptes admin
        admin_logons: defaultdict[str, set[str]] = defaultdict(set)
        admin_events: defaultdict[str, list[NormalizedEvent]] = defaultdict(list)

        for event in events:
            if event.event_id == 4624 and event.user in admin_users:
                source = event.ip_address or event.source_host
                if source:
                    admin_logons[event.user].add(source)
                    admin_events[event.user].append(event)

        for user, sources in admin_logons.items():
            if len(sources) >= 3:
                detection = self.create_detection(
                    description=(
                        f"Compte admin '{user}' utilisé depuis "
                        f"{len(sources)} sources : "
                        f"{', '.join(list(sources)[:5])}"
                    ),
                    events=admin_events[user][:15],
                    entities=[user] + list(sources)[:5],
                    confidence=min(0.5 + len(sources) * 0.1, 0.90),
                )
                detections.append(detection)

        return detections