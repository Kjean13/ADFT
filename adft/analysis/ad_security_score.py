from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, List, Set

from adft.core.models import (
    ADSecurityScore,
    DetectionAlert,
    InvestigationObject,
    SecurityScoreCategory,
)


class ADSecurityScoreCalculator:
    """Calcule un score d'exposition AD observée robuste, explicable et piloté par les preuves."""

    TECHNIQUE_TO_CATEGORY: Dict[str, str] = {
        "T1110": "authentication",
        "T1078": "authentication",
        "T1558": "authentication",
        "T1556": "authentication",
        "T1552": "authentication",
        "T1550": "authentication",
        "T1068": "privileges",
        "T1134": "privileges",
        "T1098": "privileges",
        "T1484": "privileges",
        "T1078.002": "privileges",
        "T1021": "suspicious",
        "T1076": "suspicious",
        "T1075": "suspicious",
        "T1097": "suspicious",
        "T1003": "suspicious",
        "T1087": "hygiene",
        "T1069": "hygiene",
        "T1018": "hygiene",
        "T1482": "hygiene",
    }

    SEVERITY_PENALTIES: Dict[str, float] = {
        "critique": 15.0,
        "critical": 15.0,
        "élevé": 10.0,
        "high": 10.0,
        "modéré": 5.0,
        "medium": 5.0,
        "faible": 2.0,
        "low": 2.0,
        "info": 0.5,
    }

    CATEGORY_META: Dict[str, Dict[str, Any]] = {
        "authentication": {
            "name": "Exposition d'authentification",
            "weight": 0.30,
            "details": "Robustesse des mécanismes d'authentification observés dans les traces.",
            "impact": "Risque de compromission d'identités et de réutilisation d'accès valides.",
        },
        "privileges": {
            "name": "Risques de privilèges",
            "weight": 0.30,
            "details": "Exposition liée aux comptes sensibles, groupes privilégiés et élévations.",
            "impact": "Risque de prise de contrôle rapide d'actifs critiques ou du domaine.",
        },
        "suspicious": {
            "name": "Propagation et comportements suspects",
            "weight": 0.25,
            "details": "Progression, latéralisation, évasion et enchaînement d'actions anormales.",
            "impact": "Risque d'extension de l'incident à plusieurs hôtes avec perte de maîtrise opérationnelle.",
        },
        "hygiene": {
            "name": "Hygiène Active Directory observée",
            "weight": 0.15,
            "details": "Signaux montrant une hygiène AD insuffisante dans les preuves disponibles.",
            "impact": "Risque de répétition de compromission si les faiblesses structurelles persistent.",
        },
    }

    def calculate(
        self,
        alerts: List[DetectionAlert],
        investigations: List[InvestigationObject],
    ) -> ADSecurityScore:
        categories = self._init_categories()
        context = self._build_context(alerts, investigations)
        self._apply_alert_penalties(alerts, categories)
        self._apply_context_penalties(context, categories)
        self._apply_investigation_penalties(investigations, categories)
        self._apply_progression_penalties(context, categories)
        self._apply_global_critical_penalty(context, categories)
        self._apply_critical_campaign_penalty(context, categories)
        self._finalize_categories(categories, context)

        score = ADSecurityScore(categories=list(categories.values()))
        score.compute_global_score()
        score.evidence_confidence = self._compute_confidence(context)
        score.confidence_label = self._confidence_label(score.evidence_confidence)
        score.observed_scope = self._build_scope(context)
        score.severity_mix = self._build_severity_mix(context)
        score.score_drivers = self._build_global_drivers(score.categories)
        score.calibration_version = "observed-2026.03"
        score.calibration_method = "heuristic_evidence_weighting"
        score.decision_thresholds = {"critical": "<=25", "high": "<=50", "medium": "<=75", "low": ">75"}
        score.calibration_notes = [
            "Les pénalités sont pilotées par la sévérité, la diversité de règles, la confiance, la propagation observée et l'impact sur les actifs AD critiques.",
            "Les doublons sont amortis pour éviter de sur-noter une même preuve répétée.",
            "Le score exprime une exposition observée dans les traces analysées, pas un audit exhaustif de configuration.",
        ]
        score.summary = self._generate_summary(score)
        return score

    def _init_categories(self) -> Dict[str, SecurityScoreCategory]:
        out: Dict[str, SecurityScoreCategory] = {}
        for key, meta in self.CATEGORY_META.items():
            out[key] = SecurityScoreCategory(
                name=meta["name"],
                score=100.0,
                weight=float(meta["weight"]),
                details=meta["details"],
                operational_impact=meta["impact"],
            )
        return out

    def _build_context(self, alerts: List[DetectionAlert], investigations: List[InvestigationObject]) -> Dict[str, Any]:
        users: Set[str] = set()
        hosts: Set[str] = set()
        ips: Set[str] = set()
        privileged_users: Set[str] = set()
        tactic_counter: Counter[str] = Counter()
        category_counter: Counter[str] = Counter()
        rule_counter: Counter[tuple[str, str]] = Counter()
        unique_rules_per_category: Dict[str, Set[str]] = defaultdict(set)
        severity_counter: Counter[str] = Counter()
        confidences: List[float] = []
        dc_hosts: Set[str] = set()
        lateral_pairs: Set[tuple[str, str]] = set()

        for alert in alerts:
            user = self._norm(getattr(alert, "user", None))
            src = self._norm(getattr(alert, "source_host", None))
            dst = self._norm(getattr(alert, "target_host", None))
            ip = self._norm(getattr(alert, "source_ip", None))
            rule_id = self._norm(getattr(alert, "rule_id", None)) or "UNKNOWN"
            category = self._resolve_category(self._norm(getattr(alert, "mitre_technique", None)))
            severity = self._severity_key(getattr(alert, "severity", None))
            tactic = self._normalize_tactic(getattr(alert, "mitre_tactic", None))
            confidence = self._clamp_confidence(getattr(alert, "confidence", 0.5))

            confidences.append(confidence)
            severity_counter[severity] += 1
            tactic_counter[tactic] += 1
            category_counter[category] += 1
            rule_counter[(category, rule_id)] += 1
            unique_rules_per_category[category].add(rule_id)

            if user:
                users.add(user)
                if self._looks_privileged(user) or self._looks_sensitive_text(getattr(alert, "rule_name", ""), getattr(alert, "description", "")):
                    privileged_users.add(user)
            for host in (src, dst):
                if host:
                    hosts.add(host)
                    if self._looks_domain_controller(host):
                        dc_hosts.add(host)
            if ip:
                ips.add(ip)
            if src and dst and src != dst:
                lateral_pairs.add((src, dst))

        return {
            "users": users,
            "hosts": hosts,
            "ips": ips,
            "privileged_users": privileged_users,
            "tactic_counter": tactic_counter,
            "category_counter": category_counter,
            "rule_counter": rule_counter,
            "unique_rules_per_category": unique_rules_per_category,
            "severity_counter": severity_counter,
            "confidences": confidences,
            "dc_hosts": dc_hosts,
            "lateral_pairs": lateral_pairs,
            "alerts": alerts,
            "investigations": investigations,
        }

    def _apply_alert_penalties(self, alerts: List[DetectionAlert], categories: Dict[str, SecurityScoreCategory]) -> None:
        seen_per_category: Dict[str, Counter[str]] = defaultdict(Counter)

        for alert in alerts:
            category_key = self._resolve_category(self._norm(getattr(alert, "mitre_technique", None)))
            if category_key not in categories:
                category_key = "suspicious"

            severity = self._severity_key(getattr(alert, "severity", None))
            base_penalty = self.SEVERITY_PENALTIES.get(severity, 2.0)
            rule_id = self._norm(getattr(alert, "rule_id", None)) or "UNKNOWN"
            duplicate_rank = seen_per_category[category_key][rule_id]
            seen_per_category[category_key][rule_id] += 1
            dampening = 1.0 if duplicate_rank == 0 else (0.72 if duplicate_rank == 1 else 0.45)
            confidence_factor = self._confidence_factor(alert)
            penalty = round(base_penalty * dampening * confidence_factor, 1)
            categories[category_key].apply_penalty(penalty, self._format_alert_evidence(alert))

            if self._looks_privileged(getattr(alert, "user", None)):
                categories["privileges"].apply_penalty(
                    4.5 if severity in {"critical", "high"} else 2.5,
                    f"Compte sensible touché: {self._norm(getattr(alert, 'user', None))}",
                )

            if self._is_log_tampering(alert):
                categories["suspicious"].apply_penalty(7.5, "Trace d'évasion détectée: effacement ou altération de journaux")
                categories["hygiene"].apply_penalty(4.0, "Visibilité dégradée par altération de journaux")

            if self._looks_domain_controller(getattr(alert, "source_host", None)) or self._looks_domain_controller(getattr(alert, "target_host", None)):
                categories["privileges"].apply_penalty(2.5, "Activité sensible observée sur un actif AD critique")
                categories["hygiene"].apply_penalty(1.5, "Surface AD critique directement touchée par des traces suspectes")

            if category_key == "suspicious" and self._norm(getattr(alert, "source_host", None)) and self._norm(getattr(alert, "target_host", None)):
                categories["suspicious"].apply_penalty(2.0, "Déplacement entre actifs observé dans les preuves")

    def _apply_context_penalties(self, context: Dict[str, Any], categories: Dict[str, SecurityScoreCategory]) -> None:
        host_count = len(context["hosts"])
        user_count = len(context["users"])
        tactic_count = len([k for k, v in context["tactic_counter"].items() if v])
        privileged_count = len(context["privileged_users"])
        dc_count = len(context["dc_hosts"])
        lateral_count = len(context["lateral_pairs"])
        severity_counter = context["severity_counter"]

        if host_count >= 3:
            categories["suspicious"].apply_penalty(min(14.0, 4.0 + (host_count - 2) * 2.0), f"Propagation observée sur {host_count} hôtes")
        if user_count >= 3:
            categories["authentication"].apply_penalty(min(10.0, 2.0 + (user_count - 2) * 1.5), f"Surface d'identités touchées: {user_count} comptes")
        if tactic_count >= 3:
            categories["suspicious"].apply_penalty(min(10.0, 2.0 + (tactic_count - 2) * 2.0), f"Chaîne d'attaque multi-tactiques observée: {tactic_count} tactiques")
        if privileged_count >= 1:
            categories["privileges"].apply_penalty(min(14.0, 3.0 + privileged_count * 2.5), f"Signaux touchant des comptes ou opérations à privilèges ({privileged_count})")
        if dc_count >= 1:
            categories["privileges"].apply_penalty(min(10.0, 3.0 + dc_count * 2.0), f"{dc_count} actif(s) AD critique(s) impacté(s)")
            categories["hygiene"].apply_penalty(min(6.0, 2.0 + dc_count * 1.0), f"Périmètre critique exposé dans les preuves ({dc_count} hôtes AD)")
        if lateral_count >= 2:
            categories["suspicious"].apply_penalty(min(10.0, 3.0 + lateral_count * 1.5), f"Mouvement latéral probable via {lateral_count} trajectoires")

        auth_count = int(context["category_counter"].get("authentication", 0))
        hygiene_count = int(context["category_counter"].get("hygiene", 0))
        if auth_count >= 3:
            categories["authentication"].apply_penalty(min(12.0, 3.0 + auth_count), f"Volume anormal de signaux d'authentification: {auth_count}")
        if hygiene_count >= 2:
            categories["hygiene"].apply_penalty(min(10.0, 2.0 + hygiene_count * 2.0), f"Faiblesses d'hygiène observées à {hygiene_count} reprises")

        for category_key, rules in context["unique_rules_per_category"].items():
            if len(rules) >= 2 and category_key in categories:
                categories[category_key].apply_penalty(
                    min(8.0, 1.0 + len(rules) * 1.5),
                    f"Diversité des preuves dans {categories[category_key].name}: {len(rules)} règles distinctes",
                )

        critical_count = int(severity_counter.get("critical", 0) + severity_counter.get("critique", 0))
        high_count = int(severity_counter.get("high", 0) + severity_counter.get("élevé", 0))
        if critical_count >= 1 and high_count >= 2:
            categories["suspicious"].apply_penalty(5.0, f"Combinaison de signaux critiques et élevés observée ({critical_count} / {high_count})")

    def _apply_investigation_penalties(
        self,
        investigations: List[InvestigationObject],
        categories: Dict[str, SecurityScoreCategory],
    ) -> None:
        for inv in investigations:
            alert_count = len(getattr(inv, "alerts", []) or getattr(inv, "detections", []) or [])
            score = float(getattr(inv, "risk_score", 0.0) or 0.0)
            primary = self._norm(getattr(inv, "primary_entity", None) or getattr(inv, "identity", None))
            related_entities = list(getattr(inv, "related_entities", []) or [])
            attack_phase = self._norm(getattr(inv, "attack_phase", None)).lower()
            label = f"Investigation {primary or getattr(inv, 'id', 'N/A')}"
            if alert_count >= 4:
                categories["suspicious"].apply_penalty(min(12.0, 3.0 + alert_count), f"{label}: {alert_count} alertes corrélées")
            if len(related_entities) >= 2:
                categories["suspicious"].apply_penalty(min(8.0, 2.0 + len(related_entities) * 1.2), f"{label}: {len(related_entities)} entités liées")
            if score >= 80:
                categories["privileges"].apply_penalty(8.0, f"{label}: risque critique ({score}/100)")
                categories["authentication"].apply_penalty(4.0, f"{label}: exposition d'identité très élevée ({score}/100)")
            elif score >= 60:
                categories["authentication"].apply_penalty(5.0, f"{label}: risque élevé ({score}/100)")
            if "domain" in attack_phase or "privilege" in attack_phase:
                categories["privileges"].apply_penalty(4.0, f"{label}: phase d'attaque sensible ({attack_phase})")

    def _apply_progression_penalties(self, context: Dict[str, Any], categories: Dict[str, SecurityScoreCategory]) -> None:
        tactic_ids = {t for t, count in context["tactic_counter"].items() if count and t and t != "UNKNOWN"}
        progression_depth = len(tactic_ids)
        if progression_depth >= 4:
            categories["suspicious"].apply_penalty(min(12.0, 4.0 + progression_depth * 1.5), f"Progression d'attaque couvrant {progression_depth} tactiques MITRE")
        if {"TA0006", "TA0008"}.issubset(tactic_ids):
            categories["authentication"].apply_penalty(5.0, "Chaîne crédible credential access → lateral movement observée")
            categories["suspicious"].apply_penalty(4.0, "Chaîne crédible credential access → lateral movement observée")
        if {"TA0004", "TA0005"}.intersection(tactic_ids) and {"TA0008", "TA0040"}.intersection(tactic_ids):
            categories["privileges"].apply_penalty(5.0, "Progression vers domination / impact via privilèges et évasion observée")

    def _apply_global_critical_penalty(self, context: Dict[str, Any], categories: Dict[str, SecurityScoreCategory]) -> None:
        severity_counter = context["severity_counter"]
        critical_count = int(severity_counter.get("critical", 0) + severity_counter.get("critique", 0))
        if critical_count < 3:
            return
        auth_ramp = min(28.0, 12.0 + (critical_count - 3) * 4.0)
        priv_ramp = min(24.0, 10.0 + (critical_count - 3) * 3.5)
        susp_ramp = min(22.0, 9.0 + (critical_count - 3) * 3.0)
        categories["authentication"].apply_penalty(auth_ramp, f"Accumulation d'alertes critiques ({critical_count})")
        categories["privileges"].apply_penalty(priv_ramp, f"Accumulation d'alertes critiques ({critical_count})")
        categories["suspicious"].apply_penalty(susp_ramp, f"Accumulation d'alertes critiques ({critical_count})")
        if critical_count >= 5:
            categories["hygiene"].apply_penalty(8.0, f"Concentration d'alertes critiques réduisant la confiance dans l'hygiène observée ({critical_count})")


    def _apply_critical_campaign_penalty(self, context: Dict[str, Any], categories: Dict[str, SecurityScoreCategory]) -> None:
        alerts_count = len(context["alerts"])
        if alerts_count < 4:
            return
        severity_counter = context["severity_counter"]
        critical_count = int(severity_counter.get("critical", 0) + severity_counter.get("critique", 0))
        if critical_count / max(1, alerts_count) < 0.6:
            return
        categories["privileges"].apply_penalty(26.0, f"Campagne critique cohérente observée ({critical_count}/{alerts_count} alertes)")
        categories["suspicious"].apply_penalty(24.0, f"Campagne critique cohérente observée ({critical_count}/{alerts_count} alertes)")
        categories["hygiene"].apply_penalty(14.0, f"Campagne critique cohérente observée ({critical_count}/{alerts_count} alertes)")

    def _finalize_categories(self, categories: Dict[str, SecurityScoreCategory], context: Dict[str, Any]) -> None:
        for key, cat in categories.items():
            cat.finalize(
                evidence_confidence=self._compute_category_confidence(key, context, cat),
                observed_scope=self._build_category_scope(key, context),
            )

    def _compute_category_confidence(self, key: str, context: Dict[str, Any], category: SecurityScoreCategory) -> float:
        rule_diversity = len(context["unique_rules_per_category"].get(key, set()))
        evidence_count = len(category.evidence_examples)
        base = 0.18
        base += min(0.28, evidence_count * 0.06)
        base += min(0.20, rule_diversity * 0.06)
        base += min(0.20, len(context["investigations"]) * 0.05)
        if key == "privileges":
            base += min(0.14, len(context["privileged_users"]) * 0.05)
            if context["dc_hosts"]:
                base += 0.08
        if key == "suspicious":
            base += min(0.12, len(context["lateral_pairs"]) * 0.04)
        if key == "authentication":
            base += min(0.10, len(context["users"]) * 0.03)
        if key == "hygiene":
            base += min(0.10, len(context["dc_hosts"]) * 0.03)
        return round(min(1.0, base), 2)

    def _compute_confidence(self, context: Dict[str, Any]) -> float:
        unique_rules = len({rule for _, rule in context["rule_counter"].keys()})
        tactic_count = len([k for k, v in context["tactic_counter"].items() if v and k != "UNKNOWN"])
        avg_conf = sum(context["confidences"] or [0.0]) / max(1, len(context["confidences"] or []))
        evidence_points = 0.10
        evidence_points += min(0.28, len(context["alerts"]) * 0.05)
        evidence_points += min(0.16, len(context["investigations"]) * 0.07)
        evidence_points += min(0.12, len(context["hosts"]) * 0.025)
        evidence_points += min(0.08, len(context["users"]) * 0.02)
        evidence_points += min(0.14, unique_rules * 0.03)
        evidence_points += min(0.08, tactic_count * 0.02)
        evidence_points += min(0.08, avg_conf * 0.12)
        if context["dc_hosts"]:
            evidence_points += 0.04
        return round(min(1.0, evidence_points), 2)

    def _build_scope(self, context: Dict[str, Any]) -> str:
        dc_count = len(context["dc_hosts"])
        lateral_count = len(context["lateral_pairs"])
        return (
            f"{len(context['alerts'])} alertes, "
            f"{len(context['investigations'])} investigations, "
            f"{len(context['users'])} comptes, "
            f"{len(context['hosts'])} hôtes, "
            f"{dc_count} actifs AD critiques, "
            f"{lateral_count} trajectoires latérales, "
            f"{len(context['ips'])} IP source observées"
        )

    def _build_category_scope(self, key: str, context: Dict[str, Any]) -> str:
        if key == "authentication":
            return f"{context['category_counter'].get('authentication', 0)} signaux, {len(context['users'])} comptes touchés"
        if key == "privileges":
            return f"{len(context['privileged_users'])} identités sensibles, {len(context['dc_hosts'])} actifs AD critiques"
        if key == "suspicious":
            return f"{len(context['lateral_pairs'])} trajectoires latérales, {len(context['hosts'])} hôtes concernés"
        return f"{context['category_counter'].get('hygiene', 0)} signaux, visibilité sur {len(context['dc_hosts'])} actifs AD"

    def _build_severity_mix(self, context: Dict[str, Any]) -> str:
        sev = context["severity_counter"]
        critical = int(sev.get("critical", 0) + sev.get("critique", 0))
        high = int(sev.get("high", 0) + sev.get("élevé", 0))
        medium = int(sev.get("medium", 0) + sev.get("modéré", 0))
        low = int(sev.get("low", 0) + sev.get("faible", 0) + sev.get("info", 0))
        return f"{critical} critiques, {high} élevés, {medium} modérés, {low} faibles/info"

    def _build_global_drivers(self, categories: List[SecurityScoreCategory]) -> List[str]:
        ranked = sorted(categories, key=lambda c: (-float(c.penalty_points), float(c.score), c.name))
        drivers: List[str] = []
        for cat in ranked[:3]:
            driver = cat.top_driver or (cat.evidence_examples[0] if cat.evidence_examples else cat.operational_impact)
            if driver:
                drivers.append(f"{cat.name}: {driver}")
        return drivers

    def _resolve_category(self, mitre_technique: str | None) -> str:
        technique = self._norm(mitre_technique)
        if technique in self.TECHNIQUE_TO_CATEGORY:
            return self.TECHNIQUE_TO_CATEGORY[technique]
        base_technique = technique.split(".")[0] if technique else ""
        if base_technique in self.TECHNIQUE_TO_CATEGORY:
            return self.TECHNIQUE_TO_CATEGORY[base_technique]
        return "suspicious"

    def _format_alert_evidence(self, alert: DetectionAlert) -> str:
        rule = self._norm(getattr(alert, "rule_name", None)) or self._norm(getattr(alert, "rule_id", None)) or "Alerte"
        severity = self._severity_key(getattr(alert, "severity", None))
        user = self._norm(getattr(alert, "user", None))
        src = self._norm(getattr(alert, "source_host", None))
        dst = self._norm(getattr(alert, "target_host", None))
        where = " → ".join([x for x in [src, dst] if x])
        subject = f" sur {user}" if user else ""
        location = f" ({where})" if where else ""
        return f"{rule}{subject}{location} [{severity}]"

    def _severity_key(self, value: Any) -> str:
        return self._norm(value).lower() if self._norm(value) else "medium"

    def _normalize_tactic(self, value: Any) -> str:
        tactic = self._norm(value).upper()
        if not tactic:
            return "UNKNOWN"
        aliases = {
            "INITIAL ACCESS": "TA0001",
            "EXECUTION": "TA0002",
            "PERSISTENCE": "TA0003",
            "PRIVILEGE ESCALATION": "TA0004",
            "DEFENSE EVASION": "TA0005",
            "CREDENTIAL ACCESS": "TA0006",
            "DISCOVERY": "TA0007",
            "LATERAL MOVEMENT": "TA0008",
            "COLLECTION": "TA0009",
            "EXFILTRATION": "TA0010",
            "IMPACT": "TA0040",
        }
        return aliases.get(tactic, tactic)

    def _norm(self, value: Any) -> str:
        if value is None:
            return ""
        return str(value).strip()

    def _clamp_confidence(self, value: Any) -> float:
        try:
            return max(0.0, min(1.0, float(value)))
        except Exception:
            return 0.5

    def _confidence_factor(self, alert: DetectionAlert) -> float:
        confidence = self._clamp_confidence(getattr(alert, "confidence", 0.5))
        return round(0.85 + confidence * 0.4, 2)

    def _looks_privileged(self, user: Any) -> bool:
        u = self._norm(user).lower()
        if not u:
            return False
        markers = ("admin", "administrator", "domain admins", "enterprise admins", "adm", "svc-")
        return any(m in u for m in markers)

    def _looks_sensitive_text(self, *parts: Any) -> bool:
        text = " ".join(self._norm(p).lower() for p in parts if self._norm(p))
        markers = (
            "admin",
            "privilege",
            "group",
            "kerberoast",
            "golden ticket",
            "pass-the-hash",
            "credential",
            "ticket",
        )
        return any(m in text for m in markers)

    def _looks_domain_controller(self, host: Any) -> bool:
        h = self._norm(host).lower()
        if not h:
            return False
        return h.startswith("dc") or "domain controller" in h or h.endswith("-dc")

    def _is_log_tampering(self, alert: DetectionAlert) -> bool:
        content = f"{self._norm(getattr(alert, 'rule_name', None))} {self._norm(getattr(alert, 'description', None))}".lower()
        return "log" in content and any(word in content for word in ("clear", "erase", "wipe", "effacement", "journal"))

    @staticmethod
    def _confidence_label(value: float) -> str:
        if value >= 0.8:
            return "très solide"
        if value >= 0.6:
            return "solide"
        if value >= 0.4:
            return "moyenne"
        return "faible"

    @staticmethod
    def _generate_summary(score: ADSecurityScore) -> str:
        weakest = sorted(score.categories, key=lambda c: c.score)[:2]
        weakest_labels = ", ".join(f"{c.name} ({c.score}/100)" for c in weakest) if weakest else "aucune"
        scope = score.observed_scope or "périmètre non précisé"
        drivers = "; ".join(score.score_drivers[:2]) if score.score_drivers else "aucun driver dominant"
        return (
            f"Score d'exposition Active Directory observée : {score.global_score}/100. "
            f"Niveau de risque : {score.risk_level.upper()}. "
            f"Confiance des preuves : {score.evidence_confidence} ({score.confidence_label}). "
            f"Périmètre observé : {scope}. "
            f"Mix de sévérité : {score.severity_mix}. "
            f"Axes les plus dégradés : {weakest_labels}. "
            f"Drivers principaux : {drivers}."
        )
