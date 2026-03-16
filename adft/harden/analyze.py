"""ADFT — Analyseur de durcissement recentré sur les preuves."""

from __future__ import annotations

from collections import Counter
from typing import Iterable, List

from adft.core.models import DetectionAlert, InvestigationObject, HardeningFinding, HardeningReport


class HardeningAnalyzer:
    """Transforme des alertes/investigations en plan de hardening orienté preuves."""

    def analyze(
        self,
        alerts: List[DetectionAlert],
        investigations: List[InvestigationObject],
    ) -> HardeningReport:
        report = HardeningReport()
        alerts = alerts or []
        investigations = investigations or []

        self._check_kerberos_weaknesses(alerts, report)
        self._check_privilege_issues(alerts, investigations, report)
        self._check_authentication_hygiene(alerts, report)
        self._check_lateral_movement_exposure(alerts, report)
        self._check_log_resilience(alerts, report)
        self._check_ad_general_hygiene(alerts, investigations, report)

        coverage = report.script_coverage
        report.summary = (
            f"{report.total_issues} recommandation(s) pilotée(s) par preuves, "
            f"dont {report.critical_count} critique(s). "
            f"Scripts candidats disponibles pour {coverage['with_script']}/{report.total_issues} constats."
        )
        return report

    @staticmethod
    def _lc(value: object) -> str:
        return str(value or "").strip().lower()

    def _alert_tokens(self, alert: DetectionAlert) -> set[str]:
        tokens = {
            self._lc(getattr(alert, 'rule_id', '')),
            self._lc(getattr(alert, 'rule_name', '')),
            self._lc(getattr(alert, 'mitre_tactic', '')),
            self._lc(getattr(alert, 'mitre_technique', '')),
            self._lc(getattr(alert, 'mitre_id', '')),
            self._lc(getattr(alert, 'description', '')),
        }
        return {t for t in tokens if t}

    def _match_any(self, alert: DetectionAlert, *needles: str) -> bool:
        blob = ' | '.join(sorted(self._alert_tokens(alert)))
        return any(self._lc(n) in blob for n in needles if n)

    def _select(self, alerts: Iterable[DetectionAlert], *needles: str) -> list[DetectionAlert]:
        return [a for a in alerts if self._match_any(a, *needles)]

    def _evidence_from_alerts(self, alerts: Iterable[DetectionAlert], limit: int = 4) -> list[str]:
        evidence: list[str] = []
        for a in alerts:
            parts = []
            ts = getattr(a, 'timestamp', None)
            if ts:
                parts.append(str(ts))
            rule = getattr(a, 'rule_name', None) or getattr(a, 'rule_id', None)
            if rule:
                parts.append(str(rule))
            user = getattr(a, 'user', None)
            if user:
                parts.append(f"user={user}")
            src = getattr(a, 'source_host', None) or getattr(a, 'source_ip', None)
            if src:
                parts.append(f"source={src}")
            tgt = getattr(a, 'target_host', None)
            if tgt:
                parts.append(f"target={tgt}")
            line = ' | '.join(parts)
            if line and line not in evidence:
                evidence.append(line)
            if len(evidence) >= limit:
                break
        return evidence

    def _evidence_from_investigations(self, investigations: Iterable[InvestigationObject], limit: int = 3) -> list[str]:
        evidence: list[str] = []
        for inv in investigations:
            entity = getattr(inv, 'identity', None) or getattr(inv, 'primary_entity', None) or 'unknown'
            score = getattr(inv, 'risk_score', 0)
            summary = getattr(inv, 'summary', '')
            line = f"investigation={entity} | risk_score={score}"
            if summary:
                line += f" | {summary}"
            if line not in evidence:
                evidence.append(line)
            if len(evidence) >= limit:
                break
        return evidence

    def _confidence(self, count: int) -> str:
        if count >= 4:
            return 'high'
        if count >= 2:
            return 'medium'
        return 'low'

    def _add(self, report: HardeningReport, **kwargs) -> None:
        report.add_finding(HardeningFinding(**kwargs))

    def _check_kerberos_weaknesses(self, alerts: List[DetectionAlert], report: HardeningReport) -> None:
        kerberoast = self._select(alerts, 'kerberoast', 't1558.003', 'kerb-001')
        if kerberoast:
            evidence = self._evidence_from_alerts(kerberoast)
            self._add(
                report,
                finding_id='HARD-001',
                title='Comptes de service exposés au Kerberoasting',
                category='authentication',
                risk_explanation=(
                    'Des tickets de service Kerberos ont été demandés dans un contexte '
                    'compatible avec une tentative de cassage hors ligne de mots de passe de comptes de service.'
                ),
                recommendation=(
                    'Basculer les services compatibles vers des gMSA, imposer AES-only sur les comptes de service, '
                    'réinitialiser les secrets faibles et auditer les SPN encore nécessaires.'
                ),
                impact='Un compte de service compromis peut ouvrir un accès transversal durable à des serveurs et applications métiers.',
                priority='critique',
                references=['https://attack.mitre.org/techniques/T1558/003/'],
                evidence=evidence,
                prerequisites=[
                    'Valider la liste des comptes de service réellement utilisés.',
                    'Prévoir une fenêtre de changement pour les applications dépendantes des SPN.',
                ],
                validation_steps=[
                    'Vérifier que le compte est passé en AES-only ou gMSA.',
                    'Confirmer qu’aucune demande RC4 n’apparaît encore pour ce compte.',
                ],
                rollback_steps=[
                    'Conserver la configuration SPN d’origine avant changement.',
                    'Prévoir le retour au secret précédent si une application critique casse.',
                ],
                candidate_scope='Comptes de service avec SPN observés dans les preuves collectées.',
                confidence=self._confidence(len(kerberoast)),
                analyst_notes='Traiter en priorité les comptes Tier 0 et ceux exposés sur plusieurs hôtes.',
            )

        asrep = self._select(alerts, 'as-rep', 'pre-auth', 't1558.004', 'kerb-002', 'comp-003')
        if asrep:
            evidence = self._evidence_from_alerts(asrep)
            self._add(
                report,
                finding_id='HARD-002',
                title='Pré-authentification Kerberos potentiellement contournable',
                category='authentication',
                risk_explanation=(
                    'Les preuves montrent des événements compatibles avec du roasting sans pré-authentification '
                    'ou avec une pression anormale sur la phase Kerberos initiale.'
                ),
                recommendation=(
                    'Lister les comptes avec DoesNotRequirePreAuth, réactiver la pré-authentification si non justifiée '
                    'et renforcer immédiatement les secrets des comptes exposés.'
                ),
                impact='Facilite le vol de secrets de comptes sans interaction directe avec les postes visés.',
                priority='élevé',
                evidence=evidence,
                prerequisites=['Identifier les comptes de service historiques ou techniques qui dépendent de ce réglage.'],
                validation_steps=[
                    'Exécuter un inventaire DoesNotRequirePreAuth après correction.',
                    'Vérifier qu’aucun compte métier légitime n’échoue après réactivation.',
                ],
                rollback_steps=['Documenter les exceptions métier avant changement afin de restaurer uniquement les cas justifiés.'],
                candidate_scope='Comptes identifiés dans les journaux Kerberos analysés.',
                confidence=self._confidence(len(asrep)),
            )

        golden = self._select(alerts, 'golden ticket', 't1558.001', 'kerb-003')
        if golden:
            evidence = self._evidence_from_alerts(golden)
            self._add(
                report,
                finding_id='HARD-003',
                title='Suspicion de compromission KRBTGT / Golden Ticket',
                category='authentication',
                risk_explanation='Une activité compatible Golden Ticket suggère qu’un secret de domaine critique a pu être compromis.',
                recommendation=(
                    'Conduire une procédure encadrée de double rotation KRBTGT, valider l’intégrité des DC '
                    'et requalifier tous les comptes privilégiés impliqués avant retour à la normale.'
                ),
                impact='Risque de compromission complète du domaine avec persistance invisible.',
                priority='critique',
                evidence=evidence,
                prerequisites=[
                    'Préparer la procédure de double reset KRBTGT avec fenêtre et validation CAB.',
                    'Vérifier la santé de la réplication AD avant toute action.',
                ],
                validation_steps=[
                    'Contrôler la réplication réussie du nouveau secret sur tous les DC.',
                    'Vérifier la disparition des tickets suspects dans la nouvelle fenêtre d’observation.',
                ],
                rollback_steps=['Aucun rollback simple : traiter comme changement de crise avec plan de restauration validé.'],
                candidate_scope='Contrôleurs de domaine et comptes privilégiés liés au périmètre de l’investigation.',
                confidence=self._confidence(len(golden)),
                analyst_notes='Ne jamais déclencher la rotation KRBTGT sans coordination AD/IR.',
            )

    def _check_privilege_issues(self, alerts: List[DetectionAlert], investigations: List[InvestigationObject], report: HardeningReport) -> None:
        priv = self._select(alerts, 'ta0004', 'privilege escalation', 'priv-001', 'priv-002', 'modification de groupe privilégié', 'privilèges spéciaux')
        if priv:
            evidence = self._evidence_from_alerts(priv)
            self._add(
                report,
                finding_id='HARD-010',
                title='Escalade ou expansion de privilèges observée',
                category='privileges',
                risk_explanation='Les alertes montrent une augmentation de privilèges ou une manipulation de groupes sensibles.',
                recommendation=(
                    'Requalifier les groupes privilégiés touchés, revoir les ACL des objets sensibles, '
                    'activer le tiering administratif et séparer les usages d’administration des usages bureautiques.'
                ),
                impact='Un compte standard peut devenir pivot d’administration et accélérer la compromission du domaine.',
                priority='critique',
                evidence=evidence,
                prerequisites=[
                    'Exporter l’appartenance actuelle aux groupes privilégiés avant correction.',
                    'Identifier les exceptions temporaires ou comptes break-glass.',
                ],
                validation_steps=[
                    'Comparer l’appartenance aux groupes avant/après correction.',
                    'Vérifier que les comptes retirés n’obtiennent plus les privilèges 4672 inattendus.',
                ],
                rollback_steps=['Préserver un export CSV des membres initiaux pour restauration contrôlée.'],
                candidate_scope='Groupes privilégiés et comptes administratifs impliqués par les alertes.',
                confidence=self._confidence(len(priv)),
            )

        risky = [inv for inv in investigations if getattr(inv, 'risk_score', 0) >= 70]
        if risky:
            evidence = self._evidence_from_investigations(risky)
            self._add(
                report,
                finding_id='HARD-011',
                title='Identités à très fort risque à contenir en priorité',
                category='privileges',
                risk_explanation='Plusieurs investigations dépassent un seuil de risque élevé et doivent être traitées comme comptes possiblement compromis.',
                recommendation=(
                    'Forcer la rotation des secrets, invalider les sessions en cours, contrôler les délégations '
                    'et enclencher une revue ciblée des dernières actions de ces identités.'
                ),
                impact='Le maintien de sessions ou secrets actifs permet à l’attaquant de revenir après remédiation.',
                priority='critique',
                evidence=evidence,
                prerequisites=[
                    'Valider les dépendances applicatives des comptes concernés.',
                    'Prévoir le séquencement des resets pour éviter une coupure métier brutale.',
                ],
                validation_steps=[
                    'Confirmer l’expiration des sessions/tickets pour les identités ciblées.',
                    'Vérifier qu’aucune authentification suspecte ne réapparaît sur ces identités.',
                ],
                rollback_steps=['Conserver une procédure d’ouverture contrôlée si un compte technique critique doit être réactivé.'],
                candidate_scope='Identités dont le risk_score d’investigation est ≥ 70.',
                confidence=self._confidence(len(risky)),
            )

        account_creation = self._select(alerts, 'priv-003', 'create account', 'création de compte suspecte', 'modification de groupe privilégié')
        if account_creation:
            evidence = self._evidence_from_alerts(account_creation)
            self._add(
                report,
                finding_id='HARD-012',
                title='Création ou enrôlement de compte à requalifier',
                category='privileges',
                risk_explanation='Des comptes nouveaux ou modifiés ont été observés dans un contexte anormal et peuvent constituer un mécanisme de persistance.',
                recommendation='Valider l’origine métier de chaque compte créé, contrôler les groupes hérités et désactiver immédiatement les comptes non justifiés.',
                impact='Permet une persistance discrète ou une réapparition de privilèges après nettoyage.',
                priority='élevé',
                evidence=evidence,
                prerequisites=['Exporter les attributs et groupes des comptes récemment créés avant changement.'],
                validation_steps=['Vérifier que seuls les comptes approuvés restent actifs et correctement groupés.'],
                rollback_steps=['Conserver les exports des comptes avant désactivation/suppression.'],
                candidate_scope='Comptes créés ou modifiés dans la fenêtre temporelle investiguée.',
                confidence=self._confidence(len(account_creation)),
            )

    def _check_authentication_hygiene(self, alerts: List[DetectionAlert], report: HardeningReport) -> None:
        brute_force = self._select(alerts, 'brute force', 'password guessing', 't1110', 'auth-001', 'comp-003')
        if brute_force:
            sources = Counter((getattr(a, 'source_ip', None) or getattr(a, 'source_host', None) or 'unknown') for a in brute_force)
            top_sources = ', '.join(f"{src}({count})" for src, count in sources.most_common(3))
            evidence = self._evidence_from_alerts(brute_force)
            if top_sources:
                evidence.append(f"sources dominantes={top_sources}")
            self._add(
                report,
                finding_id='HARD-020',
                title='Protection contre le brute force à durcir',
                category='authentication',
                risk_explanation='Les preuves montrent une pression d’authentification anormale compatible avec du brute force ou du password spraying.',
                recommendation=(
                    'Renforcer la politique de verrouillage, activer MFA sur les accès d’administration '
                    'et surveiller les sources d’authentification répétitives ou hors profil.'
                ),
                impact='Un mot de passe faible ou réutilisé peut suffire à ouvrir un premier accès puis à propager l’attaque.',
                priority='élevé',
                evidence=evidence,
                prerequisites=['Vérifier l’impact de la politique de lockout sur les comptes de service et applications legacy.'],
                validation_steps=['Contrôler la nouvelle politique de mot de passe et les seuils de verrouillage appliqués au domaine.'],
                rollback_steps=['Prévoir un retour arrière des seuils uniquement si une dépendance métier documentée casse.'],
                candidate_scope='Politiques de domaine et sources d’authentification observées.',
                confidence=self._confidence(len(brute_force)),
            )

    def _check_lateral_movement_exposure(self, alerts: List[DetectionAlert], report: HardeningReport) -> None:
        lateral = self._select(alerts, 'lateral movement', 'remote services', 'pass the hash', 'auth-002', 'lm-4624-smb', 't1021', 't1550.002')
        if lateral:
            evidence = self._evidence_from_alerts(lateral)
            self._add(
                report,
                finding_id='HARD-030',
                title='Surface de mouvement latéral encore exploitable',
                category='lateral_movement',
                risk_explanation='Des connexions et techniques compatibles avec du mouvement latéral ont été observées entre plusieurs hôtes.',
                recommendation=(
                    'Segmenter les flux d’administration, restreindre SMB/WinRM/RDP aux jump hosts autorisés '
                    'et déployer Credential Guard/LAPS sur le périmètre concerné.'
                ),
                impact='L’attaquant peut rebondir rapidement d’un poste à l’autre et augmenter sa profondeur de compromission.',
                priority='élevé',
                evidence=evidence,
                prerequisites=['Cartographier les flux d’administration réellement nécessaires entre hôtes.'],
                validation_steps=['Confirmer qu’un poste non autorisé ne peut plus initier de connexions d’administration latérales.'],
                rollback_steps=['Préserver la matrice des flux initiaux pour réouvrir un flux critique en urgence.'],
                candidate_scope='Postes et serveurs reliés par les chemins observés dans le graphe d’attaque.',
                confidence=self._confidence(len(lateral)),
            )

        rdp = self._select(alerts, 'remote desktop protocol', 'connexion rdp suspecte', 'auth-003')
        if rdp:
            evidence = self._evidence_from_alerts(rdp)
            self._add(
                report,
                finding_id='HARD-031',
                title='Exposition RDP à resserrer',
                category='lateral_movement',
                risk_explanation='Des ouvertures RDP suspectes montrent que la surface d’administration interactive reste trop large ou mal filtrée.',
                recommendation='Limiter RDP aux bastions dédiés, imposer MFA/NLA, filtrer les sources autorisées et journaliser strictement les accès interactifs.',
                impact='RDP offre un canal direct de déplacement et d’exécution interactive après vol d’identifiants.',
                priority='élevé',
                evidence=evidence,
                prerequisites=['Inventorier les serveurs qui nécessitent réellement RDP.'],
                validation_steps=['Tester qu’un compte non approuvé ou une source non approuvée est refusé en RDP.'],
                rollback_steps=['Conserver la liste des hôtes précédemment exposés afin de rétablir un accès d’urgence documenté.'],
                candidate_scope='Serveurs/hôtes présentant des connexions RDP dans la fenêtre d’investigation.',
                confidence=self._confidence(len(rdp)),
            )

        services = self._select(alerts, 'windows service', 'service installé', 'service installé (suspect)', 'comp-002', 'pers-7045', 'create or modify system process')
        if services:
            evidence = self._evidence_from_alerts(services)
            self._add(
                report,
                finding_id='HARD-032',
                title='Création de service / persistance à contenir',
                category='persistence',
                risk_explanation='La création ou modification de service observée peut matérialiser une persistance ou un déploiement latéral.',
                recommendation='Examiner chaque service créé, valider son binaire, limiter les droits de création de service et supprimer les services non approuvés après qualification.',
                impact='Un service malveillant fournit un point de réentrée persistant et peut exécuter du code avec des privilèges élevés.',
                priority='élevé',
                evidence=evidence,
                prerequisites=['Sauvegarder la configuration du service et le chemin du binaire avant suppression.'],
                validation_steps=['Vérifier que le service suspect est absent ou désactivé et que son binaire n’est plus exécutable.'],
                rollback_steps=['Documenter la configuration initiale pour restaurer un service légitime en cas de faux positif.'],
                candidate_scope='Services installés ou modifiés sur les hôtes touchés.',
                confidence=self._confidence(len(services)),
            )

    def _check_log_resilience(self, alerts: List[DetectionAlert], report: HardeningReport) -> None:
        log_clear = self._select(alerts, "journal d'audit effacé", 'clear windows event logs', 't1070', 'comp-001')
        if log_clear:
            evidence = self._evidence_from_alerts(log_clear)
            self._add(
                report,
                finding_id='HARD-042',
                title='Résilience de journalisation insuffisante face à l’effacement de traces',
                category='visibility',
                risk_explanation='Des traces d’effacement ou d’altération de journaux ont été vues, ce qui réduit la capacité de détection et de preuve.',
                recommendation='Durcir l’audit avancé, centraliser les journaux hors hôte, protéger les droits de nettoyage et surveiller explicitement les événements d’effacement.',
                impact='Les investigations ultérieures deviennent incomplètes et l’attaquant gagne en furtivité.',
                priority='critique',
                evidence=evidence,
                prerequisites=['Vérifier la capacité de stockage et la rétention du collecteur central avant augmentation de logs.'],
                validation_steps=['Contrôler que les événements d’effacement sont bien remontés au SIEM et non supprimables localement sans trace.'],
                rollback_steps=['Aucun rollback recommandé sur la centralisation ; ajuster seulement le niveau de verbosité si surcharge.'],
                candidate_scope='Contrôleurs de domaine et hôtes ayant montré un comportement d’effacement de traces.',
                confidence=self._confidence(len(log_clear)),
            )

    def _check_ad_general_hygiene(self, alerts: List[DetectionAlert], investigations: List[InvestigationObject], report: HardeningReport) -> None:
        evidence = []
        if alerts:
            evidence.extend(self._evidence_from_alerts(alerts, limit=2))
        if investigations:
            evidence.extend(self._evidence_from_investigations(investigations, limit=2))
        self._add(
            report,
            finding_id='HARD-040',
            title='Journalisation et visibilité AD à confirmer',
            category='hygiene',
            risk_explanation='Même avec des preuves exploitables, la couverture de logs peut rester partielle et masquer d’autres pivots ou comptes touchés.',
            recommendation='Valider l’audit avancé sur DC/serveurs critiques, centraliser les Event IDs clés et conserver au moins 90 jours de rétention utile pour l’IR.',
            impact='Une meilleure visibilité réduit le temps de qualification et augmente la confiance du scoring observé.',
            priority='modéré',
            evidence=evidence,
            prerequisites=['Confirmer les contraintes de rétention et de volumétrie du SIEM.'],
            validation_steps=['Vérifier la présence des Event IDs critiques sur les DC et serveurs d’administration.'],
            rollback_steps=['Réduire uniquement la verbosité non critique si le SIEM sature.'],
            candidate_scope='Politique d’audit Windows/AD et pipeline de centralisation.',
            confidence='medium',
        )

        if len(alerts) >= 20 or len(investigations) >= 5:
            self._add(
                report,
                finding_id='HARD-041',
                title='Revue AD ciblée recommandée après volume d’alertes élevé',
                category='hygiene',
                risk_explanation='Le volume observé suggère un problème systémique ou une dette de sécurité AD plus large que le seul incident en cours.',
                recommendation='Lancer un audit AD ciblé sur tiering, groupes privilégiés, comptes inactifs, délégations et GPO sensibles après containment.',
                impact='Réduit la probabilité de rechute et prépare un hardening durable au-delà du cas courant.',
                priority='modéré',
                evidence=[f"alerts={len(alerts)}", f"investigations={len(investigations)}"],
                prerequisites=['Attendre la stabilisation de l’incident avant audit exhaustif pour éviter de brouiller la qualification.'],
                validation_steps=['Comparer les findings d’audit AD aux faiblesses déjà observées dans l’investigation.'],
                rollback_steps=['Non applicable : revue de sécurité.'],
                candidate_scope='Active Directory dans son ensemble, avec priorité sur le périmètre touché.',
                confidence='medium',
            )
