from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Dict, Iterable, List, Tuple

from adft.graph.attack_path import build_attack_paths


def _parse_ts(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    try:
        text = str(value).replace('Z', '+00:00')
        return datetime.fromisoformat(text)
    except Exception:
        return None


def _uniq(values: Iterable[str], limit: int | None = None) -> List[str]:
    out: List[str] = []
    seen = set()
    for value in values:
        text = str(value or '').strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if limit is not None and len(out) >= limit:
            break
    return out


def _top(values: Iterable[str], limit: int = 6) -> List[str]:
    counts = Counter(str(v).strip() for v in values if str(v).strip())
    return [name for name, _ in counts.most_common(limit)]


def _is_dc_like(host: str) -> bool:
    s = str(host or '').strip().lower()
    return s.startswith('dc') or s in {'domaincontroller', 'domain-controller'}


def _is_privileged_account(name: str) -> bool:
    s = str(name or '').strip().lower()
    tokens = ('admin', 'administrator', 'krbtgt', 'domain admins', 'enterprise admins', 'root', 'svc_')
    return any(tok in s for tok in tokens)


def _severity_weight(value: Any) -> int:
    order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    return order.get(str(value or '').strip().lower(), 0)


def _pick_patient_zero_alert(alerts: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    if not alerts:
        return None
    ranked = sorted(
        alerts,
        key=lambda a: (
            _parse_ts(a.get('timestamp')) or datetime.min,
            -_severity_weight(a.get('severity')),
            str(a.get('rule_id') or a.get('rule_name') or ''),
        ),
    )
    high = [a for a in ranked if _severity_weight(a.get('severity')) >= 3]
    return (high or ranked)[0]


def _scope_label(hosts: List[str], dcs: List[str], accounts: List[str]) -> str:
    if dcs or any(_is_privileged_account(a) for a in accounts):
        return 'domain_tier_observed'
    if len(hosts) >= 3:
        return 'multi_host_observed'
    if len(hosts) == 2:
        return 'two_hosts_observed'
    if len(hosts) == 1:
        return 'single_host_observed'
    return 'limited_scope_observed'


def _confidence(alerts_count: int, phases_count: int, paths_count: int) -> Tuple[float, str]:
    score = min(1.0, 0.35 + alerts_count * 0.04 + phases_count * 0.07 + paths_count * 0.03)
    if score >= 0.85:
        return (round(score, 2), 'high')
    if score >= 0.65:
        return (round(score, 2), 'moderate')
    return (round(score, 2), 'limited')


def build_compromise_reconstruction(
    *,
    alerts: List[Dict[str, Any]] | None = None,
    investigations: List[Dict[str, Any]] | None = None,
    timeline: Dict[str, Any] | None = None,
    entity_graph: Dict[str, Any] | None = None,
    attack_story: List[str] | None = None,
) -> Dict[str, Any]:
    alerts = list(alerts or [])
    investigations = list(investigations or [])
    timeline = dict(timeline or {})
    entity_graph = dict(entity_graph or {})
    attack_story = list(attack_story or [])

    timeline_entries = list(timeline.get('entries') or [])
    timeline_entries.sort(key=lambda e: _parse_ts(e.get('timestamp')) or datetime.min)
    alert_times = [_parse_ts(a.get('timestamp')) for a in alerts]
    alert_times = [x for x in alert_times if x is not None]
    entry_times = [_parse_ts(e.get('timestamp')) for e in timeline_entries]
    entry_times = [x for x in entry_times if x is not None]
    all_times = sorted(alert_times + entry_times)
    first_seen = all_times[0] if all_times else None
    last_seen = all_times[-1] if all_times else None
    duration_minutes = 0.0
    if first_seen and last_seen:
        duration_minutes = round(max(0.0, (last_seen - first_seen).total_seconds() / 60.0), 1)

    accounts = _uniq(
        [a.get('user') for a in alerts]
        + [i.get('primary_entity') or i.get('identity') for i in investigations]
        + [n.get('value') for n in (entity_graph.get('nodes') or []) if n.get('type') == 'account'],
        12,
    )
    hosts = _uniq(
        [a.get('source_host') for a in alerts]
        + [a.get('target_host') for a in alerts]
        + [n.get('value') for n in (entity_graph.get('nodes') or []) if n.get('type') == 'host'],
        16,
    )
    source_ips = _uniq(
        [a.get('source_ip') for a in alerts]
        + [n.get('value') for n in (entity_graph.get('nodes') or []) if n.get('type') == 'ip'],
        12,
    )
    phases_seen = _uniq([e.get('phase') for e in timeline_entries], 8)
    dcs = _uniq([h for h in hosts if _is_dc_like(h)], 8)
    privileged_accounts = _uniq([a for a in accounts if _is_privileged_account(a)], 8)

    pz_alert = _pick_patient_zero_alert(alerts)
    patient_zero_account = None
    patient_zero_host = None
    initial_access = None
    if pz_alert:
        patient_zero_account = pz_alert.get('user') or None
        candidate_hosts = [pz_alert.get('source_host'), pz_alert.get('target_host')]
        patient_zero_host = next((h for h in candidate_hosts if h and not _is_dc_like(h)), None) or next((h for h in candidate_hosts if h), None)
        initial_access = {
            'timestamp': pz_alert.get('timestamp'),
            'rule_name': pz_alert.get('rule_name') or pz_alert.get('rule_id'),
            'mitre_tactic': pz_alert.get('mitre_tactic'),
            'mitre_technique': pz_alert.get('mitre_technique'),
            'source_ip': pz_alert.get('source_ip'),
            'source_host': pz_alert.get('source_host'),
            'target_host': pz_alert.get('target_host'),
            'user': pz_alert.get('user'),
        }

    if not patient_zero_account and accounts:
        patient_zero_account = accounts[0]
    if not patient_zero_host:
        patient_zero_host = next((h for h in hosts if not _is_dc_like(h)), None) or (hosts[0] if hosts else None)

    path_candidates = list((entity_graph.get('analysis') or {}).get('paths') or [])
    if not path_candidates:
        paths = build_attack_paths(entity_graph, max_depth=6, include_single_hop=True)
        path_candidates = [
            {'path': path, 'summary': ' → '.join(path), 'length': len(path)}
            for path in paths[:8]
        ]
    else:
        path_candidates = [
            {
                'path': item.get('path') or [],
                'summary': item.get('summary') or ' → '.join(item.get('path') or []),
                'length': item.get('length') or len(item.get('path') or []),
                'risk_level': item.get('risk_level'),
                'risk_score': item.get('risk_score'),
                'reasons': item.get('reasons') or [],
            }
            for item in path_candidates[:8]
        ]

    severity_mix = Counter(str(a.get('severity') or '').lower() for a in alerts if a.get('severity'))
    top_rules = _top([a.get('rule_name') or a.get('rule_id') or '' for a in alerts], 5)
    top_tactics = _top([a.get('mitre_tactic') or '' for a in alerts], 5)
    confidence, confidence_label = _confidence(len(alerts), len(phases_seen), len(path_candidates))
    scope = _scope_label(hosts, dcs, accounts)

    objective = 'lateral_movement_or_access_expansion'
    if 'domain_dominance' in phases_seen or privileged_accounts or dcs:
        objective = 'ad_control_or_privileged_access'
    elif 'credential_access' in phases_seen:
        objective = 'credential_theft_or_abuse'

    key_observations: List[str] = []
    if patient_zero_host or patient_zero_account:
        key_observations.append(
            f"Pivot initial probable: {patient_zero_account or 'compte inconnu'} depuis {patient_zero_host or 'hôte inconnu'}."
        )
    if dcs:
        key_observations.append('Actifs AD sensibles observés: ' + ', '.join(dcs[:4]) + '.')
    if privileged_accounts:
        key_observations.append('Identités à privilèges exposées: ' + ', '.join(privileged_accounts[:4]) + '.')
    if path_candidates:
        key_observations.append('Chemin(s) d’attaque observé(s): ' + ' ; '.join(p['summary'] for p in path_candidates[:2]) + '.')
        top_path = path_candidates[0]
        if top_path.get('reasons'):
            key_observations.append('Justification du chemin prioritaire: ' + ', '.join(top_path.get('reasons')[:3]) + '.')
    if top_tactics:
        key_observations.append('Tactiques dominantes: ' + ', '.join(top_tactics[:3]) + '.')
    if not key_observations and attack_story:
        key_observations.extend(attack_story[:3])

    affected_accounts = _uniq(accounts, 10)
    impacted_hosts = _uniq(hosts, 10)
    crown_jewels = _uniq(dcs + privileged_accounts, 10)
    narrative_steps = []
    for idx, entry in enumerate(timeline_entries[:10], 1):
        narrative_steps.append({
            'step': idx,
            'timestamp': entry.get('timestamp'),
            'phase': entry.get('phase'),
            'title': entry.get('title') or entry.get('rule_id') or f'step-{idx}',
            'description': entry.get('description'),
            'entities': entry.get('entities') or [],
        })

    summary_parts = []
    if patient_zero_account or patient_zero_host:
        summary_parts.append(
            f"Compromission observée à partir de {patient_zero_account or 'compte indéterminé'} sur {patient_zero_host or 'hôte indéterminé'}"
        )
    if impacted_hosts:
        summary_parts.append(f"{len(impacted_hosts)} hôte(s) touché(s)")
    if phases_seen:
        summary_parts.append('phases visibles : ' + ', '.join(phases_seen[:4]))
    if crown_jewels:
        summary_parts.append('actifs/identités sensibles : ' + ', '.join(crown_jewels[:3]))
    summary = '; '.join(summary_parts) + ('.' if summary_parts else 'Reconstruction limitée faute de preuves suffisantes.')

    return {
        'available': bool(alerts or timeline_entries),
        'summary': summary,
        'first_observed': first_seen.isoformat() if first_seen else None,
        'last_observed': last_seen.isoformat() if last_seen else None,
        'duration_minutes': duration_minutes,
        'phases_seen': phases_seen,
        'scope': scope,
        'confidence': confidence,
        'confidence_label': confidence_label,
        'probable_objective': objective,
        'patient_zero_account': patient_zero_account,
        'patient_zero_host': patient_zero_host,
        'initial_access': initial_access,
        'source_ips': source_ips,
        'impacted_hosts': impacted_hosts,
        'affected_accounts': affected_accounts,
        'privileged_accounts': privileged_accounts,
        'domain_controllers': dcs,
        'crown_jewels': crown_jewels,
        'top_rules': top_rules,
        'top_tactics': top_tactics,
        'severity_mix': dict(severity_mix),
        'path_candidates': path_candidates,
        'key_observations': key_observations[:6],
        'narrative_steps': narrative_steps,
        'attack_story': attack_story[:12],
        'investigation_ids': _uniq([i.get('id') for i in investigations], 12),
    }
