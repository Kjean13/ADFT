# ADFT v1.0 — Scoring observé

## Purpose

The ADFT score measures **observed exposure in the analyzed evidence**. It is not a full Active Directory configuration audit.

## Categories

- authentication exposure;
- privilege risks;
- suspicious propagation / behavior;
- observed AD hygiene.

## Inputs used by the score

- alert severity;
- diversity of triggered rules;
- signal confidence;
- impacted AD-sensitive assets;
- exposed privileged identities;
- lateral movement evidence;
- observed campaign progression.

## Published calibration

- version: `observed-2026.03`
- method: `heuristic_evidence_weighting`
- output order for `severity_mix`: `critical, high, medium, low/info`

## Thresholds

- `<= 25`: critical
- `<= 50`: high
- `<= 75`: medium
- `> 75`: low

## Recommended reading

Interpret the score together with:

- `observed_scope`
- `severity_mix`
- `score_drivers`
- `data_quality`
