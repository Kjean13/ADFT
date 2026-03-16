# ADFT — RulePack v1.0

This pack freezes the current deterministic rule set used by ADFT v1.0

## Scope

- **34 rules**
- deterministic evaluation only
- MITRE ATT&CK mapping kept in the rulepack

## Coverage areas

- Kerberos abuse
- identity and authentication abuse
- privilege escalation and group changes
- lateral movement
- persistence and service installation
- ransomware pre-encryption signals
- suspicious process and PowerShell abuse
- GPO abuse
- DCShadow / DCSync
- DLL / LOLBin abuse
- service account abuse
- anti-forensics

## Source of truth

- `adft/detection/rulepacks/v1.py`
- `adft/detection/engine.py`

## Validation

- `adft/tests/test_rulepack_v1_datasets.py`
- end-to-end scenario tests under `adft/tests/`

## Usage

`adft investigate ...` loads RulePack v1.0 by default.
