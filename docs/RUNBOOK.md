# Runbook

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

Optional EVTX support:

```bash
pip install -e ".[evtx]"
```

## Convert evidence

```bash
adft convert test_logs -o converted_inputs
```

## Run an investigation

```bash
adft investigate test_logs/attack.json -o reports_core
```

## Inspect outputs

```bash
adft summary -o reports_core
adft alerts -o reports_core --full
adft score -o reports_core
adft story -o reports_core --full
adft attack-chain -o reports_core
adft attack-path -o reports_core
adft reconstruct -o reports_core --full
adft report -o reports_core
```

## Launch the integrated GUI

```bash
adft ui -o reports_gui --host 127.0.0.1 --port 8765
```

Then open `http://127.0.0.1:8765`.

## Export remediation candidates

```bash
adft harden -o reports_core --dry-run --export-scripts reports_core/remediation
```
