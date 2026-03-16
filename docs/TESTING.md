# Testing

## Unit and integration tests

```bash
pytest -q
```

## Frontend packaging validation

```bash
cd frontend_source
npm ci
npm run build
```

Then copy `frontend_source/dist/` into `adft/webui_dist/` before packaging a release.

## CLI smoke test

```bash
python main.py investigate adft/datasets/ransomware_pre_encryption_campaign.json -o /tmp/adft_reports_smoke --format html json csv --export-events-jsonl
python main.py summary -o /tmp/adft_reports_smoke
python main.py alerts -o /tmp/adft_reports_smoke --full
python main.py story -o /tmp/adft_reports_smoke
python main.py attack-chain -o /tmp/adft_reports_smoke
python main.py attack-path -o /tmp/adft_reports_smoke
python main.py report -o /tmp/adft_reports_smoke
```

## Integrated GUI smoke test

```bash
python main.py ui -o /tmp/adft_gui_smoke --host 127.0.0.1 --port 8765
```

Then open `http://127.0.0.1:8765` and validate:

- refresh button reloads backend state
- browser tab is branded `ADFT UI`
- analysis page exposes backend release and EVTX availability
- graph page supports centering, pan, zoom, node drag and time filtering
- graph page shows edges with directions and labels
- benchmark page exposes runtime and packaging checks
- exports page lists real artefacts from the last run

## Optional EVTX validation

```bash
./install_adft.sh --dev
source .venv/bin/activate
pytest -q adft/tests/test_evtx_resilience.py
```
