# Release validation

Repository sanity:

- `pyproject.toml` = packaging source of truth
- `install_adft.sh` = official complete install path for v1.0
- `requirements-dev.txt` = contributor/test bootstrap only

```bash
python3 -m py_compile $(find adft -name '*.py' -type f) main.py
pytest -q
cd frontend_source && npm ci && npm run build && cd ..
rm -rf adft/webui_dist && cp -r frontend_source/dist adft/webui_dist
python3 main.py investigate adft/datasets/ransomware_pre_encryption_campaign.json -o /tmp/adft_release_reports --format html json csv --export-events-jsonl
python3 main.py report -o /tmp/adft_release_reports
python3 main.py ui -o /tmp/adft_release_reports --host 127.0.0.1 --port 8765
```

Manual browser checks:

- tab title = `ADFT UI`
- refresh button works
- graph page shows arrows and labels
- graph page supports zoom / pan / drag
- benchmark page shows EVTX capability and artefacts
