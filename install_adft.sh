#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"
INSTALL_DEV=0
RUN_DEMO=0
LAUNCH_UI=0
OUTPUT_DIR="${ROOT_DIR}/reports_demo"
HOST="127.0.0.1"
PORT="8765"

usage() {
  cat <<USAGE
Usage: ./install_adft.sh [options]

Options:
  --dev           Install contributor/test dependencies too.
  --run-demo      Run a demo investigation after installation.
  --launch-ui     Launch the integrated GUI after installation.
  --output DIR    Output directory for demo/UI. Default: ./reports_demo
  --host HOST     UI bind host. Default: 127.0.0.1
  --port PORT     UI bind port. Default: 8765
  -h, --help      Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dev) INSTALL_DEV=1 ;;
    --run-demo) RUN_DEMO=1 ;;
    --launch-ui) LAUNCH_UI=1 ;;
    --output) OUTPUT_DIR="$2"; shift ;;
    --host) HOST="$2"; shift ;;
    --port) PORT="$2"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[ADFT] Unknown option: $1" >&2; usage; exit 1 ;;
  esac
  shift
done

echo "[ADFT] Repository root : ${ROOT_DIR}"
echo "[ADFT] Python         : ${PYTHON_BIN}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[ADFT] Python interpreter not found: ${PYTHON_BIN}" >&2
  exit 1
fi

"$PYTHON_BIN" -m venv "$VENV_DIR"
# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip setuptools wheel

if [[ "$INSTALL_DEV" -eq 1 ]]; then
  python -m pip install -e ".[full,dev]"
else
  python -m pip install -e ".[full]"
fi

echo "[ADFT] Dependency check"
python - <<'PY'
import importlib
checks = {
    'yaml': 'PyYAML runtime',
    'Evtx': 'python-evtx optional EVTX support',
}
for module, label in checks.items():
    try:
        importlib.import_module(module)
        print(f"  [OK] {label}")
    except Exception as exc:
        print(f"  [WARN] {label}: {exc}")
PY

echo "[ADFT] Installation complete."
echo "[ADFT] Official install path: ./install_adft.sh"
echo "[ADFT] Recommended demo dataset: adft/datasets/ransomware_demo_6000_events.json (zip twin included)"
echo "[ADFT] Next steps:"
echo "  source .venv/bin/activate"
echo "  adft investigate adft/datasets/ransomware_demo_6000_events.json -o ${OUTPUT_DIR} --format html json csv --export-events-jsonl"
echo "  adft ui -o ${OUTPUT_DIR} --host ${HOST} --port ${PORT}"

if [[ "$RUN_DEMO" -eq 1 ]]; then
  echo "[ADFT] Running demo investigation..."
  python main.py investigate adft/datasets/ransomware_demo_6000_events.json -o "$OUTPUT_DIR" --format html json csv --export-events-jsonl
fi

if [[ "$LAUNCH_UI" -eq 1 ]]; then
  echo "[ADFT] Launching GUI on http://${HOST}:${PORT}"
  python main.py ui -o "$OUTPUT_DIR" --host "$HOST" --port "$PORT"
fi
