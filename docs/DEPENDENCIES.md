# Dependencies

## Source of truth

`pyproject.toml` is the authoritative packaging definition for ADFT v1.0.

Top-level install entry points:

- `install_adft.sh` → official complete installation path for v1.0
- `requirements-dev.txt` → contributor/test bootstrap

There is intentionally no `requirements-full.txt` in the repository anymore. The old split added ambiguity without adding value.

## Python runtime

Required:

- Python 3.10+
- `PyYAML>=6.0`

Strongly recommended for real-world use and EVTX validation:

- `python-evtx>=0.7`

## Install paths

Packaging installs:

- `pip install -e .` → minimal runtime from `pyproject.toml`
- `pip install -e ".[full]"` → runtime + EVTX support
- `pip install -e ".[full,dev]"` → runtime + EVTX + pytest stack

Convenience requirements installs:

- `./install_adft.sh` → creates `.venv`, installs ADFT with EVTX support and verifies imports
- `pip install -r requirements-dev.txt` → contributor/test bootstrap from the repository root

## Development-only

- `pytest>=7.0`
- `pytest-cov>=4.0`

## Frontend build chain

The packaged GUI in `adft/webui_dist/` is already built and served by the backend.

Only contributors rebuilding the UI need:

- Node.js 20+
- npm 10+

Frontend source lives in `frontend_source/` and is built with Vite/React.

## Failure mode to know

If `python-evtx` is missing:

- EVTX files stay within the declared supported perimeter
- EVTX conversion cannot succeed at runtime
- the CLI and GUI should report the failure clearly
- the recommended installation path remains `./install_adft.sh`

## One-command install

Use `./install_adft.sh --run-demo --launch-ui` to create the virtual environment, install the full dependency set including `python-evtx`, run the bundled demo dataset and launch the integrated UI. Use `--dev` when you want the contributor/test stack too.
