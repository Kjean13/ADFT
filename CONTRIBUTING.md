# Contributing to ADFT

## Principles

- keep the product centered on offline evidence analysis
- keep the canonical ingestion contract intact: supported inputs -> canonical JSONL -> analysis
- prefer deterministic and testable logic over opaque heuristics
- never introduce automatic remediation against live environments
- update tests and documentation whenever behavior changes
- keep packaged GUI assets aligned with `frontend_source/`

## Recommended workflow

1. create a branch
2. add or adapt a minimal dataset showing the change
3. implement the change
4. run `pytest -q`
5. if the GUI changed, run `cd frontend_source && npm ci && npm run build`
6. copy the generated `frontend_source/dist/` into `adft/webui_dist/`
7. run at least one CLI smoke test and one GUI smoke test
8. update the relevant docs

## Pull requests

A good pull request should include:

- the problem being solved
- the exact scope of the change
- test evidence
- documentation updates when user-visible behavior changed
- packaged GUI refresh if frontend files changed

## Repository expectations

- keep CLI, API, UI, tests, and docs aligned
- avoid overclaiming in README or UI copy
- preserve original source traceability in conversion and reporting
- document any new output field or generated artefact
- explicitly mention optional dependencies when they affect runtime success, especially `python-evtx`
