# Architecture

ADFT v1.0 is an offline investigation engine with an integrated local web UI.

## Core flow

1. source evidence is collected from exported files
2. every supported source is converted to canonical JSONL
3. the investigation pipeline ingests the canonical JSONL set
4. deterministic detections and correlations are applied
5. scoring, reconstruction, hardening and reporting are generated
6. the backend stores a run state and exposes it to the integrated GUI

## Main modules

- `adft/core` — ingestion, normalization and data models
- `adft/detection` — rulepack and detection pipeline
- `adft/correlation` — alert grouping and campaign logic
- `adft/timeline` — chronological reconstruction
- `adft/graph` — entity graph and attack path analysis
- `adft/investigation` — case narrative and compromise reconstruction
- `adft/analysis` — scoring and data-quality logic
- `adft/harden` — remediation logic
- `adft/reporting` — report rendering
- `adft/exports` — Navigator and replay exports
- `adft/ui_server.py` — integrated HTTP server and GUI backend bridge
- `adft/webui_dist` — packaged web UI assets served by the backend
- `frontend_source` — React/Vite source used to rebuild the packaged GUI

## Product stance

v1.0 distributes one official GUI only: the integrated web UI launched with `adft ui`.

## GUI data contract

The browser does not reimplement the engine.
It consumes backend endpoints that expose:

- run state
- artefacts
- conversion manifest
- backend health
- GUI capabilities

## Graph view design

The graph page now follows these constraints:

- centered pivot-based navigation
- visible directed edges with analyst-readable labels
- time-window filtering on observed relations
- node enrichment with risk, first-seen, last-seen and IOC marker when present
- bounded display with pagination for noisy graphs
- local interaction only: pan, zoom and node drag

## Cache behavior

The integrated server serves GUI static assets with no-cache headers so release retests are not polluted by stale browser bundles.


- Web UI includes a client-side FR/EN language layer persisted in browser storage for analyst-facing navigation and screens.
