
## 2026-03-15 — Benchmark UI refinement
- removed the static benchmark recommendation block from the GUI
- replaced raw text with visual benchmark charts
- added observed incident-rate stats (avg evt/s, peak window, graph density, artifact footprint, source count)
- improved benchmark artifact listing with per-artifact size

# Changelog

## v1.0.0

- official integrated GUI aligned with the canonical CLI and backend state
- browser title/icon changed from placeholder branding to `ADFT UI`
- refresh action hardened with backend capability reload and cache-busting fetches
- static GUI assets served with no-cache headers
- graph page upgraded with centered pivot view, directed edges, pan/zoom, drag, time filter and node enrichment
- benchmark page added for runtime and packaging validation
- install script added for one-shot setup and optional demo launch
- dependency documentation clarified, including mandatory `python-evtx` path for real EVTX validation
- tests and release docs updated to cover packaged frontend behavior

- GUI: added persistent FR/EN language switch for the integrated web UI.
- graph workspace: added a fullscreen mode for laptop-friendly analysis and easier pan/zoom navigation.
