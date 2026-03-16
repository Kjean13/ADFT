# Security notes

- ADFT is an offline investigation toolkit. Feed it exported evidence rather than live domain credentials.
- Treat generated remediation scripts as candidate actions to review before execution.
- Prefer running investigations on copies of evidence, not on production systems.
- If EVTX support is required, install the optional `.[evtx]` extra in a controlled Python environment.
