# ADFT v1.0 — Event Schema

## Canonical ingestion model

ADFT accepts multiple source formats at the edge, but the runtime analyzes a single internal format:

- **canonical format**: JSONL
- **canonical event contract**: JSON object later normalized into `NormalizedEvent`

Every supported non-JSON source is parsed and rewritten to canonical JSONL before analysis.

## Supported source formats

| Source format | Parser | Canonical output |
|---|---|---|
| EVTX | `EvtxParser` | JSONL |
| JSON / JSONL / NDJSON | `JsonParser` | JSONL |
| YAML / YML | `YamlParser` | JSONL |
| CSV / TSV | `CsvParser` | JSONL |
| CEF | `CefParser` | JSONL |
| LEEF | `LeefParser` | JSONL |
| XML | `XmlEventParser` | JSONL |
| Syslog / log / txt | `SyslogParser`, `CefParser`, `LeefParser` | JSONL |
| Markdown tables | `MarkdownTableParser` | JSONL |
| ZIP | `ZipParser` | JSONL |

## Canonical metadata fields

Canonical conversion preserves source traceability through metadata such as:

- `_source_file`
- `_parser`
- `_canonical_format`
- `_source_extension`
- `_conversion`
- `_canonical_source_file`

## NormalizedEvent core fields

- `timestamp`
- `event_id`
- `user`
- `source_host`
- `target_host`
- `action`
- `severity`
- `source_log`

## Enrichment fields

- `domain`
- `logon_type`
- `ticket_encryption`
- `ticket_options`
- `service_name`
- `target_user`
- `group_name`
- `process_name`
- `ip_address`
- `status`
- `sub_status`

## Validation rules

Conversion manifests also record parser failures, skipped files, empty sources, and optional dependency availability.


- `event_id` must be convertible to an integer;
- `timestamp` must be parseable or coercible;
- malformed or unsupported records are dropped and surfaced in `data_quality`.
