# Changelog

## 0.2.0 — Milestone 2

- Build stable process forests, preserve missing parents and uncertain times, and break cycles deterministically.
- Interpret Windows paths using captured roots and scoped environment values; retain unsupported, conflicting, or excessive expansions as unresolved.
- Extract a conservative subset of PowerShell host options and explicit service/Run executable targets without decoding or executing payloads.
- Associate network records and finding evidence with processes without propagating severity.
- Construct factual timelines using reported event times and observed collection boundaries.
- Render process trees as literal, control-safe Rich text; add a read-only example and interpretation documentation.
- Add fixture and subprocess regression tests, including ambiguous paths, UUID collisions, partial snapshots, and command/payload boundaries.

Snapshot schema remains `1.0`. Live collection, detection rules, and full reports remain planned.

## 0.1.0 — Milestone 1

- Define versioned evidence and analysis contracts using Pydantic.
- Validate coverage, references, strict scalar fields, and UTC-aware timestamps.
- Add snapshot JSON loading and atomic writes with explicit overwrite control.
- Add the help/version CLI and Python module entry point.
- Include a synthetic sample and meaningful model, storage, and CLI tests.

Live collection and behavioral analysis are not part of this milestone.
