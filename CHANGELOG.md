# Changelog

## 0.3.0 — Milestone 3

- Implement ten process rules and three persistence rules with fixed severity, deterministic finding IDs, original evidence, and benign explanations.
- Extract direct executable and supported interpreter/file persistence targets conservatively; aggregate multiple matching task actions without duplicate projection findings.
- Add the analysis engine with per-rule failure isolation, stable ordering, preserved evidence, and separate collection/analysis completeness.
- Add literal-text console reporting and atomic JSON investigation-report publication.
- Add `irsnapshot analyze SNAPSHOT [--output PATH] [--overwrite]` with explicit outcomes for partial collection and invalid input.
- Include synthetic review/partial walkthroughs, rule documentation, and positive/near-miss regression tests.

Snapshot and analysis schemas remain `1.0`; bundled ruleset version is `1.0.0`. Live collection and HTML reporting remain planned.

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
