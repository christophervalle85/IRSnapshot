# Changelog

## 0.5.0 — Milestone 5

- Add a packaged Jinja2 HTML report with escaped evidence, inline styles, print support, and no scripts or external assets.
- Present collection and analysis completeness, prioritized findings, process ancestry, network ownership, persistence inventory, factual UTC timeline, and raw evidence.
- Add `report SNAPSHOT --output PATH [--overwrite]` for offline HTML generation with input preservation.
- Add `run --output DIRECTORY [--overwrite]` for snapshot, JSON analysis, HTML report, and a scoped diagnostic log.
- Save the snapshot before downstream work; preserve it after analysis/reporting failure and prevent stale reports from representing a new run.
- Add HTML, CLI, output-safety, recovery, and logging regression tests plus a reporting guide.

Snapshot and analysis schemas remain `1.0`; ruleset remains `1.0.0`. Actual Windows integration remains unverified on the macOS development host.

## 0.4.0 — Milestone 4

- Add Windows system, process, network, user, service, scheduled-task, and persistence collectors.
- Add typed Windows source responses, fixed read-only PowerShell queries, native path/identity discovery, and explicit registry views.
- Preserve partial records, unavailable fields, and source failures in the existing coverage model.
- Add failure-isolated collection orchestration and `collect --output PATH [--overwrite]` with atomic snapshot publication.
- Add injected adapter/collector/pipeline tests, opt-in Windows smoke coverage, and collection documentation.

Snapshot and analysis schemas remain `1.0`; ruleset remains `1.0.0`. Actual Windows integration remains unverified on the macOS development host. HTML reporting and `report`/`run` remain planned.

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
