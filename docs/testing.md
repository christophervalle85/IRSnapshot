# Verification evidence

## Milestone 5 — release 0.5.0

Verified on 2026-10-02 on macOS (ARM64). These checks cover offline reporting and orchestration with injected Windows boundaries. **Actual Windows collection and live `run` remain unverified.**

| Check | Result |
|---|---|
| Full portable suite, Python 3.12.14 | 540 passed, 1 live test deselected |
| Full portable suite, Python 3.14.7 | 540 passed, 1 live test deselected |
| Focused reporting/workflow/collection integration suite | 108 passed |
| Package, test, and example compilation | Passed |
| Dependency integrity, both development environments and clean install | No broken requirements |
| Whitespace/error diff check | Passed |
| Wheel build | `irsnapshot-0.5.0-py3-none-any.whl` built successfully |
| Clean offline wheel installation | Imported from a fresh environment's `site-packages`, outside the source tree |
| Installed version/help and all four command help pages | Passed |
| Installed sample analysis and HTML | Benign/review/partial: 0/13/11 findings; exit 0/0/3 |
| Installed workflow with injected collection | Snapshot, JSON, HTML and log produced for all three samples; outputs match standalone reporting |
| Packaged template | Read and rendered from the installed wheel |
| Output safety | Refused writes preserve bytes; explicit overwrites deterministic; input same-path/symlink/hardlink aliases rejected |
| Non-Windows collect/run | Actionable exit 1; existing evidence/reports preserved, including explicit overwrite |
| Browser inspection | Review/partial reports checked; coverage, navigation, expandable evidence and IPv6 presentation inspected |
| Responsive report | 1280px and 390px checked; compact columns readable, tables scroll internally, no page overflow |
| Live Windows investigation | Not run; Windows x64 host required |

New cases exercise escaped HTML and issue text, safe static anchors, visible partial coverage, severity ordering, missing tree/ownership associations, 1,300-level iterative ancestry, invalid mutable reports, bounded atomic HTML publication, all four CLI commands, and input alias protection. The end-to-end collection test now carries all seven actual collectors through analysis and both report writers with only the typed Windows adapter replaced.

Workflow tests inject failures at analysis, JSON publication, and HTML publication, including keyboard interruption, and then reload the saved snapshot. Overwrite tests preserve unrelated files and earlier evidence until replacement publication succeeds. Logging tests exercise hard-link replacement, opening/write failures, escaped chained diagnostics, handler restoration, and source failures inside the actual collection pipeline.

One regression exposed a subtle publication boundary: the snapshot writer can finish publishing before its diagnostic log write fails. Logging errors now latch and surface at controlled workflow boundaries, allowing the workflow to record the saved snapshot and clear stale derived outputs before stopping. A separate integration check ensures collector isolation cannot hide a failed log as an ordinary partial success.

The HTML is self-contained, with inline CSS and no scripts or external resources. Parser checks verify safe tags, local anchor targets and unique IDs; browser inspection verified navigation and expandable raw evidence. Print styles are included, but printed output was not manually validated. Dependency versions remain those recorded for Milestone 3 below. Historical sample capture versions are unchanged.

Reproduce the new focused checks from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_investigation.py tests/test_workflow_cli.py tests/test_collection_pipeline.py tests/test_html_report.py tests/test_cli.py tests/test_collect_cli.py -q
.\.venv\Scripts\irsnapshot.exe report samples/review.snapshot.json --output review.html
.\.venv\Scripts\irsnapshot.exe report samples/partial.snapshot.json --output partial.html
$LASTEXITCODE
# Windows only; choose a new or empty directory:
.\.venv\Scripts\irsnapshot.exe run --output investigation/
```

## Milestone 4 — release 0.4.0

Verified on 2026-09-30, on macOS 26.5.2 (ARM64). These are portable tests with injected Windows boundaries and installed-package checks. **Actual Windows collection remains unverified.**

| Check | Result |
|---|---|
| Full portable suite, Python 3.12.14 | 467 passed, 1 live test deselected |
| Full portable suite, Python 3.14.7 | 467 passed, 1 live test deselected |
| Compilation and dependency integrity | Passed; no broken requirements |
| Whitespace/error diff check | Passed |
| Independent specification and quality review | Passed after traceback control-escaping regression fix |
| Wheel build | `irsnapshot-0.4.0-py3-none-any.whl` built successfully |
| Clean wheel installation | Installed offline in a new Python 3.12 environment |
| Installed help/version and both command help pages | Passed outside source tree |
| Installed sample analysis | 0/13/11 findings and exit 0/0/3 for benign/review/partial samples |
| Installed collect on macOS | Actionable Windows-only rejection, exit 1, no snapshot created |
| Existing output protection | Refusal and unsupported-platform failures preserve existing bytes, including with overwrite requested |
| Actual Windows read-only smoke | Not run; requires a Windows x64 host |

New cases exercise typed PowerShell envelopes and zero/one/many results, UTF-8 and malformed output, timeouts/nonzero exits, fixed script routing, data-only shortcut inputs, explicit registry views and shared duplicates, native discovery failures, remote/reparse path rejection, owner SID uncertainty, malformed nested task data, partial field and iteration failures, source projections, collector isolation, and CLI status/identity rendering. Reproducing regressions preceded corrections.

Independent review found that default traceback logging could expose terminal controls from a source exception. The repair retains readable chained diagnostics while escaping those controls before logging; its CLI regression verifies visible escapes, preserved traceback context, and a saved partial snapshot. Scoped re-review closed the finding with no remaining blocking issues.

An end-to-end fixture test uses all seven real collectors through the collection pipeline with only the Windows adapter replaced. It validates the snapshot, writes and reloads it, checks source references, and runs the actual analysis engine. Separate pipeline failure tests ensure malformed references, unexpected exceptions, context mutation, and invalid intervals do not erase other collectors' results. No fixture command or live endpoint query was executed.

The installed package imported from its new environment's `site-packages`; metadata and CLI reported `0.4.0`. Saved sample reports validated against `InvestigationReport` and retained the original snapshots. Repeated explicit overwrites were byte-identical, and refused writes preserved earlier files. Dependency versions remain those recorded for Milestone 3 below.

Live tests are deliberately excluded by default. On Windows, explicitly run `python -m pytest tests/test_windows_smoke.py -m windows_live -q`; see [collection verification](collection.md#verification-on-windows). That test requires usable basic evidence while allowing permission-related partial sources and variable ambient process counts.

## Milestone 3 — release 0.3.0

Verified on 2026-09-23, on macOS 26.5.2 (ARM64). These checks establish portable offline analysis and reporting behavior, not Windows integration readiness.

| Check | Result |
|---|---|
| Full pytest suite, Python 3.12.14 | 407 passed, 0 skipped |
| Full pytest suite, Python 3.14.7 | 407 passed, 0 skipped |
| Dependency integrity (`pip check`) | No broken requirements in development or clean installation |
| Package, example, and test compilation | Passed |
| Whitespace/error diff check | Passed |
| Independent final specification and quality review | Passed after regression fixes |
| Wheel build | `irsnapshot-0.3.0-py3-none-any.whl` built successfully |
| Clean wheel installation | Installed offline into a new Python 3.12 environment |
| Installed package outside source tree | CLI help/version/analyze and JSON validation passed |
| Installed benign sample | 0 findings, exit 0 |
| Installed review sample | 13 findings, exit 0 |
| Installed partial sample | 11 findings, exit 3; evaluation complete, collection incomplete |

The clean environment imported from `site-packages`, not the repository or an editable install. Package metadata and the installed console entry point reported `0.3.0`. Real subprocess checks validated every sample's JSON against `InvestigationReport`, preserved its original snapshot, and confirmed ruleset `1.0.0`. Refused writes preserved existing reports; explicit overwrites reproduced identical report bytes. Selecting the input as output was rejected even with overwrite enabled, and unsupported snapshot versions returned exit 2.

The 407 cases retain the foundation and interpretation coverage below and add process/persistence predicates, rule-failure isolation, deterministic findings, console/JSON reports, and real CLI behavior. Tests cover both positive and near-miss evidence, unsupported grammar, disabled and multi-action tasks, owner-scoped paths, malformed rule outputs, mutation isolation, duplicate evidence, missing system data, literal terminal rendering, file publication failures, and input aliases.

Independent review found a missing canonical rundll32 form, a certutil URL mistaken for an unrelated option's value, malformed URLs raising rule errors, non-exec task fields being promoted into findings, and escaped quotes exposing an unsupported script target. Each fix has a regression that failed before correction. No fixture command was executed. Engine, reporter, and CLI review found no further actionable issues.

Tested dependency versions remain Pydantic 2.13.5, Typer 0.27.2, Rich 14.3.4, psutil 7.2.2, Jinja2 3.1.6, and pytest 9.1.1. The wheel supplies the Python package; the source ZIP also supplies documentation, tests, examples, and synthetic snapshots.

## Milestone 2 — release 0.2.0

Verified on 2026-09-18, on macOS 26.5.2 (ARM64). These checks establish portable offline interpretation behavior; they do not establish Windows integration readiness.

| Check | Result |
|---|---|
| Full pytest suite, Python 3.12.14 | 247 passed, 0 skipped |
| Full pytest suite, Python 3.14.7 | 247 passed, 0 skipped |
| Retained foundation tests (models, storage, CLI) | 94 cases |
| Process trees and literal rendering | 17 cases |
| Windows lexical paths and captured variables | 51 cases |
| Command targets and PowerShell host options | 63 cases |
| Network and finding correlation | 12 cases |
| Factual timeline | 3 cases |
| Offline example subprocess behavior | 7 cases |
| Dependency integrity (`pip check`) | No broken requirements |
| Package and example compilation | Passed |
| Whitespace/error diff check | Passed |
| Independent specification and quality review | Passed after regression fixes |
| Wheel build | `irsnapshot-0.2.0-py3-none-any.whl` built successfully |
| Clean wheel installation | Installed offline into a new Python 3.12 environment |
| Installed package outside source tree | All interpretation imports, fixture APIs, CLI help/version, and example passed |

The clean environment imported from `site-packages`, not the repository or an editable install. Package metadata and the CLI both reported `0.2.0`. The source-tree example was launched from outside the repository using the clean interpreter, which imported the installed wheel. The wheel contains the interpretation, correlation, and rendering packages; the example, documentation, sample, and tests ship in the source archive.

Tested dependency versions: Pydantic 2.13.5, Typer 0.27.2, Rich 14.3.4, psutil 7.2.2, Jinja2 3.1.6, and pytest 9.1.1. The declared compatible ranges are in `pyproject.toml`; this record describes the versions actually exercised, not every possible resolution.

## What Milestone 2 tests establish

- Stable parent/child associations retain orphans, equal or missing creation times, PID 0, rejected newer parents, and broken cycles. Deep-tree construction handles 1,800 nodes without recursive traversal; rendering is tested for hierarchy and literal labels.
- Windows path normalization respects boundaries and captured owner-scoped variables, remains independent of the analyst host, and preserves unsupported syntax as unresolved.
- Direct and indirect variable cycles, expansion fan-out, additional colons/streams, and conflicting root captures cannot produce false supported-path facts or unbounded expansion.
- PowerShell aliases are distinguished from script arguments and encoded-argument options. Encoded content is retained as opaque text. Missing, unsupported, and malformed options stop interpretation.
- Network ownership retains null, missing, and time-conflicting owners; PID 0 and scoped IPv6 evidence remain intact. Findings obtain structural context without severity propagation or PID-hint guesses.
- Timeline events use actual captured event timestamps, distinguish reported from observed times, and never substitute task schedules or observation times for unknown execution events.
- The example reads a valid snapshot without writing files; it reports invalid/missing inputs cleanly and retains evidence when system collection failed. Captured Rich markup and terminal controls render as literal data.

Tests were run before the corresponding implementations and failed as expected. Independent review found four interpretation defects (unsupported colons, growing variable cycles, cross-category UUID collisions, and order-dependent root ties) and one example defect (absent system information). Each received a failing regression before correction. Additional regressions cover modern PowerShell working-directory and version prefixes. The final reviewer independently ran all 247 cases on both Python versions and found no remaining actionable issues.

## Retained Milestone 1 verification

Release 0.1.0 was verified on 2026-09-17 on the same macOS architecture with 94 passing cases on Python 3.12.14 and 3.14.7, a clean wheel installation, package compilation, and dependency checks. The installed version/help/usage behavior and snapshot read/write round trip passed outside the source tree. All foundation cases remain in the current suite:

- Valid snapshots survive JSON round trips, including UUIDs, Unicode, null values, and timezone offsets.
- Naive timestamps, numeric epoch strings, negative/coerced PIDs, invalid ports, wrong address families, and unexpected fields are rejected.
- Duplicate artifacts, mismatched coverage counts, unsupported schema versions, and dangling persistence/report references are rejected.
- Failed/skipped system collection can be represented explicitly; absent system fields cannot masquerade as successful collection without matching issues.
- Invalid input produces `SnapshotValidationError` without echoing raw evidence values in its message, including JSON parser integer-limit failures.
- Existing files survive refused writes; eight concurrent writers publish exactly one complete file.
- Simulated publication and sync failures preserve existing destinations and clean temporary files.
- Mutated invalid models are rejected before publication. File size limits and symlink no-clobber behavior are exercised.
- Help/version work through both Typer's test runner and actual Python subprocesses; nonexistent collection commands return a usage error.

The initial foundation review found unknown system fields without issues, numeric-string timestamp coercion, and an unnormalized JSON integer error. Reproducing regressions preceded the fixes.

## Reproduce on Windows

From the extracted repository root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\irsnapshot.exe --version
.\.venv\Scripts\irsnapshot.exe --help
.\.venv\Scripts\irsnapshot.exe analyze samples/review.snapshot.json --output analysis.json
.\.venv\Scripts\irsnapshot.exe analyze samples/partial.snapshot.json
$LASTEXITCODE
.\.venv\Scripts\irsnapshot.exe report samples/review.snapshot.json --output review.html
.\.venv\Scripts\irsnapshot.exe report samples/partial.snapshot.json --output partial.html
$LASTEXITCODE
.\.venv\Scripts\python.exe examples/interpret_snapshot.py samples/benign.snapshot.json
.\.venv\Scripts\python.exe -m pip wheel --no-deps --wheel-dir dist .
```

The review sample should produce thirteen findings and exit 0; the partial sample should produce eleven and exit 3. A Windows account without permission to create symbolic links may skip alias tests; inspect the test summary rather than assuming a zero-skip result. The [README](../README.md) includes the analysis/collection subset commands and a sample storage round trip. The output file must not already exist unless you explicitly add `--overwrite`.

## Remaining validation limits

No Windows host was available for this milestone. Windows installation, NTFS publication semantics, path permissions, native API behavior, and actual PowerShell queries still require Windows execution. Hard-link publication is intentionally unsupported on filesystems that do not provide it. Endpoint collectors and an opt-in live test are implemented but have only portable fixture coverage here. HTML reporting and investigation orchestration are implemented; live `run` verification requires a Windows host.

Tests use synthetic inputs; no suspicious fixture is executed. JSON Schema documents types and field constraints, but Python validators also enforce semantic and cross-record constraints. Validating a file with a generic JSON Schema checker alone is not equivalent to `load_snapshot`.
