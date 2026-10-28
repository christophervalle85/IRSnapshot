# Verification evidence

Dated results below describe the environments and source revisions actually exercised. Earlier platform status is superseded by later execution records.

## Version 1.0.0 release verification — 2026-10-28

Version 1.0.0 closes M6 for the implemented triage workflow and release packaging. Windows 10/11 x64 ordinary/elevated desktop validation is deferred and remains unverified. Follow-up work is tracked in [repository issues](https://github.com/christophervalle85/IRSnapshot/issues).

| Check | Result |
|---|---|
| Portable suite, macOS ARM64, Python 3.12.14 | 562 passed, 3 live tests deselected |
| Portable suite, macOS ARM64, Python 3.14.8 | 562 passed, 3 live tests deselected |
| Version 1.0.0 wheel | Built successfully with setuptools; no new runtime dependencies |
| Fresh Python 3.12 wheel installation and dependency check | Passed; imported from the new environment's site-packages |
| Isolated installed-command validation | Passed; console/module entry points, packaged template, JSON/HTML, and investigation orchestration |
| Synthetic expected findings/exits | Benign 0/0, review 13/0, partial 11/3 |

Application implementation matches the previously tested native Windows source apart from the package version constant. Original snapshot capture versions, snapshot/analysis schema `1.0`, and ruleset `1.0.0` are preserved.

The successful native Windows evidence below was recorded on October 15 against its original source revision. Later hosted jobs did not start: GitHub's [October 22 run](https://github.com/christophervalle85/IRSnapshot/actions/runs/39825998456) reports an account billing/spending-limit restriction before any steps executed. These are unavailable reruns, not new passing Windows results. Local release verification does not establish Windows desktop coverage.

## Milestone 6 — LocalAccounts correction, 2026-10-15

Windows 10/11 x64 desktop privilege checks remain unverified. Hosted Server results do not establish desktop coverage.

The [module-discovery diagnostic and regression](https://github.com/christophervalle85/IRSnapshot/actions/runs/38108022999) established the account-collection defect before the production change. Both baseline runs returned only the current token and two `System.IO.FileNotFoundException` issues. Replacing the manifest path with its trusted absolute module directory returned one current token, four local accounts and one administrator membership, with no issues. Repeating the baseline still failed, ruling out cache warming as the explanation. The new native regression failed against the original application code.

Commit `51e635b665f6053f578d1e8f5d614b91b15baf5c` applies that directory-based import to both LocalAccounts queries. It accommodates version subdirectories while preserving the fixed system executable, sanitized environment, absolute trusted module root and `-NoProfile` behavior. Temporary diagnostic files were removed.

Fresh macOS checks after the fix: Python 3.12.14 and 3.14.7 each passed **562 portable cases**, with **3 live tests deselected**. A new wheel was built with the already-installed setuptools 84.0.0, installed offline into a fresh Python 3.12 environment, and passed dependency and isolated installed-package validation for all three samples. The first offline isolated build attempt could not find a cached setuptools wheel; the successful build used the existing build backend without build isolation. No network fetch was needed for the local build or installation. This is an unreleased verification build, not a replacement for the historical Milestone 5 wheel.

The [full corrected-source Windows run](https://github.com/christophervalle85/IRSnapshot/actions/runs/38686690894) passed on both matrix entries for commit `51e635b665f6053f578d1e8f5d614b91b15baf5c`:

| Check | Python 3.12.10 | Python 3.15.0 |
|---|---|---|
| Platform | Windows Server 2025 x64, build 26100, elevated | Same |
| Runner image | `windows-2025-vs2026`, `20261007.264.1` | `windows-2025-vs2026`, `20260925.250.1` |
| Portable suite | 562 passed, 3 live tests deselected | 562 passed, 3 live tests deselected |
| Fresh wheel, dependency and synthetic installation checks | Passed | Passed |
| Installed-wheel live tests | 3 passed | 3 passed |
| Real `collect` and `run` exits | 3 (partial) | 3 (partial) |
| System, network, users, services, tasks, persistence | All six sources `ok`, no issues | All six sources `ok`, no issues |
| Processes | Partial: 4 access-denied issues | Partial: 4 access-denied issues |

Both real captures on both runners recorded 7 user/session records, 259 services, 209 scheduled tasks and 475 persistence entries. Ambient process/network counts varied, as expected. The native LocalAccounts regression now passes against the actual fixed application, completing the observed red/green cycle. The live CLI checks confirm JSON snapshot equality, HTML snapshot identifiers, overwrite protection, deterministic report replacement and the complete investigation artifact set; they do not constitute visual inspection of every rendered field.

The dedicated LocalAccounts regression allows 120 seconds to test discovery independently of the production query timeout. The full CLI retains its 30-second PowerShell limit. No query timed out in these final reported CLI captures; earlier runner timeouts remain a documented operational limit, not a condition guaranteed to be eliminated. Process-access denials correctly kept the investigation exit at 3.

Final code, tests and workflow match the tested commit; subsequent documentation-only changes do not claim additional platform coverage. This October 15 record predates the v1.0.0 scope decision. Windows 10/11 desktop validation was subsequently deferred; current release verification is recorded above.

## Milestone 6 — first hosted Windows execution, 2026-10-10

The timestamps in GitHub are 2026-10-11 UTC; the local verification date is 2026-10-10 (America/Chicago).

The [first run](https://github.com/christophervalle85/IRSnapshot/actions/runs/38105351348) at `e3f34cb` failed 13 test cases on both Python versions. Six help assertions assumed ANSI styling was absent; seven workflow cases used C0 control characters in filenames that Windows rejects. No application-code change was needed. Commit `bd93193` normalizes only help assertion text and uses DEL in filename fixtures, preserving tests of literal markup, control escaping, evidence recovery and overwrite protection. ESC/BEL evidence tests remain elsewhere. Forced-color help failures were reproduced locally before the fix; the full 562-case suite then passed under forced-color settings.

The [successful rerun](https://github.com/christophervalle85/IRSnapshot/actions/runs/38105710915) verified `bd93193685c642be26a575873ec8fe81f13f4726`:

| Check | Python 3.12.10 | Python 3.15.0 |
|---|---|---|
| Runner | Windows Server 2025 x64, build 26100 | Same |
| Image | `windows-2025-vs2026`, `20260925.250.1` | Same |
| Elevation | True | True |
| Portable suite | 562 passed, 1 live test deselected | 562 passed, 1 live test deselected |
| Wheel build, fresh installation and dependency check | Passed | Passed |
| Isolated installed validator, all three synthetic samples | Passed (0/13/11 findings; exits 0/0/3) | Passed (same expectations) |
| Original live snapshot/serialization smoke | 1 passed | 1 passed |

The original smoke requires system/process evidence and seven collector records but permits partial/failed sources. A passing result alone does not establish complete collection coverage.

Follow-up changes add a second live test covering all four commands from the installed wheel, matching snapshot/report evidence, exact partial exit behavior, refused writes, deterministic explicit report replacement, and all four investigation files. CI uses isolated Python with pytest's importlib mode to prevent checkout imports. Endpoint output remains captured; only typed enum/count coverage summaries are printed. Pytest's short failure summary could expose evidence even with traceback/capture disabled; `-rN --disable-warnings` now suppresses it. A synthetic CI-mode failure confirmed the secret sentinel and warning text remain absent while pytest still exits nonzero.

The [expanded live run](https://github.com/christophervalle85/IRSnapshot/actions/runs/38107279643) at `d338cbc` and [privacy-corrected repeat](https://github.com/christophervalle85/IRSnapshot/actions/runs/38107394086) at `904361f` each passed 562 portable cases and 2 installed-wheel live tests on both Python versions. Both `collect` and `run` returned the expected partial exit 3. The collection summaries revealed important limits: four process-access denials, two unavailable account sources, and scheduled-task timeouts on some runners with corresponding partial persistence coverage. System, network and services succeeded throughout these reported captures. Passing workflow/serialization assertions did not imply complete source coverage.

A [targeted read-only diagnostic](https://github.com/christophervalle85/IRSnapshot/actions/runs/38107827268) retained only counts, runtime exception types and durations. The account failures were `System.IO.FileNotFoundException` for both LocalAccounts imports, unchanged by the tested environment additions. The task query completed with 209 items and no issues in 15.3 seconds in its warmed diagnostic session; this does not erase earlier 30-second timeouts. A module-discovery regression and correction are being validated separately.

After those test changes, macOS Python 3.12.14 and 3.14.7 each passed 562 portable cases with 2 live tests deselected. Both dependency checks passed. This is test-tooling validation, not another native platform result.

At this stage, Windows 10/11 x64 desktop sessions were unverified. The local Windows VM was ARM64, outside the declared contract. Historical 0.5.0 release artifacts remain preserved. Earlier dated sections below describe their historical state and are superseded by this execution record where applicable.

## Milestone 6 follow-up — 2026-10-06

The unchanged application and validation tools were checked again on macOS ARM64: Python 3.12.14 passed all 562 portable cases, with one live Windows test deselected. The clean installed-wheel validator again passed the benign/review/partial walkthroughs with expected findings 0/13/11 and exits 0/0/3. No live endpoint collection was performed.

After the documentation updates, a new local verification wheel was built and installed offline into another fresh Python 3.12 environment. Its isolated validation ran from outside the checkout and passed all three samples; dependency integrity passed. All 41 Python/template files and the updated README metadata matched the source. This was a verification build, not a new published release.

Report presentation follow-ups are tracked in repository issues.

At this stage, M6 validation was in progress and the version remained `0.5.0`. Later dated records supersede this status.

## Milestone 6 — validation tooling in progress

Work resumed on 2026-10-05 on macOS ARM64. The completed Milestone 5 ZIP and wheel were checked against their release source before starting this branch; all 83 tracked files and all 41 wheel Python/template files matched. The unchanged baseline passed 544 tests on Python 3.12.14, with the live Windows test deselected.

Milestone 6 adds a Windows CI matrix, a reusable installed-wheel validator, and a [release checklist](release-validation.md). These are validation tools, not a new application release: the version remains `0.5.0`, and the original Milestone 5 artifacts are preserved.

| Check | Result |
|---|---|
| Validator regression cases | 18 passed |
| Full portable suite, Python 3.12.14 | 562 passed, 1 live test deselected |
| Full portable suite, Python 3.14.7 | 562 passed, 1 live test deselected |
| Package, tests, scripts, and examples compile | Passed |
| Dependency checks, Python 3.12/3.14 and new clean installation | No broken requirements |
| New wheel built and installed offline into fresh Python 3.12 environment | Passed |
| Installed validation from outside the checkout with isolated Python | Passed; console/module help and version, template, all three samples, JSON/HTML and orchestration |
| Synthetic expected findings/exits | Benign 0/0, review 13/0, partial 11/3 |
| Refused writes and deterministic explicit overwrites | Passed for reports and synthetic investigation output |
| Wheel content | All 41 package/template files and updated README metadata verified |
| Workflow YAML syntax | Parsed successfully; workflow execution and PowerShell commands not run on this host |

New tests demonstrate rejection of source/editable imports, including editable metadata outside the named checkout; unexpected subprocess exits; UTF-8 output and import-environment isolation; expected partial exits; and rejection of active HTML, external resources, duplicate IDs, or broken anchors. Validation remains active with Python optimization. Sample verification preserves input bytes and compares saved snapshot/JSON/HTML outputs with the installed orchestration path. The collection boundary alone is substituted with synthetic evidence.

An import-isolation check showed that the documented desktop module commands could import the source checkout instead of the fresh wheel. All four commands now use `-I`. A targeted check from the checkout reproduced the original source import, then confirmed the corrected invocation imports the clean environment's `site-packages`. This documentation correction does not constitute native Windows execution.

This section records the validation-tooling stage before native Windows execution and release finalization.

Windows workflow execution and Windows 10/11 desktop checks had not yet been performed at this stage. Hosted Windows runners use administrator context, which is recorded separately from desktop privilege validation.

## Milestone 5 — release 0.5.0

Verified on 2026-10-02 on macOS (ARM64). These checks cover offline reporting and orchestration with injected Windows boundaries. **Actual Windows collection and live `run` remain unverified.**

| Check | Result |
|---|---|
| Full portable suite, Python 3.12.14 | 544 passed, 1 live test deselected |
| Full portable suite, Python 3.14.7 | 544 passed, 1 live test deselected |
| Focused cleanup and workflow CLI regression suite | 67 passed |
| Package, test, and example compilation | Passed |
| Dependency integrity, both development environments and clean install | No broken requirements |
| Whitespace/error diff check | Passed |
| Wheel build | `irsnapshot-0.5.0-py3-none-any.whl` built successfully |
| Clean offline wheel installation | Imported from a fresh environment's `site-packages`, outside the source tree |
| Installed version/help and all four command help pages | Passed |
| Installed sample analysis and HTML | Benign/review/partial: 0/13/11 findings; exit 0/0/3 |
| Installed workflow with injected collection | Snapshot, JSON, HTML and log produced for all three samples; outputs match standalone reporting |
| Packaged template | Read and rendered from the installed wheel |
| Release archive/source comparison | All 83 tracked source files and 41 wheel Python/template files match the checkout |
| Output safety | Refused writes preserve bytes; explicit overwrites deterministic; input same-path/symlink/hardlink aliases rejected |
| Non-Windows collect/run | Actionable exit 1; existing evidence/reports preserved, including explicit overwrite |
| Browser inspection | Review/partial reports checked; coverage, navigation, expandable evidence and IPv6 presentation inspected |
| Responsive report | 1280px and 390px checked; compact columns readable, tables scroll internally, no page overflow |
| Live Windows investigation | Not run; Windows x64 host required |

New cases exercise escaped HTML and issue text, safe static anchors, visible partial coverage, severity ordering, missing tree/ownership associations, 1,300-level iterative ancestry, invalid mutable reports, bounded atomic HTML publication, all four CLI commands, and input alias protection. The end-to-end collection test now carries all seven actual collectors through analysis and both report writers with only the typed Windows adapter replaced.

Workflow tests inject failures at analysis, JSON publication, and HTML publication, including keyboard interruption, and then reload the saved snapshot. Overwrite tests preserve unrelated files and earlier evidence until replacement publication succeeds. Logging tests exercise hard-link replacement, opening/write failures, escaped chained diagnostics, handler restoration, and source failures inside the actual collection pipeline.

A stale-output cleanup regression showed that an error removing the old JSON report prevented removal of the old HTML report. Cleanup now attempts both files before surfacing the error, and regression tests cover refusal of either removal while preserving the new snapshot and unrelated files.

One regression exposed a subtle publication boundary: the snapshot writer can finish publishing before its diagnostic log write fails. Logging errors now latch and surface at controlled workflow boundaries, allowing the workflow to record the saved snapshot and clear stale derived outputs before stopping. A separate integration check ensures collector isolation cannot hide a failed log as an ordinary partial success.

The HTML is self-contained, with inline CSS and no scripts or external resources. Parser checks verify safe tags, local anchor targets and unique IDs; browser inspection verified navigation and expandable raw evidence. Print styles are included; report presentation follow-ups are tracked in repository issues. Dependency versions remain those recorded for Milestone 3 below. Historical sample capture versions are unchanged.

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
| Wheel build | `irsnapshot-0.4.0-py3-none-any.whl` built successfully |
| Clean wheel installation | Installed offline in a new Python 3.12 environment |
| Installed help/version and both command help pages | Passed outside source tree |
| Installed sample analysis | 0/13/11 findings and exit 0/0/3 for benign/review/partial samples |
| Installed collect on macOS | Actionable Windows-only rejection, exit 1, no snapshot created |
| Existing output protection | Refusal and unsupported-platform failures preserve existing bytes, including with overwrite requested |
| Actual Windows read-only smoke | Not run; requires a Windows x64 host |

New cases exercise typed PowerShell envelopes and zero/one/many results, UTF-8 and malformed output, timeouts/nonzero exits, fixed script routing, data-only shortcut inputs, explicit registry views and shared duplicates, native discovery failures, remote/reparse path rejection, owner SID uncertainty, malformed nested task data, partial field and iteration failures, source projections, collector isolation, and CLI status/identity rendering. Reproducing regressions preceded corrections.

A logging regression showed that default traceback logging could expose terminal controls from a source exception. The repair retains readable chained diagnostics while escaping those controls before logging; its CLI regression verifies visible escapes, preserved traceback context, and a saved partial snapshot.

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
| Wheel build | `irsnapshot-0.3.0-py3-none-any.whl` built successfully |
| Clean wheel installation | Installed offline into a new Python 3.12 environment |
| Installed package outside source tree | CLI help/version/analyze and JSON validation passed |
| Installed benign sample | 0 findings, exit 0 |
| Installed review sample | 13 findings, exit 0 |
| Installed partial sample | 11 findings, exit 3; evaluation complete, collection incomplete |

The clean environment imported from `site-packages`, not the repository or an editable install. Package metadata and the installed console entry point reported `0.3.0`. Real subprocess checks validated every sample's JSON against `InvestigationReport`, preserved its original snapshot, and confirmed ruleset `1.0.0`. Refused writes preserved existing reports; explicit overwrites reproduced identical report bytes. Selecting the input as output was rejected even with overwrite enabled, and unsupported snapshot versions returned exit 2.

The 407 cases retain the foundation and interpretation coverage below and add process/persistence predicates, rule-failure isolation, deterministic findings, console/JSON reports, and real CLI behavior. Tests cover both positive and near-miss evidence, unsupported grammar, disabled and multi-action tasks, owner-scoped paths, malformed rule outputs, mutation isolation, duplicate evidence, missing system data, literal terminal rendering, file publication failures, and input aliases.

Regression cases exposed a missing canonical rundll32 form, a certutil URL mistaken for an unrelated option's value, malformed URLs raising rule errors, non-exec task fields being promoted into findings, and escaped quotes exposing an unsupported script target. Each fix has a regression that failed before correction. No fixture command was executed.

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

Tests were run before the corresponding implementations and failed as expected. Regression cases exposed four interpretation defects (unsupported colons, growing variable cycles, cross-category UUID collisions, and order-dependent root ties) and one example defect (absent system information). Each received a failing regression before correction. Additional regressions cover modern PowerShell working-directory and version prefixes. All 247 cases passed on both recorded Python versions.

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

Foundation regressions covered unknown system fields without issues, numeric-string timestamp coercion, and an unnormalized JSON integer error. Reproducing regressions preceded the fixes.

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

Hosted Windows execution is now recorded above, including native publication, installation and live collection. Windows 10/11 desktop privilege contexts remain unverified. Hard-link publication is intentionally unsupported on filesystems that do not provide it. A hosted Server smoke result is not evidence that every source or field is available on a desktop endpoint.

Tests use synthetic inputs; no suspicious fixture is executed. JSON Schema documents types and field constraints, but Python validators also enforce semantic and cross-record constraints. Validating a file with a generic JSON Schema checker alone is not equivalent to `load_snapshot`.
