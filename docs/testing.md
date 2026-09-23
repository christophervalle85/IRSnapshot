# Verification evidence

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
.\.venv\Scripts\python.exe examples/interpret_snapshot.py samples/benign.snapshot.json
.\.venv\Scripts\python.exe -m pip wheel --no-deps --wheel-dir dist .
```

The review sample should produce thirteen findings and exit 0; the partial sample should produce eleven and exit 3. A Windows account without permission to create symbolic links may skip alias tests; inspect the test summary rather than assuming a zero-skip result. The [README](../README.md) includes the Milestone 3 subset command and a sample storage round trip. The output file must not already exist unless you explicitly add `--overwrite`.

## Remaining validation limits

No Windows host was available for this milestone. Windows installation, NTFS publication semantics, path permissions, and actual PowerShell host behavior still require Windows execution. Hard-link publication is intentionally unsupported on filesystems that do not provide it. Endpoint collectors, live integration tests, and HTML reports remain unimplemented. The current portable scope includes deterministic rules, console/JSON investigation reports, and the offline demonstration.

Tests use synthetic inputs; no suspicious fixture is executed. JSON Schema documents types and field constraints, but Python validators also enforce semantic and cross-record constraints. Validating a file with a generic JSON Schema checker alone is not equivalent to `load_snapshot`.
