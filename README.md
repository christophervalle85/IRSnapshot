# IRSnapshot

A Windows endpoint incident-response and triage CLI in Python. It collects a point-in-time snapshot, applies transparent deterministic rules, and produces analyst-friendly reports. It is not an EDR, antivirus, or background agent.

**Current release: 0.5.0 — Milestone 5, full investigation and standalone HTML reporting.**

Milestone 6 has passing Windows Server CI on Python 3.12 and 3.15, including clean installation and live collection. Windows 10/11 desktop sessions and printed report appearance remain release gates. See the [release checklist](docs/release-validation.md) and [résumé assessment](docs/portfolio.md).

I included a [portfolio demonstration](portfolio-demo/README.md) with ready-to-open synthetic HTML reports, original snapshots, and my project walkthrough. I also included a [downloadable demo ZIP](portfolio-demo.zip). I can present it on a Mac or Windows computer without installing Python.

Implemented:

- Pydantic evidence, collection-coverage, findings, and report models.
- Strict validation, aware UTC timestamps, UUID references, and JSON serialization.
- Validated snapshot loading and atomic file writing with overwrite protection.
- Working `irsnapshot --help`, `irsnapshot --version`, and `python -m irsnapshot`.
- A clearly labelled synthetic snapshot, JSON Schema, and fixture-based tests.
- Deterministic process trees with missing-parent, time-conflict, and cycle handling.
- Conservative Windows path and PowerShell command interpretation with explicit uncertainty.
- Network ownership associations, finding context, and a factual UTC timeline.
- Literal-text Rich process-tree rendering and a read-only offline demonstration.
- Thirteen documented process and persistence rules with fixed severities and source evidence.
- Reproducible finding IDs, rule-failure isolation, and separate collection/analysis status.
- A working `analyze` command with console output and atomic JSON report saving.
- Windows collectors for system, processes, network, users, services, scheduled tasks, and persistence.
- Typed Windows adapters, fixed PowerShell queries, and a collection pipeline that records source failures.
- A working `collect` command with explicit coverage and overwrite protection.
- A standalone HTML report with prioritized findings, evidence, coverage, process ancestry, network ownership, persistence, and a UTC timeline.
- A working `report` command for saved snapshots and `run` for a complete investigation folder.
- Snapshot-first orchestration and a local diagnostic log that preserve evidence when a downstream stage fails.

Collection requires Windows; saved snapshots and the synthetic samples can be analyzed and rendered offline. HTML reports contain their own styles and use no JavaScript or external assets. Hosted Windows Server administrator collection has passed; Windows 10/11 desktop coverage is still pending. See the [verification record](docs/testing.md).

## Install and verify on Windows

Install Python 3.12 or newer (64-bit). From the extracted IRSnapshot repository folder, use PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\irsnapshot.exe --version
.\.venv\Scripts\irsnapshot.exe --help
.\.venv\Scripts\python.exe -m irsnapshot --version
.\.venv\Scripts\irsnapshot.exe analyze --help
```

Use your installed Python version in place of `-3.12` if needed. Activation is unnecessary. Version output is `IRSnapshot 0.5.0`. Bare `irsnapshot` displays help and succeeds. Unknown commands exit with status 2.

The current code is portable for development and offline fixture interpretation. Endpoint collection targets Windows 10/11 x64, 64-bit Python, and Windows PowerShell 5.1. No Windows integration behavior has been validated by a macOS test run; see [testing evidence](docs/testing.md).

## Collect on Windows

From the extracted repository after installation:

```powershell
.\.venv\Scripts\irsnapshot.exe collect --output snapshot.json
$LASTEXITCODE
.\.venv\Scripts\irsnapshot.exe analyze snapshot.json --output analysis.json
```

Collection runs once and saves a validated snapshot before any separate analysis. Access-denied fields and failed sources are recorded alongside available evidence. Exit **3** means the snapshot was saved with incomplete collection; review the coverage and issues. Elevation is optional and is never requested automatically. Running under another identity changes the current-user registry and Startup scope.

An existing destination is refused; use `--overwrite` only when you intend to replace it. Snapshot contents may include usernames, paths, command-line arguments, addresses, and configured startup commands. Collection is read-only, but the saved evidence can be sensitive. [Collection details](docs/collection.md) describe source scope and limitations.

## Generate a report or complete investigation

Create an offline HTML report from the included synthetic sample:

```powershell
.\.venv\Scripts\irsnapshot.exe report samples/review.snapshot.json --output review.html
```

Open `review.html` in a browser. The report analyzes the saved snapshot using the bundled ruleset; it does not collect new evidence. All thirteen sample findings retain their original evidence. For a partial-coverage example, use `samples/partial.snapshot.json`; the report is still written and the command exits **3**.

On a Windows endpoint, collect and report in one command:

```powershell
.\.venv\Scripts\irsnapshot.exe run --output investigation/
$LASTEXITCODE
```

The folder contains `snapshot.json`, `analysis.json`, `report.html`, and `irsnapshot.log`. Use a new or empty folder. The snapshot is saved before analysis so later failures leave collected evidence available for retry. Explicit `--overwrite` replaces the known output files, preserves unrelated files, and removes stale derived reports only after the new snapshot is saved. See the [reporting and recovery guide](docs/reporting.md) for output safety, log behavior, and exact recovery commands.

## Analyze the included samples

From the extracted repository after installation:

```powershell
.\.venv\Scripts\irsnapshot.exe analyze samples/benign.snapshot.json
.\.venv\Scripts\irsnapshot.exe analyze samples/review.snapshot.json --output analysis.json
.\.venv\Scripts\irsnapshot.exe analyze samples/partial.snapshot.json
$LASTEXITCODE
```

The benign sample produces zero findings. The review sample exercises all 13 rules, with one finding per rule, including a disabled task with two matching actions. The partial sample retains 11 findings while exposing failed system/network collection and an unreadable PowerShell command line; its exit code is **3**. These are invented walkthroughs, not endpoint captures or malware verdicts. Nothing in a captured command is executed.

Console output includes collection coverage, analysis status, prioritized findings, original evidence, process context, network associations, and a factual UTC timeline. `analysis.json` is a validated `InvestigationReport` containing both the original snapshot and derived analysis. IDs and ordering are reproducible for the same snapshot and ruleset. A failed rule produces an explicit issue and incomplete analysis while other rules continue.

Existing output files are refused by default. To replace a previously generated report, rerun with `--overwrite`. The input snapshot is protected from being selected as the output, including through an existing alias. JSON reports retain sensitive evidence such as command lines and usernames; choose where to store or share them accordingly.

| Exit | Meaning |
|---|---|
| `0` | Requested operation finished with complete collection/analysis; findings alone do not fail the command |
| `1` | I/O, unsupported live platform, or fatal runtime failure |
| `2` | Invalid arguments, unsupported schema, or invalid snapshot |
| `3` | Output produced with incomplete analysis or partial/failed/skipped collection |
| `130` | Interrupted |

[Rule reference](docs/rules.md) documents exact matching boundaries and benign explanations. [Limitations](docs/limitations.md) explains what the snapshot and rules cannot establish.

## Exercise the interpretation APIs

After installing from the extracted repository, run:

```powershell
.\.venv\Scripts\python.exe examples/interpret_snapshot.py samples/benign.snapshot.json
```

This reads the synthetic sample and prints collection coverage, the process tree, command/path facts, network ownership associations, service command targets, and the timeline. It creates no files and executes no captured command. The sample shows `explorer.exe` (PID 400) with a missing parent, one `pid_match` network association, and four timeline events. The original sample still declares its capture tool version, `0.1.0`; the snapshot schema remains `1.0`.

An unknown field stays unknown. A PID association does not prove historical ownership, a path category does not establish write permissions or trust, and a command option is not a malware verdict. [Interpretation contracts](docs/interpretation.md) explain the supported syntax and limits.

The example exits 0 after displaying a valid snapshot, including snapshots with partial collection (statuses remain visible); read or validation errors exit 2. This source-tree example demonstrates interpretation without detection rules and requires the ZIP/source checkout, not just the wheel. Use `irsnapshot analyze` for rule evaluation and the exit behavior above.

## Exercise the snapshot API

This reads synthetic evidence and writes a new validated copy. It does not inspect your endpoint.

```powershell
.\.venv\Scripts\python.exe -c "from pathlib import Path; from irsnapshot.storage import load_snapshot, write_snapshot; s = load_snapshot(Path('samples/benign.snapshot.json')); print(s.system.hostname, len(s.processes)); write_snapshot(s, Path('snapshot-copy.json'))"
```

Expected output: `EXAMPLE-LAB 1`. The new `snapshot-copy.json` is UTF-8 JSON. Running this a second time raises `FileExistsError` and preserves the first copy. An API caller can explicitly request replacement using `write_snapshot(snapshot, path, overwrite=True)`.

The storage API distinguishes invalid evidence (`SnapshotValidationError`) from filesystem failures (`OSError` subclasses). Invalid in-memory models raise Pydantic `ValidationError` before any file is published. Input files must explicitly declare `schema_version: "1.0"`; duplicate JSON keys and unsupported schema versions are rejected.

Writes use a temporary sibling file, flush and sync its contents, then publish it atomically. New-file publication requires filesystem hard-link support; explicit overwrites use atomic replacement. Unsupported filesystems fail rather than fall back to a race-prone write. The destination directory must exist. Readers and writers enforce a 64 MiB snapshot limit. These properties do not constitute a forensic chain of custody or guarantee survival of a power loss.

## Model overview

`SystemSnapshot` holds `SystemInfo`, `ProcessArtifact`, `NetworkConnection`, `UserArtifact`, `ServiceArtifact`, `ScheduledTaskArtifact`, and `PersistenceArtifact` records. Every artifact has a UUID, observation time, and collector identity.

All seven collectors require a `CollectorRun` record describing scope, count, status, and structured issues. Partial data is represented without pretending an inaccessible source was empty. `AnalysisResult` records findings, relationships, event times, and evaluation issues; `InvestigationReport` binds it to its original snapshot. Both the snapshot and analysis schemas remain `1.0`; the bundled ruleset version is `1.0.0`.

- [Data model and invariants](docs/data-model.md)
- [Interpretation API and uncertainty handling](docs/interpretation.md)
- [Thirteen-rule reference](docs/rules.md)
- [Operational and interpretation limits](docs/limitations.md)
- [Windows collection sources and verification](docs/collection.md)
- [Standalone reports, investigation folders, and recovery](docs/reporting.md)
- [Machine-readable snapshot JSON Schema](docs/snapshot.schema.json)
- [Accepted v1 design and milestone sequence](docs/architecture.md)
- [Verification evidence and limitations](docs/testing.md)
- [Release validation and Windows desktop checklist](docs/release-validation.md)
- [Portfolio value, résumé wording, and completion assessment](docs/portfolio.md)
- [Synthetic sample provenance](samples/README.md)

## Development

Runtime dependencies are Typer, Rich, Pydantic, psutil, and Jinja2. pytest is the development test dependency. Offline interpretation and reporting do not access endpoint APIs, the network, or the analyst machine's environment. `collect` and `run` explicitly read the local Windows endpoint through its adapters.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_process_rules.py tests/test_persistence_rules.py tests/test_engine.py tests/test_reporting.py tests/test_cli.py tests/test_sample_analysis.py -q
.\.venv\Scripts\python.exe -m pytest tests/test_windows_adapters.py tests/test_collectors.py tests/test_collection_pipeline.py tests/test_collect_cli.py -q
.\.venv\Scripts\python.exe -m pytest tests/test_html_report.py tests/test_investigation.py tests/test_workflow_cli.py -q
.\.venv\Scripts\python.exe -m pip wheel --no-deps --wheel-dir dist .
```

For fixture development on the current macOS host, create a virtual environment with `python3 -m venv .venv`, then use `.venv/bin/python` and `.venv/bin/irsnapshot` instead of Windows paths.

Models are mutable for straightforward collector construction. Mutating a nested list or assigning a field is not an automatic validation boundary; revalidate before consumption. `write_snapshot` and the interpretation APIs revalidate their model inputs. Collection-time values remain distinct from event times: an unknown process start or task execution time is never inferred from an observation timestamp.

No credentials, personal endpoint records, or malicious commands are needed to run this milestone's tests. Synthetic paths and usernames in fixtures are example data, not collection defaults.
