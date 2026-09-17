# IRSnapshot

A Windows endpoint incident-response and triage CLI in Python. The planned v1 collects a point-in-time snapshot, applies transparent deterministic rules, and produces analyst-friendly reports. It is not an EDR, antivirus, or background agent.

**Current release: 0.1.0 — Milestone 1, typed foundation.**

Implemented:

- Pydantic evidence, collection-coverage, findings, and report models.
- Strict validation, aware UTC timestamps, UUID references, and JSON serialization.
- Validated snapshot loading and atomic file writing with overwrite protection.
- Working `irsnapshot --help`, `irsnapshot --version`, and `python -m irsnapshot`.
- A clearly labelled synthetic snapshot, JSON Schema, and fixture-based tests.

Collection, detection rules, process-tree construction, correlation, and HTML reporting are later milestones. The `collect`, `analyze`, `report`, and `run` commands do not exist yet. There are no placeholder commands that report success.

## Install and verify on Windows

Install Python 3.12 or newer (64-bit). From the extracted IRSnapshot repository folder, use PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\irsnapshot.exe --version
.\.venv\Scripts\irsnapshot.exe --help
.\.venv\Scripts\python.exe -m irsnapshot --version
```

Use your installed Python version in place of `-3.12` if needed. Activation is unnecessary. Version output is `IRSnapshot 0.1.0`. Bare `irsnapshot` displays help and succeeds. Unknown commands exit with status 2.

Milestone 1 is portable code for development and fixture validation. The product's planned endpoint-collection support remains Windows only. No Windows integration behavior has been validated by a macOS test run; see [testing evidence](docs/testing.md).

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

All seven collectors require a `CollectorRun` record describing scope, count, status, and structured issues. Partial data can be represented without pretending an inaccessible source was empty. Findings and investigation-report models are defined now so later milestones can depend on stable interfaces; no detection engine is implemented in this release.

- [Data model and invariants](docs/data-model.md)
- [Machine-readable snapshot JSON Schema](docs/snapshot.schema.json)
- [Accepted v1 design and milestone sequence](docs/architecture.md)
- [Verification evidence and limitations](docs/testing.md)
- [Synthetic sample provenance](samples/README.md)

## Development

Runtime dependencies are Typer, Rich, Pydantic, psutil, and Jinja2. pytest is the development test dependency. Endpoint APIs are not imported by the current models, storage, or CLI.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_models.py tests/test_storage.py tests/test_cli.py -q
.\.venv\Scripts\python.exe -m pip wheel --no-deps --wheel-dir dist .
```

For fixture development on the current macOS host, create a virtual environment with `python3 -m venv .venv`, then use `.venv/bin/python` and `.venv/bin/irsnapshot` instead of Windows paths.

Models are mutable for straightforward collector construction. Mutating a nested list or assigning a field is not an automatic validation boundary; revalidate before consumption. `write_snapshot` revalidates the full object, including nested models, before serialization. Collection-time values must remain distinct from event times: an unknown process start or task execution time is never inferred from an observation timestamp.

No credentials, personal endpoint records, or malicious commands are needed to run this milestone's tests. Synthetic paths and usernames in fixtures are example data, not collection defaults.
