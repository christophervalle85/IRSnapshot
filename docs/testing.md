# Milestone 1 verification

Verified on 2026-09-17, on macOS 26.5.2 (ARM64). This verifies portable foundation code; it is not evidence of Windows integration readiness.

| Check | Result |
|---|---|
| Full pytest suite, Python 3.12.14 | 94 passed |
| Full pytest suite, Python 3.14.7 | 94 passed |
| Model and severity contracts | 66 test cases |
| Real-file storage behavior | 20 test cases |
| Typer CLI and module entry point | 8 test cases |
| Dependency integrity (`pip check`) | No broken requirements |
| Package compilation | Passed |
| Wheel build | `irsnapshot-0.1.0-py3-none-any.whl` built successfully |
| Clean wheel installation | Installed offline into a new Python 3.12 environment |
| Installed package outside source tree | CLI help/version/usage and snapshot read/write round trip passed |

The installed package was verified to come from the clean environment's `site-packages`, not the repository or an editable-install path. Package metadata agreed with the CLI version. The sample read/write check preserved the validated model and did not import Windows-only APIs.

Tested dependency versions: Pydantic 2.13.5, Typer 0.27.2, Rich 14.3.4, psutil 7.2.2, Jinja2 3.1.6, and pytest 9.1.1. The declared compatible ranges are in `pyproject.toml`; this record describes the versions actually exercised, not every possible resolution.

## What the tests establish

- Valid snapshots survive JSON round trips, including UUIDs, Unicode, null values, and timezone offsets.
- Naive timestamps, numeric epoch strings, negative/coerced PIDs, invalid ports, wrong address families, and unexpected fields are rejected.
- Duplicate artifacts, mismatched coverage counts, unsupported schema versions, and dangling persistence/report references are rejected.
- Failed/skipped system collection can be represented explicitly; absent system fields cannot masquerade as successful collection without matching issues.
- Invalid input produces `SnapshotValidationError` without echoing raw evidence values in its message, including JSON parser integer-limit failures.
- Existing files survive refused writes; eight concurrent writers publish exactly one complete file.
- Simulated publication and sync failures preserve existing destinations and clean temporary files.
- Mutated invalid models are rejected before publication. File size limits and symlink no-clobber behavior are exercised.
- Help/version work through both Typer's test runner and actual Python subprocesses; nonexistent collection commands return a usage error.

The initial model and storage test groups were run before their production modules existed and failed as expected. An independent code review subsequently found three validation gaps: unknown system fields without issues, numeric-string timestamp coercion, and an unnormalized JSON integer error. Regression tests reproduced those failures before corrections; the final suite includes the fixes.

## Reproduce on Windows

From the extracted repository root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\irsnapshot.exe --version
.\.venv\Scripts\irsnapshot.exe --help
.\.venv\Scripts\python.exe -m pip wheel --no-deps --wheel-dir dist .
```

The suite has 94 cases. A Windows account without permission to create symbolic links may skip the single symlink test; inspect the test summary rather than assuming a zero-skip result. The [README](../README.md) includes an executable sample load/write command.

## Remaining validation limits

No Windows host was available for this milestone. Windows installation, NTFS publication semantics, path permissions, and runtime behavior still require a Windows run. Hard-link publication is intentionally unsupported on filesystems that do not provide it. No endpoint collectors, behavioral detections, live integration tests, or report rendering exist yet.

Tests use synthetic inputs; no suspicious fixture is executed. JSON Schema documents types and field constraints, but Python validators also enforce semantic and cross-record constraints. Validating a file with a generic JSON Schema checker alone is not equivalent to `load_snapshot`.
