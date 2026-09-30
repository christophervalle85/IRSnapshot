# Windows collection

`irsnapshot collect --output snapshot.json` reads the local Windows endpoint once and saves the existing versioned `SystemSnapshot`. It does not analyze the snapshot automatically. Use `irsnapshot analyze snapshot.json` afterward; saved evidence survives a later analysis failure.

The target baseline is Windows 10/11 x64 with 64-bit Python 3.12+ and Windows PowerShell 5.1. Other live platforms and unsupported architectures are rejected before collection. Windows Server behavior is best effort until exercised. Importing the package and offline analysis do not require Windows APIs.

## What is collected

| Source | Evidence and declared scope | Important limits |
|---|---|---|
| System | Host/version/architecture, endpoint time and boot time, collecting identity/SID/elevation, captured path roots | Unavailable fields have explicit issues; elevation is recorded, never requested |
| Processes | PID/PPID, name, executable, argument list, username, creation time | Denied fields remain null; disappearing processes can retain their other readable fields |
| Network | Local IPv4/IPv6 TCP/UDP endpoints, remote endpoint when available, TCP state and reported owner PID | No packet capture or historical connections; UDP has no fabricated TCP state |
| Users | Current token, logged-in sessions, local accounts, direct built-in Administrators members | Separate provenance; membership may be a group or domain principal; no recursive expansion |
| Services | Service name/display name, state, raw command, startup type, account and PID | Configured command is evidence, not proof of execution or successful executable resolution |
| Scheduled tasks | Namespace/name, state/enabled flag/principal, every projected action and trigger | COM/other actions remain inventory; raw schedule boundaries are not execution timestamps |
| Persistence | Current identity's HKCU and machine HKLM Run values, current/common Startup files, task/service projections | No offline hive loading or other users' HKCU; task/service source records are reused |

The inventory spans an interval rather than an atomic point in time. The collector and its inventory subprocesses may appear in evidence. Parent/owner associations remain subject to races and PID reuse; the analysis layer preserves uncertainty.

Process and service fields use per-field error handling. A denied executable path does not discard a readable PID, name, or command line. Missing observations and malformed source data produce issues rather than guessed values. A failed collector does not stop the remaining collectors. Each snapshot records exactly seven collector runs, including failed/skipped sources.

## Identity, paths, registry views, and shortcuts

HKCU and per-user Startup mean the identity running IRSnapshot. An elevated process launched with different credentials may therefore collect a different user's scope. Current-token observations are separate from interactive sessions. Administrator membership uses the built-in SID `S-1-5-32-544`, avoiding a dependency on the group's display language. [Microsoft documents the SID parameter and the 64-bit host requirement](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localgroupmember?view=powershell-5.1).

Run keys are queried with explicit 32-bit and 64-bit access flags, without manufacturing `Wow6432Node` paths. Exact identical observations from shared views are deduplicated with shared-view provenance; differing values remain separate. Missing keys are ordinary empty results. Access-denied keys are coverage failures. Non-string registry values retain their type and are not converted into executable command strings. [Microsoft registry-view guidance](https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view) explains why both views must be queried explicitly.

Captured native known-folder roots and a limited set of path environment values travel with the snapshot. Offline analysis uses this captured context; it never substitutes the analyst machine's environment. Paths describe locations, not ACLs or trust. Unavailable owner SIDs remain unknown rather than being inferred from a username.

Startup files remain inventory even when shortcut metadata is unavailable. Shortcut resolution reads metadata only; it does not launch the target. Target paths and arguments are evidence, not a request to execute them. Missing targets remain unresolved.

Service and Run commands retain their original source strings. Task and shortcut targets/arguments arrive as separate fields; any combined persistence command is a labelled reconstruction for display. Source task records and action indices preserve the original structure, so the analysis does not have to infer it from that reconstruction.

## PowerShell boundary

Queries use fixed source text and the trusted system Windows PowerShell executable. Invocation uses an argument vector with no shell, profiles, or interactive prompts. Collection does not alter execution policy, request elevation, download modules, or deliberately query remote endpoints. Windows account-name resolution can consult domain infrastructure internally, so live collection is not an air-gap guarantee. Shortcut paths cross the boundary as JSON input data, not interpolated PowerShell source.

Responses are projected into explicit JSON envelopes and validated into typed adapter records. Arrays preserve zero, one, and multiple results. UTF-8 handling preserves Unicode. Timeouts, nonzero process exits, malformed JSON, and invalid response shapes become visible collection failures. When a query can retain successful sub-scopes, their records remain available alongside issues.

PowerShell queries default to a 30-second timeout and reject captured stdout larger than 32 MiB before parsing. Output is buffered before this size check, so it is not a streaming memory bound. Native Windows calls have no separate timeout; operating-system stalls can delay collection. Local-drive and reparse checks reduce unintended traversal but cannot eliminate filesystem races between checking and reading a path.

Task schedules retain their raw boundaries. An offsetless date stays raw with no normalized timestamp; the collector never assigns the local timezone by guess. Task definitions come from the local [Get-ScheduledTask inventory](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask?view=windowsserver2025-ps).

## Save behavior and exit codes

The output directory must already exist. Existing destinations are refused unless `--overwrite` is explicit. Publication uses the established validated temporary-file/no-clobber storage boundary. A platform failure does not create a snapshot. A completed attempt with source failures still saves the usable snapshot and reports incomplete coverage.

| Exit | Meaning |
|---|---|
| 0 | Snapshot saved; all declared collection scopes succeeded |
| 1 | Unsupported platform, fatal runtime failure, or output I/O failure |
| 2 | Invalid command-line usage |
| 3 | Snapshot saved with partial, failed, or skipped collection |
| 130 | Interrupted |

An `ok` run means the declared scope was queried successfully, not that the endpoint inventory is exhaustive. Coverage issues are separate from findings and severity. Snapshot contents can include sensitive command arguments and identity data; review the actual content before sharing it.

## Verification on Windows

From the installed source checkout in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_windows_adapters.py tests/test_collectors.py tests/test_collection_pipeline.py tests/test_collect_cli.py -q
.\.venv\Scripts\python.exe -m pytest tests/test_windows_smoke.py -m windows_live -q
.\.venv\Scripts\irsnapshot.exe collect --output snapshot.json
$LASTEXITCODE
.\.venv\Scripts\irsnapshot.exe analyze snapshot.json --output analysis.json
```

Ordinary test runs exclude live collection. The explicitly selected smoke test validates evidence contracts and coverage rather than expecting fixed process counts or universal permissions. Run from a normal account first; elevated collection is optional and should be recorded separately. An incomplete result can be expected when permissions or Windows components restrict visibility; inspect the actual issues.

The current macOS development host can exercise injected native/transport boundaries and all pure normalizers. It cannot establish actual Windows PowerShell, COM, registry, permissions, or NTFS behavior. See the [verification record](testing.md) for actual results. No Windows-ready or live-integration claim follows from portable fixture tests.
