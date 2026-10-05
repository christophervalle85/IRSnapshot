# IRSnapshot v1.0 — proposed architecture and milestone contract

Status: accepted design. Milestones 1–5 are implemented; Milestone 6 validation tooling is in progress and live Windows execution remains pending. See README and testing.md for current capabilities and verification.

## 1. Scope and recommended approach

IRSnapshot collects a bounded, point-in-time Windows triage snapshot, applies explainable deterministic rules, correlates evidence, and produces terminal, JSON, and standalone HTML reports. Collection spans an interval; it is not an atomic image of the endpoint. Observed behavior warrants review and is not a malware verdict.

Use Python 3.12+, Typer, Rich, Pydantic v2, psutil, Jinja2, and pytest. Standard-library modules cover registry access, subprocesses, Windows path syntax, identifiers, timestamps, logging, and file output. There is no runtime web access, service, remote agent, remediation, payload execution, or monitoring loop. No Linux or macOS collectors will be implemented. Pure analysis tests can run on the development host without implying support for those operating systems.

Recommended implementation: psutil for process/network/service data; winreg for Run keys and profile-path discovery; small standard-library Windows API adapters where needed; fixed, read-only PowerShell queries for users, scheduled tasks, and shortcut metadata. This balances readable portfolio code with native data sources.

Alternatives considered:

| Approach | Benefit | Cost | Decision |
|---|---|---|---|
| psutil + standard library + narrow PowerShell adapters | Small dependency set and independently testable collectors | Several transport formats to normalize | Recommended |
| PowerShell for nearly all collection | Consistent inventory transport | Larger JSON/process boundary and more subprocess dependence | Keep only where it improves reliability |
| Direct Win32/COM throughout | Detailed control | Much more interop code and testing than this v1 budget supports | Reserve for specific gaps |

Proposed release baseline: Windows 10/11 x64 with 64-bit Python and Windows PowerShell 5.1. Windows Server compatibility is best effort until exercised. Unsupported Python architecture fails with an actionable message. Collection works without elevation where permissions permit; elevation is optional, recorded, and never requested automatically.

## 2. Exact proposed repository structure

Every Python package directory shown includes an `__init__.py`. Templates live inside the installed package so wheel installations retain HTML reporting. This is a deliberate adjustment to the proposed root-level templates directory.

```text
IRSnapshot/
├── pyproject.toml
├── README.md
├── CHANGELOG.md
├── .gitignore
├── .github/
│   └── workflows/
│       └── tests.yml
├── irsnapshot/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── models.py
│   ├── severity.py
│   ├── pipeline.py
│   ├── investigation.py
│   ├── storage.py
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── system.py
│   │   ├── processes.py
│   │   ├── network.py
│   │   ├── users.py
│   │   ├── services.py
│   │   ├── scheduled_tasks.py
│   │   ├── persistence.py
│   │   └── windows.py
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── engine.py
│   │   ├── process_tree.py
│   │   ├── commands.py
│   │   ├── paths.py
│   │   ├── persistence.py
│   │   └── network.py
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── process_rules.py
│   │   └── persistence_rules.py
│   ├── correlation/
│   │   ├── __init__.py
│   │   ├── relationships.py
│   │   └── timeline.py
│   └── reporting/
│       ├── __init__.py
│       ├── console.py
│       ├── json_report.py
│       ├── html_report.py
│       └── templates/
│           └── report.html.j2
├── tests/
│   ├── conftest.py
│   ├── test_models.py
│   ├── test_storage.py
│   ├── test_process_tree.py
│   ├── test_paths.py
│   ├── test_commands.py
│   ├── test_process_rules.py
│   ├── test_persistence_rules.py
│   ├── test_correlation.py
│   ├── test_timeline.py
│   ├── test_collectors.py
│   ├── test_windows_adapters.py
│   ├── test_reporting.py
│   ├── test_cli.py
│   ├── test_windows_smoke.py
│   └── fixtures/
│       ├── users.json
│       ├── scheduled_tasks.json
│       └── shortcuts.json
├── samples/
│   ├── README.md
│   ├── benign.snapshot.json
│   ├── review.snapshot.json
│   └── partial.snapshot.json
└── docs/
    ├── architecture.md
    ├── data-model.md
    ├── collection.md
    ├── reporting.md
    ├── rules.md
    ├── testing.md
    └── limitations.md
```

`pipeline.py` coordinates collection; `investigation.py` coordinates snapshot-first analysis/report publication and scoped logging. Neither contains detection expressions or presentation logic. `storage.py` validates input and handles snapshot file output. `collectors/windows.py` owns the narrow platform adapters, PowerShell transport, and explicit response models. `analyzers/commands.py` and `paths.py` are pure parsing/classification helpers. `correlation/relationships.py` joins findings to already-built tree/network relationships.

Runtime dependencies are exactly the five requested libraries: Typer, Rich, Pydantic, psutil, Jinja2. Test/build dependencies include pytest and a standard packaging backend; there is no general plugin system, database, ORM, queue, or rules language.

## 3. Pydantic model contract

The tables below specify the data model to implement in the first milestone. `T?` means `T | None`, with a default of `None`. Collections use `list[T]` with independent empty defaults. Other fields are required unless a default is stated. No arbitrary `dict[str, Any]` crosses component boundaries. Dictionaries from external APIs are validated immediately into typed adapter responses.

### Shared types and invariants

- Base configuration rejects unknown fields (`extra="forbid"`). PIDs, ports, booleans, and string identifiers use strict validation so malformed input is not silently coerced. JSON UUID and ISO timestamp strings remain accepted by the JSON validation path.
- `Timestamp` is an aware datetime normalized to UTC. Naive datetimes fail validation; unknown timestamps remain null. Raw timestamps without a trustworthy offset are retained as strings where specified, not guessed.
- `ArtifactID`, `SnapshotID`, and `FindingID` are UUIDs serialized as strings. Artifact IDs are generated once during normalization, unique within a snapshot, and preserved during loading and analysis. PIDs alone are never artifact IDs.
- `PID` is an integer greater than or equal to zero; `Port` is an integer in 0–65535. PID 0 is a valid value, distinct from unavailable.
- `Severity` is `informational | low | medium | high | critical`, with an explicit ordering in `severity.py`. Initial rules do not assign critical severity.
- `CollectorName` is `system | processes | network | users | services | scheduled_tasks | persistence`.
- `CollectionStatus` is `ok | partial | failed | skipped`. `ok` means the declared scope was queried successfully, not that the machine has no unobserved evidence.
- Every artifact inherits `artifact_id: UUID`, `observed_at: Timestamp`, and `collector: CollectorName`.
- Windows paths are stored as strings and interpreted with Windows semantics (`PureWindowsPath`/`ntpath`), never resolved against the analysis machine's filesystem.
- Snapshot validators check duplicate artifact IDs, duplicate process PIDs, collector-status consistency, timestamp ordering, and internal persistence references. Analysis validators check finding references and relationship endpoints.

### Collected artifacts

| Model | Fields beyond the artifact base | Meaning |
|---|---|---|
| `SystemInfo` | `hostname: str?`, `windows_version: str?`, `architecture: str?`, `current_time: Timestamp?`, `boot_time: Timestamp?`, `collector_username: str?`, `collector_sid: str?`, `elevated: bool?` | Each unavailable system field has a corresponding collection issue. Current time is endpoint-observed time. |
| `ProcessArtifact` | `pid: PID`, `ppid: PID?`, `name: str?`, `executable: str?`, `command_line: list[str]?`, `username: str?`, `created_at: Timestamp?` | Null command line means unreadable; an empty list means it was read and empty. The collected argument list is authoritative; any joined display string is labelled reconstructed. |
| `NetworkEndpoint` | `address: str`, `port: Port` | Validated IPv4/IPv6 literal, preserving an IPv6 scope identifier when present. This helper is not an artifact. |
| `NetworkConnection` | `family: ipv4/ipv6`, `protocol: tcp/udp`, `local: NetworkEndpoint`, `remote: NetworkEndpoint?`, `state: str?`, `owning_pid: PID?` | No remote endpoint is expected for listeners and many UDP entries. UDP state is null, not a fabricated TCP status. |
| `UserArtifact` | `name: str`, `domain: str?`, `sid: str?`, `source: current_token/logged_in_session/local_account/local_admin_member`, `enabled: bool?`, `session_name: str?`, `logged_in_at: Timestamp?`, `member_of_sid: str?` | Separate observations retain provenance. Administrator members may be groups or domain principals; they are not all local user accounts. |
| `ServiceArtifact` | `name: str`, `display_name: str?`, `status: str?`, `command: str?`, `startup_type: str?`, `username: str?`, `pid: PID?` | Retains the complete service command; executable parsing is analysis, not evidence rewriting. |
| `TaskAction` | `kind: exec/com_handler/other`, `executable: str?`, `arguments: str?`, `working_directory: str?`, `class_id: str?` | One record per action; no execution or COM handler activation. Helper model, not an artifact. |
| `TaskTrigger` | `kind: str`, `enabled: bool?`, `start_boundary_raw: str?`, `end_boundary_raw: str?`, `start_at: Timestamp?`, `end_at: Timestamp?`, `user_id: str?`, `repetition_interval: str?` | Boundaries are schedules, not evidence that a task ran. Unknown trigger classes retain their type name. |
| `ScheduledTaskArtifact` | `name: str`, `task_path: str`, `state: str?`, `enabled: bool?`, `principal: str?`, `actions: list[TaskAction]`, `triggers: list[TaskTrigger]` | Captures all actions and obtainable trigger metadata; full namespace path identifies the task. |
| `PersistenceArtifact` | `kind: run_key/startup_folder/scheduled_task/service`, `location: str`, `entry_name: str`, `command: str?`, `target_path: str?`, `owner_sid: str?`, `registry_view: native/32/64?`, `registry_value_type: str?`, `enabled: bool?`, `source_artifact_id: UUID?`, `action_index: int?` | Run values and Startup files are collected directly. Service/task entries reference their source artifact; task entries identify their action. Unknown shortcut targets remain unknown. |
| `KnownPath` | `kind: profile/appdata/local_appdata/temp/startup/common_startup/windows`, `path: str`, `owner_sid: str?`, `source: str` | Typed helper describing endpoint-derived directory roots, with provenance. |
| `EnvironmentValue` | `name: str`, `value: str`, `owner_sid: str?` | Captures only path variables needed for interpretation; never dumps the full environment. |
| `PathContext` | `known_paths: list[KnownPath]`, `environment: list[EnvironmentValue]` | Travels with the snapshot so reanalysis does not consult the analyst host's environment. |

The artifact base applies to SystemInfo, ProcessArtifact, NetworkConnection, UserArtifact, ServiceArtifact, ScheduledTaskArtifact, and PersistenceArtifact. The other types in this table are nested helpers.

### Collection coverage and snapshot envelope

| Model | Fields |
|---|---|
| `CollectionIssue` | `collector: CollectorName`, `category: access_denied/disappeared/timeout/unavailable/parse_error/invalid_data/unexpected_error`, `message: str`, `observed_at: Timestamp`, `artifact_id: UUID?`, `target: str?`, `field: str?`, `exception_type: str?` |
| `CollectorRun` | `collector: CollectorName`, `status: CollectionStatus`, `started_at: Timestamp`, `finished_at: Timestamp`, `item_count: int >= 0`, `scope: list[str]`, `issues: list[CollectionIssue]` |
| `CollectorResult[T]` | `items: list[T]`, `run: CollectorRun` |
| `SystemSnapshot` | `schema_version: Literal["1.0"] = "1.0"`, `snapshot_id: UUID`, `tool_version: str`, `started_at: Timestamp`, `finished_at: Timestamp`, `system: SystemInfo?`, `processes: list[ProcessArtifact]`, `network: list[NetworkConnection]`, `users: list[UserArtifact]`, `services: list[ServiceArtifact]`, `scheduled_tasks: list[ScheduledTaskArtifact]`, `persistence: list[PersistenceArtifact]`, `path_context: PathContext`, `collector_runs: list[CollectorRun]` |

Every completed collection attempt records all seven collector runs, including failed/skipped ones. A successful empty query is `ok` with zero items. A partly unreadable process is retained alongside field-specific issues. A missing Run key or empty Startup directory is an ordinary empty result, not an exception-shaped failure. Failed queries cannot masquerade as empty successes.

### Findings and derived analysis

| Model | Fields |
|---|---|
| `EvidenceItem` | `artifact_id: UUID`, `field: str`, `value: str/int/float/bool/null/list[str]`, `explanation: str` |
| `Finding` | `finding_id: UUID`, `rule_id: str`, `title: str`, `severity: Severity`, `description: str`, `artifact_ids: list[UUID]`, `pids: list[PID]`, `evidence: list[EvidenceItem]`, `mitre_technique: str?` |
| `ProcessNode` | `process_id: UUID`, `parent_id: UUID?`, `child_ids: list[UUID]`, `parent_status: root/linked/unverified/missing/newer_parent/cycle_broken` |
| `ProcessTree` | `nodes: list[ProcessNode]`, `root_ids: list[UUID]` |
| `NetworkProcessLink` | `connection_id: UUID`, `process_id: UUID?`, `status: pid_match/owner_unavailable/process_missing/temporal_conflict` |
| `FindingContext` | `finding_id: UUID`, `process_ids: list[UUID]`, `ancestor_ids: list[UUID]`, `child_ids: list[UUID]`, `connection_ids: list[UUID]` |
| `TimelineEvent` | `timestamp: Timestamp`, `kind: boot/process_start/user_logon/collection_start/collection_end`, `basis: reported/observed`, `description: str`, `artifact_ids: list[UUID]` |
| `AnalysisIssue` | `component: str`, `message: str`, `artifact_ids: list[UUID]`, `rule_id: str?` |
| `AnalysisResult` | `schema_version: Literal["1.0"] = "1.0"`, `snapshot_id: UUID`, `ruleset_version: str`, `complete: bool`, `findings: list[Finding]`, `process_tree: ProcessTree`, `network_links: list[NetworkProcessLink]`, `finding_context: list[FindingContext]`, `timeline: list[TimelineEvent]`, `issues: list[AnalysisIssue]` |
| `InvestigationReport` | `snapshot: SystemSnapshot`, `analysis: AnalysisResult` |

Findings require at least one evidence item and referenced artifact. Finding IDs derive deterministically from snapshot ID, rule ID, and sorted matched artifact IDs. Reanalysis of the same snapshot and ruleset produces the same analysis, ordering, and IDs; the analyzer does not call the current clock. This is independent of whether the original collection was complete.

## 4. Component interfaces and data flow

These signatures are design contracts. Milestones 1–5 implement storage, interpretation, analysis, console/JSON/HTML reporting, Windows collection, and investigation orchestration. Collection uses injected adapter boundaries in portable tests; actual Windows integration requires separate verification.

| Component | Contract | Responsibility |
|---|---|---|
| Collection context | `CollectionContext(snapshot_id, clock, id_factory, windows, path_context)` | Small dependency container; injectable clock, ID factory, and Windows adapter for tests. Starts with an empty PathContext, then receives endpoint context from the system collector. |
| Windows adapter | `run_query(query: WindowsQuery, inputs: QueryInputs, timeout_seconds: float) -> QueryResponse` | WindowsQuery selects users/tasks/shortcuts. QueryInputs is NoInputs or ShortcutInputs(paths); QueryResponse is a discriminated union of validated users/tasks/shortcuts responses. Collected paths are data, never interpolated into scripts. |
| Ordinary collector | `collect(context: CollectionContext) -> CollectorResult[T]` | Query one source, normalize artifacts, report coverage and errors. Each module supplies its concrete T. |
| System collector | `collect(context: CollectionContext) -> CollectorResult[SystemInventory]` | SystemInventory contains `system: SystemInfo` and `path_context: PathContext`. The pipeline transfers both into the snapshot and updates context for subsequent collectors. |
| Persistence collector | `collect(context, services: list[ServiceArtifact], tasks: list[ScheduledTaskArtifact]) -> CollectorResult[PersistenceArtifact]` | Enumerate Run/Startup entries and project already-collected tasks/services without querying them again. |
| Collection orchestration | `collect_snapshot(context: CollectionContext) -> SystemSnapshot` | Platform check, seven isolated collector runs, snapshot validation. |
| Storage | `load_snapshot(path: Path) -> SystemSnapshot`; `write_snapshot(snapshot, path: Path) -> None` | UTF-8 JSON, version rejection, atomic file publication, clear I/O failures. |
| Command parsing | `parse_process_command(process: ProcessArtifact) -> CommandFacts`; `parse_command_target(command: str) -> CommandTarget` | Internal typed results: executable name/host options and target path/ambiguity explanation respectively. Preserve original evidence. |
| Path classification | `classify_path(path: str, context: PathContext, owner_sid: str | None) -> PathAssessment` | Internal typed result with category, normalized path, confidence, and basis. Lexical classification only. |
| Tree construction | `build_process_tree(processes: list[ProcessArtifact]) -> ProcessTree` | PID/PPID links, parent-time checks, orphan handling, deterministic cycle-safe structure. |
| Network correlation | `correlate_network(snapshot: SystemSnapshot) -> list[NetworkProcessLink]` | Local PID association with explicit unresolved/conflicting cases. |
| Rule | `Rule.evaluate(context: AnalysisContext) -> list[Finding]` | Rule is a frozen dataclass with ID/title/severity/optional ATT&CK metadata and evaluator callable. AnalysisContext contains the snapshot, tree, and network links. |
| Analysis entry point | `analyze_snapshot(snapshot: SystemSnapshot, rules: Sequence[Rule] = DEFAULT_RULES) -> AnalysisResult` | Build context, evaluate rules, sort/deduplicate findings, correlate and build timeline. |
| Finding correlation | `correlate_findings(findings, tree, links) -> list[FindingContext]` | Associate evidence without increasing severity or implying causality. |
| Timeline | `build_timeline(snapshot: SystemSnapshot) -> list[TimelineEvent]` | Use known event times, plus explicitly labelled collection boundaries. |
| Console | `render_console(report: InvestigationReport, console: Console) -> None` | Rich summary and evidence; Console can be captured in tests. |
| JSON report | `write_json_report(report: InvestigationReport, output: Path) -> None` | Separate derived report retaining the original snapshot. |
| HTML report | `render_html(report: InvestigationReport) -> str`; `write_html_report(report, output: Path) -> None` | Jinja2 with escaping, packaged template, inline CSS, no remote assets. |
| Investigation | `run_investigation(output: Path, *, overwrite=False) -> InvestigationReport` | Scoped logging, collection, snapshot publication before analysis, then JSON and HTML publication. |

Data flow: Windows sources → collectors → validated SystemSnapshot → pure analysis/correlation → AnalysisResult → InvestigationReport → presentation. Reporting does not recollect or reinterpret evidence. Analyze and report never change the input snapshot.

The internal dataclass contracts are: CommandFacts(executable_name: str?, host_options: list[HostOption], payload: list[str], parse_issues: list[str]); HostOption(name: str, value: str?, token_index: int); CommandTarget(path: str?, ambiguous: bool, reason: str); PathAssessment(category: temp/appdata/profile/other/unknown, normalized_path: str?, confidence: known_root/conventional_pattern/unresolved, basis: str); and AnalysisContext(snapshot: SystemSnapshot, tree: ProcessTree, network_links: list[NetworkProcessLink]). Adapter response variants contain typed records and typed query issues; raw dictionaries terminate inside the adapter.

Windows-only imports are confined to adapter initialization so fixtures and model tests can import the package on the development host. Platform rejection occurs before live collection, not while importing a model.

Expected source failures are handled close to the failing item. The orchestrator additionally catches an unexpected `Exception` at each collector boundary, logs its traceback, marks that collector failed, and continues. It does not catch KeyboardInterrupt/SystemExit. Rule failures similarly produce an incomplete analysis and a visible analysis issue; a failed rule cannot silently yield a clean report.

## 5. Collection strategy and Windows risks

| Area/risk | Implementation decision and verification |
|---|---|
| Processes disappear or deny individual fields | Use psutil iteration and per-field error handling. Preserve readable fields; record AccessDenied/NoSuchProcess explicitly. Unit tests simulate each exception. |
| PID reuse and terminated parents | Process IDs are snapshot artifact IDs. Reject a parent candidate known to have started after its child. Mark links lacking creation-time evidence unverified. Missing parents are labelled, not invented. |
| Network collection follows process collection | PID matches are described as associations, not proof of identity. Reject known temporal contradictions. An apparently valid PID/time match can still be ambiguous in a non-atomic snapshot. |
| Users and administrators | Capture current security principal separately from interactive sessions. Query local accounts and direct members of the built-in Administrators SID `S-1-5-32-544`, avoiding an English group-name assumption. No recursive domain group expansion. |
| Registry architecture views | Enumerate HKCU/HKLM `Software\Microsoft\Windows\CurrentVersion\Run` with explicit 32-bit and 64-bit view flags. Deduplicate shared-view values while retaining evidence provenance. Do not hand-build Wow6432Node paths. |
| HKCU and alternate credentials | HKCU represents the collecting identity, which may differ from the desktop user. Report that scope. No loading of other users' offline registry hives. |
| Startup folders and shortcuts | Enumerate the current identity's and common Startup folders using known-folder discovery; retain each file path. Resolve `.lnk` metadata through a read-only adapter; never launch or traverse the target. Denied/unresolved shortcuts remain visible with issues. |
| Profile paths and environment variables | Capture relevant endpoint roots; use the matching owner context when known. Keep unresolved variables and state uncertainty. Never expand against the analyst's environment. Conventional user-writable locations are a heuristic, not an ACL measurement. |
| Service commands, quoting, and spaces | Preserve raw command. Parse quoted executable paths and unambiguous cases conservatively. Do not use POSIX `shlex` as a Windows parser; ambiguous targets are recorded rather than guessed. |
| PowerShell blocking, encoding, or policy restrictions | Use the trusted system executable, argument-vector invocation, no shell, NoProfile/NonInteractive, fixed script text, explicit JSON projection/UTF-8 encoding, bounded timeout, captured stderr, and checked return status. Do not change execution policy. |
| PowerShell zero/one/many object serialization | Queries explicitly return arrays and nested properties at sufficient JSON depth. Boundary tests cover empty arrays, singleton arrays, malformed output, Unicode, timeouts, and nonzero return codes. |
| Scheduled task complexity | Collect all actions and projected trigger details. Include COM/other actions as inventory even when no executable rule applies. A disabled task remains evidence, with disabled state visible. |
| Time semantics | UTC normalization with aware datetimes. A task trigger is a planned boundary, not execution time. Do not fabricate Run-key creation time, service-install time, connection-start time, or terminated-process history. |
| Self-observation | Record the collection interval. IRSnapshot and its inventory subprocesses may appear in the snapshot; no hidden filtering. |
| Partial investigation | Persist successes and all coverage issues. Collector errors are distinct from detection severity. Reports explicitly distinguish "no findings" from "complete coverage." |
| Evidence in report output | Treat command lines, names, and paths as untrusted text. Escape HTML and Rich markup/control sequences; do not create active links from artifact strings. Sensitive evidence remains local. |

Platform facts informing these choices: psutil documents permission and disappearance exceptions, network owner PIDs, and Windows services in its [API documentation](https://psutil.readthedocs.io/stable/). Microsoft's [registry-view guidance](https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view) explains explicit view flags. [Get-LocalGroupMember](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localgroupmember?view=powershell-5.1) accepts a SID and documents its 32-bit-host limitation. [Get-ScheduledTask](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask?view=windowsserver2025-ps) provides local task definitions. Pydantic documents [aware datetime validation](https://docs.pydantic.dev/latest/api/standard_library_types/).

## 6. Initial deterministic rules

Thirteen initial rules cover the requested behaviors. All have positive and negative fixtures, stable IDs, evidence fields, a fixed severity, and an explanation of plausible benign use. ATT&CK technique identifiers are optional enrichment, validated against official technique pages during implementation; they do not alter matching or severity.

| ID | Condition | Severity | Why it warrants review / boundaries |
|---|---|---|---|
| IRS-P001 | PowerShell/pwsh host invocation with EncodedCommand or a tested accepted alias/abbreviation | medium | Encoded command content obscures casual inspection; legitimate automation also uses it. Do not confuse EncodedArguments or script arguments with host switches. |
| IRS-P002 | PowerShell/pwsh host WindowStyle option requests Hidden | low | Hides an interactive window; also common in legitimate automation. Require an actual host option/value pair. |
| IRS-P003 | Direct child PowerShell/pwsh of a recognized Office process | high | Office-to-shell execution can result from document-driven code; confirm workflow and document context. |
| IRS-P004 | Direct child cmd.exe of a recognized Office process | medium | Office starting a command shell deserves contextual review; does not prove exploitation. |
| IRS-P005 | Direct child wscript.exe/cscript.exe of a recognized Office process | high | Office starting a script host is a useful triage pattern; do not claim script contents are malicious. |
| IRS-P006 | Process executable lies in an identified TEMP directory | medium | Temporary paths are unusual locations for durable software, but installers use them. Require executable-path evidence. |
| IRS-P007 | Process executable lies in an AppData directory outside its conventional `Programs` installation subtree and outside a more-specific TEMP classification | low | A low-confidence location heuristic; per-user applications remain a common benign explanation. Programs exclusion is noise reduction, not a trust decision. |
| IRS-P008 | certutil command contains an HTTP(S) source together with a supported download-related option combination | medium | Certificate tooling can transfer files. Do not match an ordinary certificate inspection or URL-free invocation. |
| IRS-P009 | rundll32 command matches an explicit script-oriented JavaScript/mshtml pattern | high | DLL launcher used in a script-oriented form; normal DLL/export invocation does not match. |
| IRS-P010 | regsvr32 command combines a remote HTTP(S) `/i:` argument with scrobj.dll | high | Remote scriptlet-oriented registration pattern; normal local component registration does not match. |
| IRS-R001 | A Run-key command's interpretable executable or explicitly parsed script target is in a conventional user-writable directory | medium | Logon execution from a mutable user location merits review; legitimate startup tools also use it. |
| IRS-R002 | A scheduled-task action targets AppData/TEMP directly, or via a supported interpreter/file argument | medium | Scheduled execution of a user-located binary/script merits review. State and principal are included. |
| IRS-R003 | A service command's executable is in a conventional user-writable directory | high | Service persistence combined with mutable-path placement warrants review. The rule does not claim an exploitable ACL or elevation path. |

Recognized Office parents are a documented fixed basename set: WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE, OUTLOOK.EXE, MSACCESS.EXE, MSPUB.EXE, and ONENOTE.EXE. Case-insensitive name comparison is not publisher verification. Parent/child rules require a temporally consistent link with both creation times available; uncertain links remain visible in the tree but do not generate these high-confidence parent/child findings.

Command matching is token-aware. Host parsing stops at PowerShell's command/script payload boundary so a script argument that happens to say `-enc` does not become a host-option finding. Abbreviations are explicitly tested for Windows PowerShell and pwsh; matching is not a broad substring search. Microsoft documents PowerShell's encoded-command, command/script, and window-style parameters in [about_PowerShell_exe](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1).

Persistence target extraction supports direct executables, PowerShell `-File`, and wscript/cscript script paths. Arbitrary inline command evaluation and nested shell interpretation are outside v1. Unresolved/ambiguous targets remain raw evidence. Directory comparisons are component-aware: `C:\Tempest` is not a child of `C:\Temp`.

No rule declares an IP, port, unrecognized executable, or encoded string inherently malicious. No base64 payload is executed. A standalone AppData process is low severity; severity is never inflated simply because several related findings exist.

## 7. Process tree, correlation, and timeline

Build a PID index once, then link artifact IDs. Sort roots/children deterministically. Represent absent parents as labelled orphan roots. PID 0 and self-parent entries are roots. A parent newer than its child is rejected as a likely PID-reuse conflict. Break malformed cycles deterministically and mark the affected node; iterative rendering avoids a recursion failure on long chains.

Network associations preserve owner PID even when no collected process matches. Successful joins are explicitly `pid_match`, not verified historical ownership. Finding context references ancestors, immediate children, and current connections without duplicating artifacts or claiming that relatives are suspicious.

Timeline events use only reported boot time, process creation time, user-logon time, and observed collection boundaries. Missing times produce no invented event. Scheduled trigger boundaries remain in task evidence, outside the event timeline. The report states that a point-in-time snapshot cannot reconstruct exited processes or past connections.

## 8. CLI and reporting behavior

Required commands remain exactly usable as requested:

```text
irsnapshot collect --output snapshot.json
irsnapshot analyze snapshot.json
irsnapshot report snapshot.json --output report.html
irsnapshot run --output investigation/
```

- `collect`: validates platform, collects all categories, writes a versioned snapshot, and prints coverage.
- `analyze`: loads and validates the snapshot, runs deterministic analysis, and prints the Rich report. Add optional `--output analysis.json` for the structured investigation report.
- `report`: analyzes the supplied snapshot using the current bundled ruleset and writes the standalone HTML report.
- `run`: creates an output directory and writes `snapshot.json`, `analysis.json`, `report.html`, and `irsnapshot.log`. Save the snapshot before running analysis so evidence survives downstream failure.
- `--version` and `--help` are available from the first implementation milestone. Other commands appear only when their implementation exists; no placeholder success commands.
- Existing output files are refused by default; an explicit `--overwrite` permits replacement. `run` requires an empty/new directory unless overwrite was requested. Evidence/report files are written through temporary siblings and published atomically; the log is initially published safely and then written incrementally. Safe no-clobber publication still requires Windows validation. Explicit run overwrite preserves unrelated files and removes old derived reports only after saving the new snapshot; see [recovery behavior](reporting.md).
- Exit codes: `0` requested operation completed with no collection/analysis failures; `1` fatal I/O/platform/runtime failure; `2` usage, input-validation, or schema-version failure; `3` outputs produced with partial/failed collection or incomplete analysis. Findings alone do not cause a nonzero exit. Keyboard interruption uses `130`.

The HTML report includes summary counts and coverage, system information, findings ordered by severity, a labelled process tree, processes referenced by findings, network activity with ownership status, persistence findings plus expandable inventory, factual timeline, collection and analysis issues, and expandable evidence details.

Use inline CSS and semantic HTML with accessible contrast, print styling, anchor links, and native `<details>` sections. There is no JavaScript requirement or external font/CDN/image. Long commands and IPv6 addresses wrap. Timestamps display UTC explicitly. Empty states say why a section is empty where coverage is unavailable. All source artifact strings are escaped; evidence never becomes executable markup.

## 9. Incremental implementation and verification

Estimated human implementation budget: 26 hours. Each milestone includes complete file implementations, added/updated tests, a concise explanation of decisions, exact verification commands, and actual results. A failed check is fixed or reported; it is never presumed to pass.

The following are planned Windows PowerShell verification commands, not claims that they have already run. Development setup in the future repository:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

| Milestone | Deliverable / files | Meaningful verification | Budget |
|---|---|---|---|
| 1. Typed foundation | Packaging; models.py; severity.py; storage.py; working version/help entry points; benign sample; model/storage tests; data-model documentation | Reject naive times, negative PIDs, invalid ports, unknown versions/fields, duplicate IDs; accept PID 0, Unicode and nulls; JSON round-trip; overwrite protection; import without Windows APIs | 3 h |
| 2. Evidence interpretation | paths.py; commands.py; process_tree.py; analyzers/network.py; correlation modules; tree/path/command/correlation/timeline tests | Orphans, time-conflicting parents, cycles, missing times, scoped IPv6, unknown owners, path prefix traps, profile/environment context, host-vs-script options, deterministic timeline | 4 h |
| 3. Rule engine | rules modules; analyzers/engine.py and persistence.py; console/JSON reporting; real analyze command; review/partial samples; rule docs/tests | Each of 13 rules has positive and near-miss fixtures; deterministic IDs and ordering; evidence references valid; no severity inflation; incomplete analysis visibly fails | 5 h |
| 4. Windows collection | All collectors and typed Windows adapters; collection pipeline; real collect command; collector and adapter tests | Denied fields, process disappearance, malformed PowerShell responses, singleton/empty arrays, Unicode, registry views, shortcut resolution failures, multiple actions, one failed collector preserving others; actual Windows read-only smoke | 7 h |
| 5. Full investigation/report | HTML renderer/template; report/run commands; CLI orchestration; HTML/CLI tests | Four commands work; snapshot preserved if reporting fails; literal HTML/Rich attack strings escaped; reports work offline; wheel contains template; visible partial-coverage states | 4 h |
| 6. Release validation | README, limitations/testing docs, changelog, samples, Windows CI workflow, packaging checks | Full suite; clean-install wheel; Windows 3.12 and latest supported Python checks; live elevated/unelevated collection; manual HTML review and sample CLI walkthrough | 3 h |

Exact checks introduced by milestone:

```powershell
# Milestone 1
.\.venv\Scripts\python.exe -m pytest tests/test_models.py tests/test_storage.py tests/test_cli.py -q
.\.venv\Scripts\irsnapshot.exe --version

# Milestone 2
.\.venv\Scripts\python.exe -m pytest tests/test_process_tree.py tests/test_paths.py tests/test_commands.py tests/test_correlation.py tests/test_timeline.py -q

# Milestone 3
.\.venv\Scripts\python.exe -m pytest tests/test_process_rules.py tests/test_persistence_rules.py tests/test_cli.py -q
.\.venv\Scripts\irsnapshot.exe analyze samples/review.snapshot.json --output analysis.json

# Milestone 4 (live collect is Windows-only)
.\.venv\Scripts\python.exe -m pytest tests/test_collectors.py tests/test_windows_adapters.py -q
.\.venv\Scripts\python.exe -m pytest tests/test_windows_smoke.py -m windows_live -q
.\.venv\Scripts\irsnapshot.exe collect --output snapshot.json

# Milestone 5
.\.venv\Scripts\python.exe -m pytest tests/test_html_report.py tests/test_investigation.py tests/test_workflow_cli.py tests/test_cli.py -q
.\.venv\Scripts\irsnapshot.exe report samples/review.snapshot.json --output report.html
.\.venv\Scripts\irsnapshot.exe run --output investigation/

# Milestone 6
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip wheel --no-deps --wheel-dir dist .
```

Live smoke tests are opt-in via `-m windows_live`; the normal suite excludes them. They collect benign endpoint data only and never execute suspicious fixture strings. The Windows CI workflow selects live smoke collection on a hosted Windows Server runner. GitHub's Windows runners use administrator accounts with UAC disabled, so this does not establish unelevated coverage ([runner documentation](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#administrative-privileges)). Windows 10/11 desktop behavior and both ordinary and elevated collection require separately recorded manual runs. Assertions target data contracts and coverage rather than fixed counts of ambient processes. See the [release checklist](release-validation.md).

Current environment limitation: this project starts in an empty, non-Git workspace on macOS. Pure model/rule/serialization/reporting tests can be run here after implementation. Windows collector integration and a Windows-ready release claim require Windows execution evidence. If no Windows runtime is available, the final status must say those checks remain unverified.

## 10. Definition of v1.0 completion

All four commands are implemented and verified; all seven collector categories have honest coverage results; 13 documented rules have positive and negative fixtures; required tree/correlation/serialization tests pass; the wheel includes its template; reports escape untrusted text and work offline; samples are synthetic and labelled; and Windows smoke evidence is recorded with OS, Python version, privilege context, and limitations. The documentation describes partial coverage, heuristics, privacy of local evidence, and collection side effects without calling the tool an EDR or malware scanner.

This document retains the accepted v1 target. The implementation status is tracked in README.md; Milestones 1–5 are included in release 0.5.0, with actual Windows collection still awaiting live verification.
