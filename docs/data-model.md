# IRSnapshot data model — schema 1.0


The tables below specify the serialized data model used by collection, analysis, and reporting. `T?` means `T | None`, with a default of `None`. Collections use `list[T]` with independent empty defaults, except Finding.artifact_ids and Finding.evidence, which are required and nonempty. Other fields are required unless a default is stated. No arbitrary `dict[str, Any]` crosses component boundaries. External API dictionaries are validated at typed adapter boundaries.

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

Findings require at least one evidence item and referenced artifact. The analysis engine generates deterministic finding IDs and validates derived results against this contract.


## Validation boundaries

Models normalize aware ISO 8601 timestamps to UTC and reject numeric epoch inputs. Collector scope must be explicit. A failed or skipped collector has zero records and at least one issue; a partial collector retains valid records and explains failures. Every snapshot contains exactly one run per collector. A successful run may be empty where absence is meaningful. Storage additionally requires an explicit schema_version and rejects duplicate JSON keys.

Serialized Windows paths are strings, not host-resolved Path objects. Raw scheduled boundaries without offsets are retained without creating a normalized event time. Report models validate reference endpoints; they do not establish causal or temporal correlation. ProcessTree validates structure but never constructs a tree.

Models can be mutated; nested mutations require explicit revalidation. The storage writer performs full revalidation before publication. JSON Schema expresses types and limits; Python validators additionally enforce IP-address syntax, timestamp semantics, cross-record relationships and coverage.
