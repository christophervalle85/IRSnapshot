"""Versioned evidence and analysis contracts; no endpoint access or detection logic."""

from collections import Counter
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import ip_address
from typing import Annotated, Generic, Literal, Self, TypeVar
from uuid import UUID

from pydantic import (
    AfterValidator, AwareDatetime, BaseModel, BeforeValidator, ConfigDict,
    Field, StrictBool, StrictFloat, StrictInt, StrictStr, field_validator,
    model_validator,
)

from irsnapshot.severity import Severity


def _timestamp_input(value: object) -> object:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass
    raise ValueError("timestamp must be an aware datetime or ISO 8601 string")


def _utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


Timestamp = Annotated[AwareDatetime, BeforeValidator(_timestamp_input), AfterValidator(_utc)]
PID = Annotated[StrictInt, Field(ge=0)]
Port = Annotated[StrictInt, Field(ge=0, le=65535)]
NonNegative = Annotated[StrictInt, Field(ge=0)]
Text = Annotated[StrictStr, Field(min_length=1)]


class Model(BaseModel):
    model_config = ConfigDict(
        extra="forbid", validate_default=True, revalidate_instances="always",
        allow_inf_nan=False, hide_input_in_errors=True,
    )


class CollectorName(StrEnum):
    SYSTEM = "system"
    PROCESSES = "processes"
    NETWORK = "network"
    USERS = "users"
    SERVICES = "services"
    SCHEDULED_TASKS = "scheduled_tasks"
    PERSISTENCE = "persistence"


class CollectionStatus(StrEnum):
    OK = "ok"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class Artifact(Model):
    artifact_id: UUID
    observed_at: Timestamp
    collector: CollectorName


class SystemInfo(Artifact):
    collector: Literal[CollectorName.SYSTEM] = CollectorName.SYSTEM
    hostname: StrictStr | None = None
    windows_version: StrictStr | None = None
    architecture: StrictStr | None = None
    current_time: Timestamp | None = None
    boot_time: Timestamp | None = None
    collector_username: StrictStr | None = None
    collector_sid: StrictStr | None = None
    elevated: StrictBool | None = None

    @model_validator(mode="after")
    def chronological_boot(self) -> Self:
        if self.boot_time and self.boot_time > (self.current_time or self.observed_at):
            raise ValueError("boot time must not follow system time")
        return self


_SYSTEM_INFO_FIELDS = (
    "hostname", "windows_version", "architecture", "current_time", "boot_time",
    "collector_username", "collector_sid", "elevated",
)


class ProcessArtifact(Artifact):
    collector: Literal[CollectorName.PROCESSES] = CollectorName.PROCESSES
    pid: PID
    ppid: PID | None = None
    name: StrictStr | None = None
    executable: StrictStr | None = None
    command_line: list[StrictStr] | None = None
    username: StrictStr | None = None
    created_at: Timestamp | None = None

    @model_validator(mode="after")
    def chronological_creation(self) -> Self:
        if self.created_at and self.created_at > self.observed_at:
            raise ValueError("process creation must not follow observation")
        return self


class NetworkEndpoint(Model):
    address: Text
    port: Port

    @field_validator("address")
    @classmethod
    def ip_literal(cls, value: str) -> str:
        ip_address(value)
        return value


class NetworkConnection(Artifact):
    collector: Literal[CollectorName.NETWORK] = CollectorName.NETWORK
    family: Literal["ipv4", "ipv6"]
    protocol: Literal["tcp", "udp"]
    local: NetworkEndpoint
    remote: NetworkEndpoint | None = None
    state: StrictStr | None = None
    owning_pid: PID | None = None

    @model_validator(mode="after")
    def consistent_protocol(self) -> Self:
        version = 4 if self.family == "ipv4" else 6
        if any(ip_address(ep.address).version != version for ep in (self.local, self.remote) if ep):
            raise ValueError("endpoint address must match connection family")
        if self.protocol == "udp" and self.state is not None:
            raise ValueError("UDP connection state must be null")
        return self


class UserArtifact(Artifact):
    collector: Literal[CollectorName.USERS] = CollectorName.USERS
    name: Text
    domain: StrictStr | None = None
    sid: StrictStr | None = None
    source: Literal["current_token", "logged_in_session", "local_account", "local_admin_member"]
    enabled: StrictBool | None = None
    session_name: StrictStr | None = None
    logged_in_at: Timestamp | None = None
    member_of_sid: StrictStr | None = None

    @model_validator(mode="after")
    def chronological_logon(self) -> Self:
        if self.logged_in_at and self.logged_in_at > self.observed_at:
            raise ValueError("logon must not follow observation")
        return self


class ServiceArtifact(Artifact):
    collector: Literal[CollectorName.SERVICES] = CollectorName.SERVICES
    name: Text
    display_name: StrictStr | None = None
    status: StrictStr | None = None
    command: StrictStr | None = None
    startup_type: StrictStr | None = None
    username: StrictStr | None = None
    pid: PID | None = None


class TaskAction(Model):
    kind: Literal["exec", "com_handler", "other"]
    executable: StrictStr | None = None
    arguments: StrictStr | None = None
    working_directory: StrictStr | None = None
    class_id: StrictStr | None = None


class TaskTrigger(Model):
    kind: Text
    enabled: StrictBool | None = None
    start_boundary_raw: StrictStr | None = None
    end_boundary_raw: StrictStr | None = None
    start_at: Timestamp | None = None
    end_at: Timestamp | None = None
    user_id: StrictStr | None = None
    repetition_interval: StrictStr | None = None

    @model_validator(mode="after")
    def ordered_boundaries(self) -> Self:
        if self.start_at and self.end_at and self.end_at < self.start_at:
            raise ValueError("trigger end must not precede start")
        return self


class ScheduledTaskArtifact(Artifact):
    collector: Literal[CollectorName.SCHEDULED_TASKS] = CollectorName.SCHEDULED_TASKS
    name: Text
    task_path: Text
    state: StrictStr | None = None
    enabled: StrictBool | None = None
    principal: StrictStr | None = None
    actions: list[TaskAction] = Field(default_factory=list)
    triggers: list[TaskTrigger] = Field(default_factory=list)


class PersistenceArtifact(Artifact):
    collector: Literal[CollectorName.PERSISTENCE] = CollectorName.PERSISTENCE
    kind: Literal["run_key", "startup_folder", "scheduled_task", "service"]
    location: Text
    entry_name: StrictStr  # The default registry value may have an empty name.
    command: StrictStr | None = None
    target_path: StrictStr | None = None
    owner_sid: StrictStr | None = None
    registry_view: Literal["native", "32", "64"] | None = None
    registry_value_type: StrictStr | None = None
    enabled: StrictBool | None = None
    source_artifact_id: UUID | None = None
    action_index: NonNegative | None = None

    @model_validator(mode="after")
    def source_shape(self) -> Self:
        derived = self.kind in ("scheduled_task", "service")
        if derived != (self.source_artifact_id is not None):
            raise ValueError("only service/task persistence requires a source artifact")
        if (self.kind == "scheduled_task") != (self.action_index is not None):
            raise ValueError("only scheduled-task persistence requires an action index")
        return self


class KnownPath(Model):
    kind: Literal["profile", "appdata", "local_appdata", "temp", "startup", "common_startup", "windows"]
    path: Text
    owner_sid: StrictStr | None = None
    source: Text


class EnvironmentValue(Model):
    name: Text
    value: StrictStr
    owner_sid: StrictStr | None = None


class PathContext(Model):
    known_paths: list[KnownPath] = Field(default_factory=list)
    environment: list[EnvironmentValue] = Field(default_factory=list)


class CollectionIssue(Model):
    collector: CollectorName
    category: Literal["access_denied", "disappeared", "timeout", "unavailable", "parse_error", "invalid_data", "unexpected_error"]
    message: Text
    observed_at: Timestamp
    artifact_id: UUID | None = None
    target: StrictStr | None = None
    field: StrictStr | None = None
    exception_type: StrictStr | None = None


class CollectorRun(Model):
    collector: CollectorName
    status: CollectionStatus
    started_at: Timestamp
    finished_at: Timestamp
    item_count: NonNegative
    scope: list[Text] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)

    @model_validator(mode="after")
    def honest_coverage(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("collector finish must not precede start")
        if not self.scope:
            raise ValueError("collector scope must be declared")
        if (self.status == CollectionStatus.OK) != (not self.issues):
            raise ValueError("ok requires no issues; partial/failed/skipped require an issue")
        if self.status in (CollectionStatus.FAILED, CollectionStatus.SKIPPED) and self.item_count:
            raise ValueError("failed/skipped collector cannot claim collected items")
        for issue in self.issues:
            if issue.collector != self.collector:
                raise ValueError("issue collector must match its run")
            if not self.started_at <= issue.observed_at <= self.finished_at:
                raise ValueError("issue observation must fall within its collector interval")
        return self


T = TypeVar("T", bound=BaseModel)


class CollectorResult(Model, Generic[T]):
    items: list[T] = Field(default_factory=list)
    run: CollectorRun

    @model_validator(mode="after")
    def consistent_items(self) -> Self:
        if self.run.item_count != len(self.items):
            raise ValueError("collector item count does not match items")
        for item in self.items:
            if isinstance(item, Artifact) and item.collector != self.run.collector:
                raise ValueError("item collector must match its run")
        return self


class SystemSnapshot(Model):
    schema_version: Literal["1.0"] = "1.0"
    snapshot_id: UUID
    tool_version: Text
    started_at: Timestamp
    finished_at: Timestamp
    system: SystemInfo | None = None
    processes: list[ProcessArtifact] = Field(default_factory=list)
    network: list[NetworkConnection] = Field(default_factory=list)
    users: list[UserArtifact] = Field(default_factory=list)
    services: list[ServiceArtifact] = Field(default_factory=list)
    scheduled_tasks: list[ScheduledTaskArtifact] = Field(default_factory=list)
    persistence: list[PersistenceArtifact] = Field(default_factory=list)
    path_context: PathContext = Field(default_factory=PathContext)
    collector_runs: list[CollectorRun] = Field(default_factory=list)

    def artifacts(self) -> list[Artifact]:
        """Return evidence records without serializing them to dictionaries."""
        return ([self.system] if self.system else []) + [
            *self.processes, *self.network, *self.users, *self.services,
            *self.scheduled_tasks, *self.persistence,
        ]

    @model_validator(mode="after")
    def consistent_snapshot(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("snapshot finish must not precede start")
        artifacts = self.artifacts()
        index = {artifact.artifact_id: artifact for artifact in artifacts}
        if len(index) != len(artifacts):
            raise ValueError("artifact IDs must be unique across all categories")
        if len({p.pid for p in self.processes}) != len(self.processes):
            raise ValueError("process PIDs must be unique within a snapshot")
        _validate_coverage(self, artifacts, index)
        _validate_persistence_sources(self.persistence, index)
        return self


def _validate_coverage(snapshot: SystemSnapshot, artifacts: list[Artifact], index: dict[UUID, Artifact]) -> None:
    runs = {run.collector: run for run in snapshot.collector_runs}
    if len(runs) != len(snapshot.collector_runs) or set(runs) != set(CollectorName):
        raise ValueError("exactly one run for each of the seven collectors is required")
    counts = Counter(artifact.collector for artifact in artifacts)
    for name, run in runs.items():
        if not snapshot.started_at <= run.started_at <= run.finished_at <= snapshot.finished_at:
            raise ValueError("collector interval must fall within snapshot interval")
        if run.item_count != counts[name]:
            raise ValueError("collector item count must match snapshot artifacts")
        for issue in run.issues:
            if issue.artifact_id is not None:
                target = index.get(issue.artifact_id)
                if target is None or target.collector != name:
                    raise ValueError("collection issue must reference an artifact from its collector")
    for artifact in artifacts:
        run = runs[artifact.collector]
        if not run.started_at <= artifact.observed_at <= run.finished_at:
            raise ValueError("artifact observation must fall within its collector interval")
    _validate_system_coverage(snapshot.system, runs[CollectorName.SYSTEM])


def _validate_system_coverage(system: SystemInfo | None, run: CollectorRun) -> None:
    if system is None:
        if run.status not in (CollectionStatus.FAILED, CollectionStatus.SKIPPED):
            raise ValueError("an absent system artifact requires a failed or skipped system collector")
        return
    issue_fields = {
        issue.field
        for issue in run.issues
        if issue.artifact_id == system.artifact_id
    }
    if any(getattr(system, field) is None and field not in issue_fields for field in _SYSTEM_INFO_FIELDS):
        raise ValueError("each unavailable system field requires an issue for the system artifact")


def _validate_persistence_sources(entries: list[PersistenceArtifact], index: dict[UUID, Artifact]) -> None:
    for entry in entries:
        if entry.source_artifact_id is None:
            continue
        source = index.get(entry.source_artifact_id)
        if entry.kind == "service" and not isinstance(source, ServiceArtifact):
            raise ValueError("service persistence must reference a collected service")
        if entry.kind == "scheduled_task":
            if not isinstance(source, ScheduledTaskArtifact):
                raise ValueError("task persistence must reference a collected task")
            if entry.action_index is None or entry.action_index >= len(source.actions):
                raise ValueError("task action index must reference a collected action")


class EvidenceItem(Model):
    artifact_id: UUID
    field: Text
    value: StrictStr | StrictInt | StrictFloat | StrictBool | None | list[StrictStr]
    explanation: Text


class Finding(Model):
    finding_id: UUID
    rule_id: Text
    title: Text
    severity: Severity
    description: Text
    artifact_ids: list[UUID] = Field(min_length=1)
    pids: list[PID] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(min_length=1)
    mitre_technique: StrictStr | None = None

    @model_validator(mode="after")
    def evidence_references(self) -> Self:
        if len(set(self.artifact_ids)) != len(self.artifact_ids):
            raise ValueError("finding artifact references must be unique")
        if any(e.artifact_id not in self.artifact_ids for e in self.evidence):
            raise ValueError("evidence must reference a finding artifact")
        return self


class ProcessNode(Model):
    process_id: UUID
    parent_id: UUID | None = None
    child_ids: list[UUID] = Field(default_factory=list)
    parent_status: Literal["root", "linked", "unverified", "missing", "newer_parent", "cycle_broken"]


class ProcessTree(Model):
    nodes: list[ProcessNode] = Field(default_factory=list)
    root_ids: list[UUID] = Field(default_factory=list)

    @model_validator(mode="after")
    def consistent_edges(self) -> Self:
        index = {node.process_id: node for node in self.nodes}
        if len(index) != len(self.nodes):
            raise ValueError("process tree node IDs must be unique")
        roots = {node.process_id for node in self.nodes if node.parent_id is None}
        if len(set(self.root_ids)) != len(self.root_ids) or set(self.root_ids) != roots:
            raise ValueError("tree roots must match nodes without parents")
        for node in self.nodes:
            if (node.parent_status in ("linked", "unverified")) != (node.parent_id is not None):
                raise ValueError("parent status must agree with presence of parent link")
            if len(set(node.child_ids)) != len(node.child_ids):
                raise ValueError("child references must be unique")
            if node.parent_id is not None:
                parent = index.get(node.parent_id)
                if parent is None or node.process_id not in parent.child_ids:
                    raise ValueError("parent and child references must be reciprocal")
            for child_id in node.child_ids:
                child = index.get(child_id)
                if child is None or child.parent_id != node.process_id:
                    raise ValueError("child and parent references must be reciprocal")
        pending, visited = list(self.root_ids), set()
        while pending:
            current = pending.pop()
            if current in visited:
                raise ValueError("process tree contains a cycle")
            visited.add(current)
            pending.extend(index[current].child_ids)
        if visited != set(index):
            raise ValueError("process tree contains an unreachable cycle")
        return self


class NetworkProcessLink(Model):
    connection_id: UUID
    process_id: UUID | None = None
    status: Literal["pid_match", "owner_unavailable", "process_missing", "temporal_conflict"]

    @model_validator(mode="after")
    def match_requires_process(self) -> Self:
        if (self.status == "pid_match") != (self.process_id is not None):
            raise ValueError("only a PID match may identify a process")
        return self


class FindingContext(Model):
    finding_id: UUID
    process_ids: list[UUID] = Field(default_factory=list)
    ancestor_ids: list[UUID] = Field(default_factory=list)
    child_ids: list[UUID] = Field(default_factory=list)
    connection_ids: list[UUID] = Field(default_factory=list)


class TimelineEvent(Model):
    timestamp: Timestamp
    kind: Literal["boot", "process_start", "user_logon", "collection_start", "collection_end"]
    basis: Literal["reported", "observed"]
    description: Text
    artifact_ids: list[UUID] = Field(default_factory=list)


class AnalysisIssue(Model):
    component: Text
    message: Text
    artifact_ids: list[UUID] = Field(default_factory=list)
    rule_id: StrictStr | None = None


class AnalysisResult(Model):
    schema_version: Literal["1.0"] = "1.0"
    snapshot_id: UUID
    ruleset_version: Text
    complete: StrictBool
    findings: list[Finding] = Field(default_factory=list)
    process_tree: ProcessTree
    network_links: list[NetworkProcessLink] = Field(default_factory=list)
    finding_context: list[FindingContext] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    issues: list[AnalysisIssue] = Field(default_factory=list)

    @model_validator(mode="after")
    def honest_analysis(self) -> Self:
        if self.complete == bool(self.issues):
            raise ValueError("complete analysis must have no issues; incomplete analysis requires an issue")
        finding_ids = {finding.finding_id for finding in self.findings}
        if len(finding_ids) != len(self.findings):
            raise ValueError("finding IDs must be unique")
        if any(context.finding_id not in finding_ids for context in self.finding_context):
            raise ValueError("finding context must reference an existing finding")
        return self


class InvestigationReport(Model):
    snapshot: SystemSnapshot
    analysis: AnalysisResult

    @model_validator(mode="after")
    def valid_relationships(self) -> Self:
        if self.analysis.snapshot_id != self.snapshot.snapshot_id:
            raise ValueError("analysis must belong to the supplied snapshot")
        artifact_ids = {a.artifact_id for a in self.snapshot.artifacts()}
        process_ids = {p.artifact_id for p in self.snapshot.processes}
        connection_ids = {c.artifact_id for c in self.snapshot.network}
        for finding in self.analysis.findings:
            _require_references(finding.artifact_ids, artifact_ids, "finding")
        for node in self.analysis.process_tree.nodes:
            _require_references([node.process_id], process_ids, "tree process")
        for link in self.analysis.network_links:
            _require_references([link.connection_id], connection_ids, "network connection")
            if link.process_id is not None:
                _require_references([link.process_id], process_ids, "network process")
        for context in self.analysis.finding_context:
            _require_references(context.process_ids + context.ancestor_ids + context.child_ids, process_ids, "finding process context")
            _require_references(context.connection_ids, connection_ids, "finding network context")
        for item in [*self.analysis.timeline, *self.analysis.issues]:
            _require_references(item.artifact_ids, artifact_ids, "analysis")
        return self


def _require_references(values: list[UUID], allowed: set[UUID], label: str) -> None:
    if not set(values).issubset(allowed):
        raise ValueError(f"{label} references an unknown or wrong-kind artifact")
