"""Shared collection context and run bookkeeping."""
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Callable, Generic, TypeVar
from uuid import UUID, uuid4

from pydantic import BaseModel

from irsnapshot.models import (CollectionIssue, CollectionStatus, CollectorName,
                               CollectorResult, CollectorRun, Model, PathContext,
                               SystemInfo)

if TYPE_CHECKING:
    from irsnapshot.collectors.windows import WindowsAdapter


def _windows_adapter():
    from irsnapshot.collectors.windows import WindowsAdapter
    return WindowsAdapter()


@dataclass
class CollectionContext:
    snapshot_id: UUID = field(default_factory=uuid4)
    clock: Callable[[], datetime] = field(default_factory=lambda: lambda: datetime.now(UTC))
    id_factory: Callable[[], UUID] = field(default_factory=lambda: uuid4)
    windows: 'WindowsAdapter' = field(default_factory=_windows_adapter)
    path_context: PathContext = field(default_factory=PathContext)
    collector_sid: str | None = None


class SystemInventory(Model):
    system: SystemInfo
    path_context: PathContext


T = TypeVar('T', bound=BaseModel)


class RunBuilder(Generic[T]):
    def __init__(self, context: CollectionContext, name: CollectorName, scope: list[str]):
        self.context = context
        self.name = name
        self.scope = scope
        self.started_at = context.clock()
        self.items: list[T] = []
        self.issues: list[CollectionIssue] = []

    def issue(self, category: str, message: str, *, artifact_id: UUID | None = None,
              target: str | None = None, field: str | None = None,
              exception_type: str | None = None) -> None:
        self.issues.append(CollectionIssue(
            collector=self.name, category=category, message=message,
            observed_at=self.context.clock(), artifact_id=artifact_id,
            target=target, field=field, exception_type=exception_type,
        ))

    def adapter_issues(self, issues: list, *, artifact_id: UUID | None = None) -> None:
        for issue in issues:
            self.issue(issue.category, issue.message, artifact_id=artifact_id,
                       target=issue.target, field=issue.field,
                       exception_type=issue.exception_type)

    def finish(self) -> CollectorResult[T]:
        finished_at = self.context.clock()
        status = CollectionStatus.OK if not self.issues else (
            CollectionStatus.PARTIAL if self.items else CollectionStatus.FAILED)
        return CollectorResult[T](items=self.items, run=CollectorRun(
            collector=self.name, status=status, started_at=self.started_at,
            finished_at=finished_at, item_count=len(self.items),
            scope=self.scope, issues=self.issues,
        ))


def classify_exception(exc: Exception) -> str:
    import psutil
    if isinstance(exc, (PermissionError, psutil.AccessDenied)):
        return 'access_denied'
    if isinstance(exc, (ProcessLookupError, psutil.NoSuchProcess, psutil.ZombieProcess)):
        return 'disappeared'
    if isinstance(exc, (TimeoutError, psutil.TimeoutExpired)):
        return 'timeout'
    return 'unexpected_error'


def reported_time(value: object, observed_at: datetime) -> datetime:
    """Accept only valid aware/reportable times no later than observation."""
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('reported timestamp has no UTC offset')
        result = value.astimezone(UTC)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        import math
        if not math.isfinite(value) or value < 0:
            raise ValueError('reported timestamp is not finite or nonnegative')
        result = datetime.fromtimestamp(value, UTC)
    else:
        raise ValueError('reported timestamp has unsupported type')
    if result > observed_at:
        raise ValueError('reported timestamp follows observation')
    return result
