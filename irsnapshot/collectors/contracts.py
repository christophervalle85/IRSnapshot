"""Typed internal Windows boundaries; importing these models never touches Windows."""
from enum import StrEnum
from typing import Annotated, Literal
from pydantic import Field, StrictBool, StrictStr
from irsnapshot.models import Model, PathContext, TaskAction, TaskTrigger, Text, Timestamp


class AdapterIssue(Model):
    category: Literal['access_denied', 'disappeared', 'timeout', 'unavailable', 'parse_error', 'invalid_data', 'unexpected_error']
    message: Text
    target: StrictStr | None = None
    field: StrictStr | None = None
    exception_type: StrictStr | None = None


class SystemReading(Model):
    hostname: StrictStr | None = None
    windows_version: StrictStr | None = None
    architecture: StrictStr | None = None
    boot_time: Timestamp | None = None
    collector_username: StrictStr | None = None
    collector_sid: StrictStr | None = None
    elevated: StrictBool | None = None
    path_context: PathContext = Field(default_factory=PathContext)
    issues: list[AdapterIssue] = Field(default_factory=list)


class UserRecord(Model):
    name: Text
    domain: StrictStr | None = None
    sid: StrictStr | None = None
    source: Literal['current_token', 'logged_in_session', 'local_account', 'local_admin_member']
    enabled: StrictBool | None = None
    session_name: StrictStr | None = None
    logged_in_at: Timestamp | None = None
    member_of_sid: StrictStr | None = None


class TaskRecord(Model):
    name: Text
    task_path: Text
    state: StrictStr | None = None
    enabled: StrictBool | None = None
    principal: StrictStr | None = None
    actions: list[TaskAction] = Field(default_factory=list)
    triggers: list[TaskTrigger] = Field(default_factory=list)


class ShortcutRecord(Model):
    path: StrictStr
    target_path: StrictStr | None = None
    arguments: StrictStr | None = None


class RunValue(Model):
    location: StrictStr
    entry_name: StrictStr
    command: StrictStr | None
    owner_sid: StrictStr | None
    registry_view: Literal['native', '32', '64']
    registry_value_type: StrictStr


class StartupFile(Model):
    path: StrictStr
    owner_sid: StrictStr | None = None


class WindowsQuery(StrEnum):
    USERS = 'users'
    TASKS = 'tasks'
    SHORTCUTS = 'shortcuts'


class NoInputs(Model):
    pass


class ShortcutInputs(Model):
    paths: list[StrictStr] = Field(default_factory=list)


QueryInputs = NoInputs | ShortcutInputs


class UsersResponse(Model):
    kind: Literal['users'] = 'users'
    items: list[UserRecord] = Field(default_factory=list)
    issues: list[AdapterIssue] = Field(default_factory=list)


class TasksResponse(Model):
    kind: Literal['tasks'] = 'tasks'
    items: list[TaskRecord] = Field(default_factory=list)
    issues: list[AdapterIssue] = Field(default_factory=list)


class ShortcutsResponse(Model):
    kind: Literal['shortcuts'] = 'shortcuts'
    items: list[ShortcutRecord] = Field(default_factory=list)
    issues: list[AdapterIssue] = Field(default_factory=list)


QueryResponse = Annotated[UsersResponse | TasksResponse | ShortcutsResponse, Field(discriminator='kind')]


class RunResponse(Model):
    items: list[RunValue] = Field(default_factory=list)
    issues: list[AdapterIssue] = Field(default_factory=list)


class StartupResponse(Model):
    items: list[StartupFile] = Field(default_factory=list)
    issues: list[AdapterIssue] = Field(default_factory=list)
