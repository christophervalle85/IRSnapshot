"""Contract tests for conservative persistence interpretation and rules."""

from copy import deepcopy
from uuid import UUID

import pytest

from irsnapshot.models import ProcessTree, SystemSnapshot, TaskAction


ALICE_SID = "S-1-5-21-100-200-300-1001"
BOB_SID = "S-1-5-21-100-200-300-1002"


def _artifact(artifact_id: int, collector: str, **fields):
    return {
        "artifact_id": str(UUID(int=artifact_id)),
        "observed_at": "2026-09-17T14:05:00Z",
        "collector": collector,
        **fields,
    }


def _context(snapshot_data, *, services=(), tasks=(), persistence=(), path_context=None):
    from irsnapshot.rules.base import AnalysisContext

    data = deepcopy(snapshot_data)
    data["services"] = list(services)
    data["scheduled_tasks"] = list(tasks)
    data["persistence"] = list(persistence)
    if path_context is not None:
        data["path_context"] = path_context
    counts = {
        "services": len(services),
        "scheduled_tasks": len(tasks),
        "persistence": len(persistence),
    }
    for run in data["collector_runs"]:
        if run["collector"] in counts:
            run["item_count"] = counts[run["collector"]]
    return AnalysisContext(
        snapshot=SystemSnapshot.model_validate(data),
        tree=ProcessTree(),
        network_links=[],
    )


def _path_context():
    return {
        "known_paths": [
            {
                "kind": "windows",
                "path": r"C:\Windows",
                "source": "synthetic fixture",
            },
            {
                "kind": "profile",
                "path": r"C:\Users\Alice",
                "owner_sid": ALICE_SID,
                "source": "synthetic fixture",
            },
        ],
        "environment": [
            {
                "name": "APPDATA",
                "value": r"C:\Users\Alice\AppData\Roaming",
                "owner_sid": ALICE_SID,
            },
            {
                "name": "APPDATA",
                "value": r"C:\Program Files\BobData",
                "owner_sid": BOB_SID,
            },
        ],
    }


@pytest.mark.parametrize(
    ("raw", "path", "kind", "provenance"),
    [
        (
            r'"C:\Program Files\Acme\agent.exe" --quiet',
            r"C:\Program Files\Acme\agent.exe",
            "executable",
            "raw_command_executable",
        ),
        (
            r'pwsh.exe -NoProfile -File "C:\Users\Alice\Job Files\daily.ps1" -Mode safe',
            r"C:\Users\Alice\Job Files\daily.ps1",
            "script",
            "powershell_file",
        ),
        (
            r'wscript.exe //B //Nologo "C:\Users\Alice\Jobs\login.vbs" argument',
            r"C:\Users\Alice\Jobs\login.vbs",
            "script",
            "script_host_file",
        ),
    ],
)
def test_raw_persistence_target_supported_subset(raw, path, kind, provenance):
    from irsnapshot.analyzers.persistence import parse_persistence_command

    target = parse_persistence_command(raw)

    assert target.path == path
    assert target.kind == kind
    assert target.provenance == provenance
    assert target.raw_value == raw
    assert target.reason


@pytest.mark.parametrize(
    "raw",
    [
        r'C:\Program Files\Acme\agent.exe --quiet',
        r'"C:\Users\Alice\broken.exe --quiet',
        r'powershell.exe -Command "C:\Users\Alice\AppData\Roaming\late.ps1"',
        r'powershell.exe -EncodedCommand QwA6AFwAVQBzAGUAcgBzAA==',
        r'cmd.exe /c "C:\Users\Alice\AppData\Roaming\late.exe"',
        r'powershell.exe -Unknown value -File C:\Users\Alice\job.ps1',
        r'wscript.exe //Unknown C:\Users\Alice\job.vbs',
        r'wscript.exe ordinary-data C:\Users\Alice\job.vbs',
    ],
)
def test_raw_persistence_target_does_not_invent_paths(raw):
    from irsnapshot.analyzers.persistence import parse_persistence_command

    target = parse_persistence_command(raw)

    assert target.path is None
    assert target.kind == "unresolved"
    assert target.provenance == "unresolved"
    assert target.raw_value == raw
    assert target.reason


@pytest.mark.parametrize(
    "raw",
    [
        "tool.exe\nC:\\Users\\Alice\\late.exe",
        r'powershell.exe --File C:\Users\Alice\job.ps1',
        r'powershell.exe -NoProfile -nop -File C:\Users\Alice\job.ps1',
        r'powershell.exe -ExecutionPolicy -NoProfile -File C:\Users\Alice\job.ps1',
        r'powershell.exe -WorkingDirectory C:\Tools -File C:\Users\Alice\job.ps1',
    ],
)
def test_raw_scanner_rejects_unsupported_separators_switches_and_alias_duplicates(raw):
    from irsnapshot.analyzers.persistence import parse_persistence_command

    assert parse_persistence_command(raw).path is None


def test_raw_scanner_accepts_tab_separator_and_pwsh_double_dash_file():
    from irsnapshot.analyzers.persistence import parse_persistence_command

    tabbed = parse_persistence_command("tool.exe\t--literal")
    modern = parse_persistence_command(r'pwsh.exe --File "C:\Users\Alice\job.ps1"')
    modern_working_directory = parse_persistence_command(
        r'pwsh.exe -WorkingDirectory C:\Tools -File C:\Users\Alice\job.ps1'
    )

    assert tabbed.path == "tool.exe"
    assert modern.path == r"C:\Users\Alice\job.ps1"
    assert modern_working_directory.path == r"C:\Users\Alice\job.ps1"


def test_raw_escaped_quote_does_not_expose_later_file_target(snapshot_data):
    from irsnapshot.analyzers.persistence import parse_persistence_command
    from irsnapshot.rules.persistence_rules import R001

    raw = (
        r'pwsh.exe -WorkingDirectory "C:\Tools\" '
        r'-File C:\Users\Alice\AppData\Roaming\late.ps1'
    )
    target = parse_persistence_command(raw)
    entry = _artifact(
        107,
        "persistence",
        kind="run_key",
        location="HKCU Run",
        entry_name="Ambiguous quote",
        command=raw,
        owner_sid=ALICE_SID,
    )
    context = _context(snapshot_data, persistence=[entry], path_context=_path_context())

    assert target.path is None
    assert target.kind == "unresolved"
    assert "quote" in target.reason.casefold()
    assert R001.evaluate(context) == []


def test_raw_escaped_quote_preserves_independent_explicit_executable(snapshot_data):
    from irsnapshot.analyzers.persistence import parse_persistence_command
    from irsnapshot.rules.persistence_rules import R001

    raw = (
        r'"C:\Users\Alice\AppData\Local\Acme\pwsh.exe" '
        r'-WorkingDirectory "C:\Tools\" -File C:\Windows\safe.ps1'
    )
    target = parse_persistence_command(raw)
    entry = _artifact(
        108,
        "persistence",
        kind="run_key",
        location="HKCU Run",
        entry_name="Explicit interpreter",
        command=raw,
        owner_sid=ALICE_SID,
    )
    context = _context(snapshot_data, persistence=[entry], path_context=_path_context())

    assert target.path is None
    assert target.executable == r"C:\Users\Alice\AppData\Local\Acme\pwsh.exe"
    findings = R001.evaluate(context)
    assert len(findings) == 1
    assert next(
        item.value for item in findings[0].evidence if item.field == "interpreted_target"
    ) == r"C:\Users\Alice\AppData\Local\Acme\pwsh.exe"


def test_structured_interpreter_escaped_quote_does_not_expose_later_file_target(
    snapshot_data,
):
    from irsnapshot.analyzers.persistence import parse_task_action
    from irsnapshot.rules.persistence_rules import R002

    arguments = (
        r'-WorkingDirectory "C:\Tools\" '
        r'-File C:\Users\Alice\AppData\Roaming\late.ps1'
    )
    action = TaskAction(
        kind="exec",
        executable=r"C:\Windows\System32\pwsh.exe",
        arguments=arguments,
    )
    task = _artifact(
        206,
        "scheduled_tasks",
        name="Ambiguous quote",
        task_path=r"\Examples\Ambiguous quote",
        actions=[action.model_dump(mode="json")],
    )
    target = parse_task_action(action)
    context = _context(snapshot_data, tasks=[task], path_context=_path_context())

    assert target.path is None
    assert target.kind == "unresolved"
    assert "quote" in target.reason.casefold()
    assert R002.evaluate(context) == []


def test_quoted_token_without_escaped_boundary_remains_supported():
    from irsnapshot.analyzers.persistence import parse_persistence_command

    target = parse_persistence_command(
        r'pwsh.exe -WorkingDirectory "C:\Tools With Space" '
        r'-File "C:\Users\Alice\Job Files\daily.ps1"'
    )

    assert target.path == r"C:\Users\Alice\Job Files\daily.ps1"


def test_task_action_keeps_separately_collected_spaced_executable():
    from irsnapshot.analyzers.persistence import parse_task_action

    action = TaskAction(
        kind="exec",
        executable=r"C:\Users\Alice\AppData\Local\Acme Tool\agent.exe",
        arguments="--quiet",
    )

    target = parse_task_action(action)

    assert target.path == action.executable
    assert target.kind == "executable"
    assert target.provenance == "task_action_executable"
    assert target.executable == action.executable
    assert target.arguments == action.arguments


def test_task_direct_executable_does_not_reparse_unrelated_arguments():
    from irsnapshot.analyzers.persistence import parse_task_action

    action = TaskAction(
        kind="exec",
        executable=r"C:\Users\Alice\AppData\Local\Acme Tool\agent.exe",
        arguments='literal "malformed data & still data',
    )

    target = parse_task_action(action)

    assert target.path == action.executable
    assert target.provenance == "task_action_executable"
    assert target.arguments == action.arguments


@pytest.mark.parametrize(
    "action",
    [
        TaskAction(kind="com_handler", class_id="{00000000-0000-0000-0000-000000000001}"),
        TaskAction(kind="other"),
        TaskAction(kind="exec", executable=None, arguments=r"C:\Users\Alice\late.exe"),
        TaskAction(kind="exec", executable="cmd.exe", arguments=r'/c "C:\Users\Alice\late.exe"'),
        TaskAction(kind="exec", executable="powershell.exe", arguments=r'-Command "C:\Users\Alice\late.ps1"'),
    ],
)
def test_task_action_unsupported_forms_are_unresolved(action):
    from irsnapshot.analyzers.persistence import parse_task_action

    target = parse_task_action(action)

    assert target.path is None
    assert target.kind == "unresolved"
    assert target.reason


def test_r001_matches_run_key_script_with_owner_scoped_expansion(snapshot_data):
    from irsnapshot.rules.persistence_rules import R001

    entry = _artifact(
        101,
        "persistence",
        kind="run_key",
        location=r"HKU\Alice\Software\Microsoft\Windows\CurrentVersion\Run",
        entry_name="Daily job",
        command=r'powershell.exe -NoProfile -File "%APPDATA%\Acme\daily.ps1"',
        owner_sid=ALICE_SID,
        registry_view="64",
        registry_value_type="REG_SZ",
        enabled=True,
    )
    context = _context(snapshot_data, persistence=[entry], path_context=_path_context())

    findings = R001.evaluate(context)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "IRS-R001"
    assert finding.severity == "medium"
    assert finding.artifact_ids == [UUID(int=101)]
    assert {item.field for item in finding.evidence} >= {
        "entry_name", "location", "command", "interpreted_target", "path_basis"
    }
    assert next(item.value for item in finding.evidence if item.field == "interpreted_target") == r"%APPDATA%\Acme\daily.ps1"


def test_r001_uses_entry_owner_and_ignores_startup_inventory(snapshot_data):
    from irsnapshot.rules.persistence_rules import R001

    entries = [
        _artifact(
            102,
            "persistence",
            kind="run_key",
            location=r"HKU\Bob\Software\Microsoft\Windows\CurrentVersion\Run",
            entry_name="Owner scoped",
            command=r"%APPDATA%\Acme\agent.exe",
            owner_sid=BOB_SID,
        ),
        _artifact(
            103,
            "persistence",
            kind="startup_folder",
            location=r"C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
            entry_name="agent.lnk",
            target_path=r"C:\Users\Alice\AppData\Local\Acme\agent.exe",
        ),
    ]
    context = _context(snapshot_data, persistence=entries, path_context=_path_context())

    assert R001.evaluate(context) == []


def test_r001_rejects_ambiguous_and_profile_prefix_targets(snapshot_data):
    from irsnapshot.rules.persistence_rules import R001

    entries = [
        _artifact(
            104,
            "persistence",
            kind="run_key",
            location="HKCU Run",
            entry_name="Ambiguous",
            command=r"C:\Users\Alice\AppData\Local\Acme Tool\agent.exe --quiet",
            owner_sid=ALICE_SID,
        ),
        _artifact(
            105,
            "persistence",
            kind="run_key",
            location="HKCU Run",
            entry_name="Prefix trap",
            command=r"C:\Users\AliceX\agent.exe",
            owner_sid=ALICE_SID,
        ),
    ]
    context = _context(snapshot_data, persistence=entries, path_context=_path_context())

    assert R001.evaluate(context) == []


def test_r001_matches_interpreter_executable_when_payload_is_unsupported(snapshot_data):
    from irsnapshot.rules.persistence_rules import R001

    entry = _artifact(
        106,
        "persistence",
        kind="run_key",
        location="HKCU Run",
        entry_name="Direct interpreter",
        command=(
            r'"C:\Users\Alice\AppData\Local\Acme\powershell.exe" '
            r'-Command "C:\Windows\safe.ps1"'
        ),
        owner_sid=ALICE_SID,
    )
    context = _context(snapshot_data, persistence=[entry], path_context=_path_context())

    findings = R001.evaluate(context)

    assert len(findings) == 1
    targets = [item.value for item in findings[0].evidence if item.field.startswith("interpreted_target")]
    assert targets == [r"C:\Users\Alice\AppData\Local\Acme\powershell.exe"]


def test_r002_aggregates_matching_actions_and_ignores_projections(snapshot_data):
    from irsnapshot.rules.persistence_rules import R002

    task = _artifact(
        201,
        "scheduled_tasks",
        name="Two actions",
        task_path=r"\Examples\Two actions",
        state="Disabled",
        enabled=False,
        principal="Alice",
        actions=[
            {
                "kind": "exec",
                "executable": r"C:\Users\Alice\AppData\Local\Acme Tool\agent.exe",
                "arguments": "--quiet",
            },
            {
                "kind": "exec",
                "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "arguments": r'-NoProfile -File "C:\Users\Alice\AppData\Roaming\Acme Jobs\daily.ps1" -Mode safe',
            },
            {
                "kind": "com_handler",
                "class_id": "{00000000-0000-0000-0000-000000000001}",
            },
        ],
    )
    projections = [
        _artifact(
            202 + index,
            "persistence",
            kind="scheduled_task",
            location=r"\Examples\Two actions",
            entry_name="Two actions",
            command="projection",
            source_artifact_id=str(UUID(int=201)),
            action_index=index,
            enabled=False,
        )
        for index in (0, 1)
    ]
    context = _context(
        snapshot_data,
        tasks=[task],
        persistence=projections,
        path_context=_path_context(),
    )

    findings = R002.evaluate(context)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "IRS-R002"
    assert finding.severity == "medium"
    assert finding.artifact_ids == [UUID(int=201)]
    assert finding.pids == []
    fields = [item.field for item in finding.evidence]
    assert "actions[0].target" in fields
    assert "actions[1].target" in fields
    assert "actions[2].target" not in fields
    assert next(item.value for item in finding.evidence if item.field == "enabled") is False
    assert next(item.value for item in finding.evidence if item.field == "state") == "Disabled"
    assert not {UUID(int=202), UUID(int=203)} & set(finding.artifact_ids)


def test_r002_does_not_infer_owner_sid_from_principal(snapshot_data):
    from irsnapshot.rules.persistence_rules import R002

    task = _artifact(
        204,
        "scheduled_tasks",
        name="Unresolved owner",
        task_path=r"\Examples\Unresolved owner",
        principal="Alice",
        actions=[{"kind": "exec", "executable": r"%APPDATA%\Acme\agent.exe"}],
    )
    context = _context(snapshot_data, tasks=[task], path_context=_path_context())

    assert R002.evaluate(context) == []


def test_r002_matches_interpreter_executable_before_unsupported_inline_payload(snapshot_data):
    from irsnapshot.rules.persistence_rules import R002

    task = _artifact(
        205,
        "scheduled_tasks",
        name="Direct interpreter",
        task_path=r"\Examples\Direct interpreter",
        actions=[
            {
                "kind": "exec",
                "executable": r"C:\Users\Alice\AppData\Local\Acme\pwsh.exe",
                "arguments": "-EncodedCommand opaque",
            }
        ],
    )
    context = _context(snapshot_data, tasks=[task], path_context=_path_context())

    findings = R002.evaluate(context)

    assert len(findings) == 1
    assert next(
        item.value for item in findings[0].evidence if item.field == "actions[0].target"
    ) == r"C:\Users\Alice\AppData\Local\Acme\pwsh.exe"


@pytest.mark.parametrize("kind", ["com_handler", "other"])
def test_r002_non_exec_action_executable_is_inventory_only(snapshot_data, kind):
    from irsnapshot.analyzers.persistence import parse_task_action
    from irsnapshot.rules.persistence_rules import R002

    action = TaskAction(
        kind=kind,
        executable=r"C:\Users\Alice\AppData\Local\Acme\agent.exe",
        class_id=(
            "{00000000-0000-0000-0000-000000000001}"
            if kind == "com_handler"
            else None
        ),
    )
    task = _artifact(
        207,
        "scheduled_tasks",
        name="Non-exec inventory",
        task_path=r"\Examples\Non-exec inventory",
        actions=[action.model_dump(mode="json")],
    )
    target = parse_task_action(action)
    context = _context(snapshot_data, tasks=[task], path_context=_path_context())

    assert target.kind == "unresolved"
    assert target.executable == action.executable
    assert R002.evaluate(context) == []


def test_r003_matches_only_service_command_executable_without_pid_hint(snapshot_data):
    from irsnapshot.rules.persistence_rules import R003

    service = _artifact(
        301,
        "services",
        name="AcmeService",
        display_name="Acme Service",
        status="running",
        command=r'"C:\Users\Alice\AppData\Local\Acme Service\agent.exe" --service',
        startup_type="automatic",
        username="LocalSystem",
        pid=999,
    )
    projection = _artifact(
        302,
        "persistence",
        kind="service",
        location="Services/AcmeService",
        entry_name="AcmeService",
        command=service["command"],
        source_artifact_id=str(UUID(int=301)),
        enabled=True,
    )
    context = _context(
        snapshot_data,
        services=[service],
        persistence=[projection],
        path_context=_path_context(),
    )

    findings = R003.evaluate(context)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "IRS-R003"
    assert finding.severity == "high"
    assert finding.artifact_ids == [UUID(int=301)]
    assert finding.pids == []
    assert {item.field for item in finding.evidence} >= {
        "name", "status", "startup_type", "username", "command",
        "interpreted_target", "path_basis",
    }
    assert UUID(int=302) not in finding.artifact_ids


def test_r003_classifies_interpreter_executable_not_file_payload(snapshot_data):
    from irsnapshot.rules.persistence_rules import R003

    matching = _artifact(
        304,
        "services",
        name="WritableInterpreter",
        command=(
            r'"C:\Users\Alice\AppData\Local\Acme\powershell.exe" '
            r'-File "C:\Windows\safe.ps1"'
        ),
    )
    payload_only = _artifact(
        305,
        "services",
        name="PayloadOnly",
        command=(
            r'"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" '
            r'-File "C:\Users\Alice\AppData\Roaming\service.ps1"'
        ),
    )
    context = _context(
        snapshot_data,
        services=[matching, payload_only],
        path_context=_path_context(),
    )

    findings = R003.evaluate(context)

    assert len(findings) == 1
    assert findings[0].artifact_ids == [UUID(int=304)]
    assert next(
        item.value for item in findings[0].evidence if item.field == "interpreted_target"
    ) == r"C:\Users\Alice\AppData\Local\Acme\powershell.exe"


@pytest.mark.parametrize(
    "command",
    [
        r'"C:\Program Files\Acme\service.exe" --service',
        r'C:\Users\Alice\AppData\Local\Acme Service\agent.exe --service',
        r'powershell.exe -File "C:\Users\Alice\AppData\Roaming\service.ps1"',
        r'"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -File "C:\Users\Alice\AppData\Roaming\service.ps1"',
        None,
    ],
)
def test_r003_ignores_benign_ambiguous_and_interpreter_payloads(snapshot_data, command):
    from irsnapshot.rules.persistence_rules import R003

    service = _artifact(
        303,
        "services",
        name="NearMiss",
        status="stopped",
        command=command,
        startup_type="manual",
        username="LocalSystem",
    )
    context = _context(snapshot_data, services=[service], path_context=_path_context())

    assert R003.evaluate(context) == []


def test_rule_evaluation_does_not_mutate_snapshot(snapshot_data):
    from irsnapshot.rules.persistence_rules import PERSISTENCE_RULES

    entry = _artifact(
        401,
        "persistence",
        kind="run_key",
        location="HKCU Run",
        entry_name="Agent",
        command=r"C:\Users\Alice\agent.exe",
        owner_sid=ALICE_SID,
    )
    context = _context(snapshot_data, persistence=[entry], path_context=_path_context())
    before = context.snapshot.model_dump(mode="json")

    for rule in PERSISTENCE_RULES:
        rule.evaluate(context)

    assert context.snapshot.model_dump(mode="json") == before


def test_persistence_rule_order_and_metadata():
    from irsnapshot.rules.persistence_rules import PERSISTENCE_RULES

    assert [rule.rule_id for rule in PERSISTENCE_RULES] == [
        "IRS-R001", "IRS-R002", "IRS-R003"
    ]
    assert [rule.severity.value for rule in PERSISTENCE_RULES] == [
        "medium", "medium", "high"
    ]
