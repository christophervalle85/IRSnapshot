"""Contract tests for host-independent Windows path interpretation."""

import pytest
from pydantic import ValidationError

from irsnapshot.analyzers.paths import PathAssessment, classify_path
from irsnapshot.models import EnvironmentValue, KnownPath, PathContext


def known(kind: str, path: str, owner_sid: str | None = None) -> KnownPath:
    return KnownPath(kind=kind, path=path, owner_sid=owner_sid, source="fixture")


def environment(
    name: str, value: str, owner_sid: str | None = None
) -> EnvironmentValue:
    return EnvironmentValue(name=name, value=value, owner_sid=owner_sid)


def test_captured_temp_root_classifies_a_child_without_owner_filtering():
    context = PathContext(
        known_paths=[
            known(
                "temp",
                r"C:\Users\Ana\AppData\Local\Temp",
                owner_sid="S-1-5-21-100",
            )
        ]
    )

    assert classify_path(
        r"c:/USERS/ANA/AppData/Local/Temp/tool.exe",
        context,
        owner_sid="S-1-5-21-999",
    ) == PathAssessment(
        category="temp",
        normalized_path=r"c:\users\ana\appdata\local\temp\tool.exe",
        confidence="known_root",
        basis="The normalized path is within a captured temp root; this is a lexical location hint, not an ACL or trust decision.",
    )


def test_normalizes_quotes_case_separators_dots_and_unicode():
    context = PathContext(
        known_paths=[known("appdata", "C:/Users/Åsa/AppData/Roaming")]
    )

    result = classify_path(
        '"C:\\USERS\\ÅSA\\AppData\\Local\\..\\Roaming\\München\\tool.exe"',
        context,
    )

    assert result.category == "appdata"
    assert result.normalized_path == r"c:\users\åsa\appdata\roaming\münchen\tool.exe"
    assert result.confidence == "known_root"


def test_dot_traversal_is_applied_before_root_classification():
    context = PathContext(known_paths=[known("temp", r"C:\Temp")])

    result = classify_path(r"C:\Temp\sub\..\..\Windows\tool.exe", context)

    assert result.category == "other"
    assert result.normalized_path == r"c:\windows\tool.exe"
    assert result.confidence == "conventional_pattern"
    assert "No recognized captured root" in result.basis
    assert "ACL" in result.basis


def test_root_matching_is_component_safe():
    context = PathContext(known_paths=[known("temp", r"C:\Temp")])

    result = classify_path(r"C:\Tempest\tool.exe", context)

    assert result.category == "other"
    assert result.normalized_path == r"c:\tempest\tool.exe"
    assert result.confidence == "conventional_pattern"


def test_longest_captured_root_wins():
    context = PathContext(
        known_paths=[
            known("profile", r"C:\Users\Ana"),
            known("local_appdata", r"C:\Users\Ana\AppData\Local"),
        ]
    )

    result = classify_path(
        r"C:\Users\Ana\AppData\Local\Programs\Acme\app.exe", context
    )

    assert result.category == "appdata"
    assert result.confidence == "known_root"
    assert "captured local_appdata root" in result.basis


def test_temp_wins_when_captured_roots_tie():
    context = PathContext(
        known_paths=[
            known("local_appdata", r"C:\Users\Ana\AppData\Local"),
            known("temp", r"C:\Users\Ana\AppData\Local"),
        ]
    )

    result = classify_path(r"C:\Users\Ana\AppData\Local\drop.exe", context)
    reversed_result = classify_path(
        r"C:\Users\Ana\AppData\Local\drop.exe",
        PathContext(known_paths=list(reversed(context.known_paths))),
    )

    assert result == reversed_result
    assert result.category == "temp"
    assert result.confidence == "known_root"
    assert "captured temp root" in result.basis


def test_conflicting_equal_roots_are_unresolved_independent_of_capture_order():
    roots = [
        known("profile", r"C:\Shared"),
        known("appdata", r"C:\Shared"),
    ]

    forward = classify_path(
        r"C:\Shared\tool.exe", PathContext(known_paths=roots)
    )
    reversed_order = classify_path(
        r"C:\Shared\tool.exe", PathContext(known_paths=list(reversed(roots)))
    )

    assert forward == reversed_order
    assert forward.category == "unknown"
    assert forward.normalized_path == r"c:\shared\tool.exe"
    assert forward.confidence == "unresolved"
    assert "conflicting captured root categories" in forward.basis.lower()
    assert "appdata" in forward.basis
    assert "profile" in forward.basis


def test_same_category_equal_roots_choose_a_stable_complete_assessment():
    roots = [
        known("local_appdata", r"C:\Shared"),
        known("appdata", r"C:\Shared"),
    ]

    forward = classify_path(
        r"C:\Shared\tool.exe", PathContext(known_paths=roots)
    )
    reversed_order = classify_path(
        r"C:\Shared\tool.exe", PathContext(known_paths=list(reversed(roots)))
    )

    assert forward == reversed_order
    assert forward.category == "appdata"
    assert forward.confidence == "known_root"


@pytest.mark.parametrize(
    ("path", "category"),
    [
        (r"C:\Users\Ana\AppData\Roaming\tool.exe", "appdata"),
        (r"C:\Users\Ana\AppData\LocalLow\tool.exe", "appdata"),
        (r"C:\Users\Ana\AppData\Local\Temp\tool.exe", "temp"),
    ],
)
def test_profile_root_enables_conventional_appdata_patterns(path, category):
    context = PathContext(known_paths=[known("profile", r"C:\Users\Ana")])

    result = classify_path(path, context)

    assert result.category == category
    assert result.confidence == "conventional_pattern"
    assert "captured profile root" in result.basis
    assert "ACL" in result.basis


def test_windows_root_enables_conventional_temp_pattern():
    context = PathContext(known_paths=[known("windows", r"D:\Windows")])

    result = classify_path(r"D:\Windows\Temp\installer.tmp", context)

    assert result.category == "temp"
    assert result.confidence == "conventional_pattern"
    assert "captured Windows root" in result.basis


@pytest.mark.parametrize("kind", ["startup", "common_startup", "windows"])
def test_non_writable_semantic_roots_are_other_with_known_root_confidence(kind):
    context = PathContext(known_paths=[known(kind, r"D:\Captured")])

    result = classify_path(r"D:\Captured\tool.exe", context)

    assert result.category == "other"
    assert result.confidence == "known_root"
    assert f"captured {kind} root" in result.basis


def test_owner_environment_value_overrides_global_case_insensitively():
    context = PathContext(
        known_paths=[
            known("temp", r"D:\GlobalTemp"),
            known("temp", r"E:\AnaTemp"),
        ],
        environment=[
            environment("TEMP", r"D:\GlobalTemp"),
            environment("temp", r"E:\AnaTemp", "S-1-5-21-ANA"),
        ],
    )

    result = classify_path(r"%TeMp%\tool.exe", context, owner_sid="s-1-5-21-ana")

    assert result.category == "temp"
    assert result.normalized_path == r"e:\anatemp\tool.exe"
    assert result.confidence == "known_root"


def test_no_owner_uses_only_unscoped_environment_value():
    context = PathContext(
        known_paths=[
            known("temp", r"D:\GlobalTemp"),
            known("temp", r"E:\AnaTemp"),
        ],
        environment=[
            environment("TEMP", r"D:\GlobalTemp"),
            environment("TEMP", r"E:\AnaTemp", "S-1-5-21-ANA"),
        ],
    )

    result = classify_path(r"%TEMP%\tool.exe", context)

    assert result.category == "temp"
    assert result.normalized_path == r"d:\globaltemp\tool.exe"


def test_nested_captured_variables_expand_to_a_bounded_fixed_point():
    context = PathContext(
        known_paths=[known("windows", r"Q:\Windows")],
        environment=[
            environment("SystemDrive", "Q:"),
            environment("SystemRoot", r"%SystemDrive%\Windows"),
        ],
    )

    result = classify_path(r"%SystemRoot%\System32\cmd.exe", context)

    assert result.category == "other"
    assert result.normalized_path == r"q:\windows\system32\cmd.exe"
    assert result.confidence == "known_root"


@pytest.mark.parametrize(
    ("environment_values", "input_path", "reason"),
    [
        (
            [environment("TEMP", r"C:\One"), environment("temp", r"D:\Two")],
            r"%TEMP%\x",
            "conflicting",
        ),
        (
            [environment("A", "%B%"), environment("B", "%A%")],
            r"%A%\x",
            "cyclic",
        ),
        ([environment("A", r"%MISSING%\dir")], r"%A%\x", "unresolved"),
    ],
)
def test_conflicting_cyclic_and_nested_unresolved_variables_are_unknown(
    environment_values, input_path, reason
):
    context = PathContext(environment=environment_values)

    result = classify_path(input_path, context)

    assert result.category == "unknown"
    assert result.normalized_path is None
    assert result.confidence == "unresolved"
    assert reason in result.basis.lower()


@pytest.mark.parametrize(
    "environment_values",
    [
        [environment("A", "%A%%A%")],
        [environment("A", "%B%x"), environment("B", "%A%y")],
    ],
)
def test_growing_environment_cycles_are_rejected_without_expansion(
    environment_values,
):
    result = classify_path(
        r"C:\%A%\tool.exe", PathContext(environment=environment_values)
    )

    assert result.category == "unknown"
    assert result.normalized_path is None
    assert result.confidence == "unresolved"
    assert "cyclic" in result.basis.lower()


def test_acyclic_environment_fanout_has_a_strict_output_bound():
    context = PathContext(
        environment=[
            environment("A", "%B%%B%"),
            environment("B", "x" * 20_000),
        ]
    )

    result = classify_path(r"C:\%A%\tool.exe", context)

    assert result.category == "unknown"
    assert result.normalized_path is None
    assert result.confidence == "unresolved"
    assert "bounded size" in result.basis.lower()


def test_conflict_in_irrelevant_owner_scope_does_not_block_global_value():
    context = PathContext(
        known_paths=[known("temp", r"C:\Global")],
        environment=[
            environment("TEMP", r"C:\Global"),
            environment("TEMP", r"D:\One", "SID-A"),
            environment("temp", r"E:\Two", "SID-A"),
        ],
    )

    result = classify_path(r"%TEMP%\x.exe", context, owner_sid="SID-B")

    assert result.category == "temp"
    assert result.normalized_path == r"c:\global\x.exe"


def test_host_environment_is_never_used(monkeypatch):
    monkeypatch.setenv("IRSNAPSHOT_HOST_ONLY", r"C:\Temp")

    result = classify_path(r"%IRSNAPSHOT_HOST_ONLY%\tool.exe", PathContext())

    assert result.category == "unknown"
    assert result.normalized_path is None
    assert result.confidence == "unresolved"
    assert "missing" in result.basis.lower()


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ('C:\\Temp\\bad"name', "quote"),
        (r"C:\Temp\wild?card", "malformed"),
    ],
)
def test_captured_values_cannot_introduce_malformed_path_syntax(value, reason):
    context = PathContext(environment=[environment("ROOT", value)])

    result = classify_path(r"%ROOT%\tool.exe", context)

    assert result.category == "unknown"
    assert result.normalized_path is None
    assert reason in result.basis.lower()


@pytest.mark.parametrize(
    "path",
    [
        r"C:\Temp\x.exe:payload",
        r"C:\Temp\:bad\x.exe",
        r"C::\Temp\x.exe",
        r"\\server:80\share\x.exe",
    ],
)
def test_additional_colons_and_alternate_data_streams_are_unresolved(path):
    context = PathContext(known_paths=[known("temp", r"C:\Temp")])

    result = classify_path(path, context)

    assert result.category == "unknown"
    assert result.normalized_path is None
    assert result.confidence == "unresolved"
    assert "colon or alternate data stream" in result.basis.lower()


def test_additional_colon_from_a_captured_variable_is_unresolved():
    context = PathContext(
        environment=[environment("TARGET", r"C:\Temp\x.exe:payload")]
    )

    result = classify_path(r"%TARGET%", context)

    assert result.category == "unknown"
    assert result.confidence == "unresolved"
    assert "colon or alternate data stream" in result.basis.lower()


def test_captured_root_with_an_additional_colon_is_not_recognized():
    context = PathContext(known_paths=[known("temp", r"C:\Temp:payload")])

    result = classify_path(r"C:\Temp\tool.exe", context)

    assert result.category == "other"
    assert result.confidence == "conventional_pattern"


def test_public_entry_point_revalidates_path_context():
    invalid_context = PathContext.model_construct(
        known_paths=[{"kind": "temp"}], environment=[]
    )

    with pytest.raises(ValidationError):
        classify_path(r"C:\Temp\tool.exe", invalid_context)


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        (r"folder\tool.exe", "relative"),
        (r"C:folder\tool.exe", "drive-relative"),
        (r"\folder\tool.exe", "root-relative"),
        ("C:\\bad\nname.exe", "control"),
        ('"C:\\Temp\\tool.exe', "quote"),
        ('C:\\Temp\\"tool.exe"', "quote"),
        (r"\\?\C:\Temp\tool.exe", "device"),
        (r"\\.\C:\Temp\tool.exe", "device"),
        (r"\??\C:\Temp\tool.exe", "device"),
        (r"\\server", "UNC"),
        ("\\\\server\\", "UNC"),
        (r"C:\Temp\ambiguous.\tool.exe", "trailing"),
        (r"C:\Temp\ambiguous \tool.exe", "trailing"),
    ],
)
def test_ambiguous_or_non_absolute_inputs_are_unknown(path, reason):
    result = classify_path(path, PathContext())

    assert result.category == "unknown"
    assert result.normalized_path is None
    assert result.confidence == "unresolved"
    assert reason.lower() in result.basis.lower()


def test_complete_unc_path_is_supported_lexically():
    context = PathContext(known_paths=[known("temp", r"\\Server\Share\Temp")])

    result = classify_path(r"//SERVER/SHARE/Temp/child/tool.exe", context)

    assert result.category == "temp"
    assert result.normalized_path == r"\\server\share\temp\child\tool.exe"
    assert result.confidence == "known_root"


def test_short_name_alias_is_not_resolved_to_a_captured_profile():
    context = PathContext(known_paths=[known("profile", r"C:\Users\Alexandra")])

    result = classify_path(r"C:\Users\ALEXAN~1\AppData\Local\tool.exe", context)

    assert result.category == "other"
    assert result.confidence == "conventional_pattern"


def test_valid_absolute_unknown_location_states_lexical_limitations():
    result = classify_path(r"Z:\Uncaptured\tool.exe", PathContext())

    assert result == PathAssessment(
        category="other",
        normalized_path=r"z:\uncaptured\tool.exe",
        confidence="conventional_pattern",
        basis="No recognized captured root contains the normalized path; this confidence label only denotes a lexical fallback, and no ACL or trust conclusion is available.",
    )
