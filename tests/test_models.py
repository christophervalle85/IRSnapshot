"""Test evidence-boundary contracts, not ambient machine state."""

import json
from copy import deepcopy
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError


def validate(data):
    from irsnapshot.models import SystemSnapshot

    return SystemSnapshot.model_validate_json(json.dumps(data))


def test_complete_sample_round_trips_without_losing_unknowns(snapshot_data):
    from irsnapshot.models import SystemSnapshot

    snapshot = validate(snapshot_data)
    restored = SystemSnapshot.model_validate_json(snapshot.model_dump_json())
    assert restored == snapshot
    assert restored.processes[0].pid == 400
    assert restored.network[0].remote is None
    assert restored.scheduled_tasks[0].triggers[0].start_at is None
    assert restored.scheduled_tasks[0].triggers[0].start_boundary_raw == "2026-09-18T12:00:00"


def test_offsets_normalize_to_utc(snapshot_data):
    snapshot_data["processes"][0]["created_at"] = "2026-09-17T09:00:00-05:00"
    snapshot = validate(snapshot_data)
    assert snapshot.processes[0].created_at == datetime(2026, 9, 17, 14, tzinfo=UTC)
    assert snapshot.processes[0].created_at.tzinfo is UTC


@pytest.mark.parametrize(
    "bad", ["2026-09-17T14:00:00", "yesterday", "0", "0.5", 0, True],
)
def test_unreliable_timestamp_rejected(snapshot_data, bad):
    snapshot_data["processes"][0]["created_at"] = bad
    with pytest.raises(ValidationError):
        validate(snapshot_data)


@pytest.mark.parametrize("bad", [-1, True, "400", 1.5])
def test_pid_is_strict_nonnegative_integer(snapshot_data, bad):
    snapshot_data["processes"][0]["pid"] = bad
    with pytest.raises(ValidationError):
        validate(snapshot_data)


def test_pid_zero_unicode_and_empty_vs_unknown_commands(snapshot_data):
    snapshot_data["processes"][0].update(pid=0, name="程序.exe", command_line=[])
    result = validate(snapshot_data)
    assert result.processes[0].pid == 0
    assert result.processes[0].command_line == []
    assert "程序.exe" in result.model_dump_json()
    snapshot_data["processes"][0]["command_line"] = None
    assert validate(snapshot_data).processes[0].command_line is None


@pytest.mark.parametrize("bad", [-1, 65536, True, "80"])
def test_ports_reject_invalid_values(snapshot_data, bad):
    snapshot_data["network"][0]["local"]["port"] = bad
    with pytest.raises(ValidationError):
        validate(snapshot_data)


@pytest.mark.parametrize("address", ["hostname.example", "999.0.0.1", "", "fe80::1%"])
def test_network_endpoints_require_ip_literals(snapshot_data, address):
    snapshot_data["network"][0]["local"]["address"] = address
    with pytest.raises(ValidationError):
        validate(snapshot_data)


def test_scoped_ipv6_preserves_scope(snapshot_data):
    snapshot_data["network"][0].update(family="ipv6", protocol="udp", state=None)
    snapshot_data["network"][0]["local"]["address"] = "fe80::1%12"
    assert validate(snapshot_data).network[0].local.address == "fe80::1%12"


def test_family_mismatch_and_udp_state_rejected(snapshot_data):
    snapshot_data["network"][0]["family"] = "ipv6"
    with pytest.raises(ValidationError):
        validate(snapshot_data)
    snapshot_data["network"][0].update(family="ipv4", protocol="udp")
    with pytest.raises(ValidationError):
        validate(snapshot_data)


@pytest.mark.parametrize("location", ["envelope", "artifact", "nested"])
def test_unknown_fields_rejected_at_each_boundary(snapshot_data, location):
    target = {"envelope": snapshot_data, "artifact": snapshot_data["processes"][0],
              "nested": snapshot_data["network"][0]["local"]}[location]
    target["unexpected"] = "silently ignoring this would lose evidence"
    with pytest.raises(ValidationError):
        validate(snapshot_data)


def test_future_schema_rejected(snapshot_data):
    snapshot_data["schema_version"] = "2.0"
    with pytest.raises(ValidationError):
        validate(snapshot_data)


def test_duplicate_ids_across_categories_rejected(snapshot_data):
    snapshot_data["network"][0]["artifact_id"] = snapshot_data["processes"][0]["artifact_id"]
    with pytest.raises(ValidationError, match="artifact.*unique"):
        validate(snapshot_data)


def test_duplicate_process_pids_rejected(snapshot_data):
    second = deepcopy(snapshot_data["processes"][0])
    second["artifact_id"] = str(UUID(int=99))
    snapshot_data["processes"].append(second)
    snapshot_data["collector_runs"][1]["item_count"] = 2
    with pytest.raises(ValidationError, match="PID"):
        validate(snapshot_data)


@pytest.mark.parametrize("change", ["missing", "duplicate", "count", "wrong_collector", "empty_failed"])
def test_collection_coverage_cannot_be_misrepresented(snapshot_data, change):
    if change == "missing":
        snapshot_data["collector_runs"].pop()
    elif change == "duplicate":
        snapshot_data["collector_runs"].append(deepcopy(snapshot_data["collector_runs"][0]))
    elif change == "count":
        snapshot_data["collector_runs"][1]["item_count"] = 0
    elif change == "wrong_collector":
        snapshot_data["processes"][0]["collector"] = "network"
    else:
        snapshot_data["collector_runs"][1]["status"] = "failed"
    with pytest.raises(ValidationError):
        validate(snapshot_data)


def test_partial_collection_preserves_field_issue(snapshot_data):
    snapshot_data["processes"][0]["command_line"] = None
    run = snapshot_data["collector_runs"][1]
    run["status"] = "partial"
    run["issues"] = [{"collector": "processes", "category": "access_denied",
                      "message": "Command line access denied", "observed_at": run["finished_at"],
                      "artifact_id": snapshot_data["processes"][0]["artifact_id"], "field": "command_line"}]
    assert validate(snapshot_data).collector_runs[1].issues[0].field == "command_line"
    run["status"] = "ok"
    with pytest.raises(ValidationError):
        validate(snapshot_data)


SYSTEM_INFO_FIELDS = (
    "hostname", "windows_version", "architecture", "current_time", "boot_time",
    "collector_username", "collector_sid", "elevated",
)


def system_run(snapshot_data):
    return next(run for run in snapshot_data["collector_runs"] if run["collector"] == "system")


def system_issue(snapshot_data, field, *, artifact_id=None):
    run = system_run(snapshot_data)
    return {
        "collector": "system",
        "category": "unavailable",
        "message": f"{field} was unavailable",
        "observed_at": run["finished_at"],
        "artifact_id": artifact_id,
        "field": field,
    }


@pytest.mark.parametrize("field", SYSTEM_INFO_FIELDS)
def test_each_null_system_field_requires_a_matching_issue(snapshot_data, field):
    snapshot_data["system"][field] = None
    run = system_run(snapshot_data)
    run["status"] = "partial"
    run["issues"] = [system_issue(
        snapshot_data,
        "unexpected_field",
        artifact_id=snapshot_data["system"]["artifact_id"],
    )]
    with pytest.raises(ValidationError):
        validate(snapshot_data)


def test_system_field_issue_must_reference_the_system_artifact(snapshot_data):
    snapshot_data["system"]["hostname"] = None
    run = system_run(snapshot_data)
    run["status"] = "partial"
    run["issues"] = [system_issue(snapshot_data, "hostname")]
    with pytest.raises(ValidationError):
        validate(snapshot_data)


def test_partial_system_accepts_issues_for_each_unavailable_field(snapshot_data):
    missing = ("architecture", "collector_sid", "elevated")
    for field in missing:
        snapshot_data["system"][field] = None
    run = system_run(snapshot_data)
    run["status"] = "partial"
    run["issues"] = [
        system_issue(snapshot_data, field, artifact_id=snapshot_data["system"]["artifact_id"])
        for field in missing
    ]
    result = validate(snapshot_data)
    collected_run = next(run for run in result.collector_runs if run.collector == "system")
    assert {issue.field for issue in collected_run.issues} == set(missing)


@pytest.mark.parametrize("status", ["ok", "partial"])
def test_absent_system_cannot_claim_success_or_partial_coverage(snapshot_data, status):
    snapshot_data["system"] = None
    run = system_run(snapshot_data)
    run["status"] = status
    run["item_count"] = 0
    if status == "partial":
        run["issues"] = [system_issue(snapshot_data, "hostname")]
    with pytest.raises(ValidationError):
        validate(snapshot_data)


@pytest.mark.parametrize("status", ["failed", "skipped"])
def test_absent_system_is_valid_for_failed_or_skipped_collection(snapshot_data, status):
    snapshot_data["system"] = None
    run = system_run(snapshot_data)
    run["status"] = status
    run["item_count"] = 0
    run["issues"] = [{
        "collector": "system",
        "category": "unavailable",
        "message": "System inventory was unavailable",
        "observed_at": run["finished_at"],
    }]
    assert validate(snapshot_data).system is None


@pytest.mark.parametrize("kind", ["interval", "collector_interval", "observed", "creation", "boot"])
def test_inconsistent_times_rejected(snapshot_data, kind):
    if kind == "interval":
        snapshot_data["finished_at"] = "2026-09-17T14:04:00Z"
    elif kind == "collector_interval":
        snapshot_data["collector_runs"][1]["started_at"] = "2026-09-17T14:06:00Z"
    elif kind == "observed":
        snapshot_data["processes"][0]["observed_at"] = "2026-09-17T14:06:00Z"
    elif kind == "creation":
        snapshot_data["processes"][0]["created_at"] = "2026-09-17T14:06:00Z"
    else:
        snapshot_data["system"]["boot_time"] = "2026-09-17T14:06:00Z"
    with pytest.raises(ValidationError):
        validate(snapshot_data)


@pytest.mark.parametrize("target", [str(UUID(int=999)), str(UUID(int=2))])
def test_persistence_source_must_exist_and_match_kind(snapshot_data, target):
    snapshot_data["persistence"][0]["source_artifact_id"] = target
    with pytest.raises(ValidationError):
        validate(snapshot_data)


def test_task_reference_requires_valid_action_index(snapshot_data):
    entry = snapshot_data["persistence"][0]
    entry.update(kind="scheduled_task", source_artifact_id=str(UUID(int=6)), action_index=0)
    assert validate(snapshot_data).persistence[0].action_index == 0
    entry["action_index"] = 1
    with pytest.raises(ValidationError):
        validate(snapshot_data)


def test_generic_collector_result_rejects_incorrect_count(snapshot_data):
    from irsnapshot.models import CollectorResult, ProcessArtifact

    run = snapshot_data["collector_runs"][1]
    result = CollectorResult[ProcessArtifact](items=snapshot_data["processes"], run=run)
    assert result.items[0].pid == 400
    with pytest.raises(ValidationError):
        CollectorResult[ProcessArtifact](items=[], run=run)


def test_boolean_fields_do_not_coerce_strings(snapshot_data):
    snapshot_data["system"]["elevated"] = "false"
    with pytest.raises(ValidationError):
        validate(snapshot_data)


def test_collection_lists_are_not_shared(snapshot_data):
    from irsnapshot.models import PathContext

    first, second = PathContext(), PathContext()
    first.environment.append(validate(snapshot_data).path_context.environment[0])
    assert second.environment == []


def test_findings_require_evidence_and_referenced_artifacts():
    from irsnapshot.models import Finding

    with pytest.raises(ValidationError):
        Finding(finding_id=UUID(int=20), rule_id="IRS-P001", title="Review",
                severity="medium", description="Why this needs review")


def test_severity_has_analyst_order():
    from irsnapshot.severity import Severity

    values = [Severity.HIGH, Severity.LOW, Severity.CRITICAL, Severity.INFORMATIONAL, Severity.MEDIUM]
    assert [v.value for v in sorted(values, key=lambda v: v.rank)] == [
        "informational", "low", "medium", "high", "critical"]


def report_data(snapshot_data):
    return {"snapshot": snapshot_data, "analysis": {
        "snapshot_id": snapshot_data["snapshot_id"], "ruleset_version": "1.0",
        "complete": True, "process_tree": {"nodes": [{
            "process_id": str(UUID(int=2)), "parent_status": "missing"}], "root_ids": [str(UUID(int=2))]}}}


def test_report_enforces_matching_snapshot_and_references(snapshot_data):
    from irsnapshot.models import InvestigationReport

    data = report_data(snapshot_data)
    assert InvestigationReport.model_validate(data).analysis.findings == []
    data["analysis"]["snapshot_id"] = str(UUID(int=999))
    with pytest.raises(ValidationError):
        InvestigationReport.model_validate(data)


def test_report_rejects_dangling_finding_evidence(snapshot_data):
    from irsnapshot.models import InvestigationReport

    data = report_data(snapshot_data)
    data["analysis"]["findings"] = [{"finding_id": str(UUID(int=20)), "rule_id": "TEST-001",
        "title": "Synthetic", "severity": "low", "description": "Fixture review reason",
        "artifact_ids": [str(UUID(int=999))], "pids": [], "evidence": [{
            "artifact_id": str(UUID(int=999)), "field": "name", "value": "unknown",
            "explanation": "Synthetic evidence"}]}]
    with pytest.raises(ValidationError):
        InvestigationReport.model_validate(data)


def test_complete_analysis_cannot_hide_issues(snapshot_data):
    from irsnapshot.models import InvestigationReport

    data = report_data(snapshot_data)
    data["analysis"]["issues"] = [{"component": "rule engine", "message": "Rule failed"}]
    with pytest.raises(ValidationError):
        InvestigationReport.model_validate(data)


def test_schema_export_contains_artifact_contract():
    from irsnapshot.models import SystemSnapshot

    schema = SystemSnapshot.model_json_schema()
    assert schema["additionalProperties"] is False
    assert schema["$defs"]["ProcessArtifact"]["properties"]["pid"]["minimum"] == 0
