"""Exercise real files and publication races without endpoint collection."""

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from pydantic import ValidationError


def snapshot(data):
    from irsnapshot.models import SystemSnapshot

    return SystemSnapshot.model_validate(data)


def test_round_trip_preserves_unicode_and_original(snapshot_data, tmp_path):
    from irsnapshot.storage import load_snapshot, write_snapshot

    snapshot_data["system"]["hostname"] = "实验-LAB"
    original = snapshot(snapshot_data)
    path = tmp_path / "snapshot.json"
    write_snapshot(original, path)
    assert load_snapshot(path) == original
    assert "实验-LAB" in path.read_text(encoding="utf-8")
    assert path.read_bytes().endswith(b"\n")


@pytest.mark.parametrize("bad", ["{", "[]", "null", '{"schema_version":"9.0"}',
                                 '{"schema_version":"1.0","schema_version":"9.0"}'])
def test_malformed_or_ambiguous_json_rejected(tmp_path, bad):
    from irsnapshot.storage import SnapshotValidationError, load_snapshot

    path = tmp_path / "bad.json"
    path.write_text(bad, encoding="utf-8")
    with pytest.raises(SnapshotValidationError):
        load_snapshot(path)


def test_missing_schema_is_not_assumed(snapshot_data, tmp_path):
    from irsnapshot.storage import SnapshotValidationError, load_snapshot

    del snapshot_data["schema_version"]
    path = tmp_path / "unversioned.json"
    path.write_text(json.dumps(snapshot_data), encoding="utf-8")
    with pytest.raises(SnapshotValidationError, match="schema_version"):
        load_snapshot(path)


def test_nested_duplicate_keys_rejected(snapshot_data, tmp_path):
    from irsnapshot.storage import SnapshotValidationError, load_snapshot

    content = json.dumps(snapshot_data).replace('"pid": 400', '"pid": 0, "pid": 400')
    path = tmp_path / "duplicate.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(SnapshotValidationError, match="Duplicate"):
        load_snapshot(path)


def test_json_integer_limit_error_is_normalized_without_leaking_input(tmp_path):
    from irsnapshot.storage import SnapshotValidationError, load_snapshot

    huge_integer = "9" * 5000
    path = tmp_path / "huge-integer.json"
    path.write_text(
        '{"schema_version":"1.0","big":' + huge_integer + "}",
        encoding="utf-8",
    )
    with pytest.raises(SnapshotValidationError) as error:
        load_snapshot(path)
    assert "9" * 20 not in str(error.value)


def test_invalid_utf8_rejected(tmp_path):
    from irsnapshot.storage import SnapshotValidationError, load_snapshot

    path = tmp_path / "invalid.json"
    path.write_bytes(b"\xff\xfe")
    with pytest.raises(SnapshotValidationError):
        load_snapshot(path)


def test_error_message_does_not_echo_sensitive_evidence(snapshot_data, tmp_path):
    from irsnapshot.storage import SnapshotValidationError, load_snapshot

    snapshot_data["processes"][0]["pid"] = "SECRET_TOKEN_123"
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(snapshot_data), encoding="utf-8")
    with pytest.raises(SnapshotValidationError) as error:
        load_snapshot(path)
    assert "SECRET_TOKEN_123" not in str(error.value)
    assert "pid" in str(error.value)


def test_existing_output_unchanged_unless_explicitly_overwritten(snapshot_data, tmp_path):
    from irsnapshot.storage import load_snapshot, write_snapshot

    path = tmp_path / "snapshot.json"
    path.write_bytes(b"original evidence")
    with pytest.raises(FileExistsError):
        write_snapshot(snapshot(snapshot_data), path)
    assert path.read_bytes() == b"original evidence"
    assert list(tmp_path.iterdir()) == [path]
    write_snapshot(snapshot(snapshot_data), path, overwrite=True)
    assert load_snapshot(path).snapshot_id == snapshot(snapshot_data).snapshot_id


def test_competing_writers_publish_exactly_one_complete_snapshot(snapshot_data, tmp_path):
    from irsnapshot.storage import load_snapshot, write_snapshot

    path = tmp_path / "contended.json"
    original = snapshot(snapshot_data)

    def publish(_):
        try:
            write_snapshot(original, path)
            return "published"
        except FileExistsError:
            return "exists"

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(publish, range(8)))
    assert results.count("published") == 1
    assert results.count("exists") == 7
    assert load_snapshot(path) == original
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("overwrite", [False, True])
def test_failed_publication_preserves_destination_and_cleans_temp(snapshot_data, tmp_path, monkeypatch, overwrite):
    from irsnapshot import storage

    path = tmp_path / "snapshot.json"
    if overwrite:
        path.write_bytes(b"original evidence")

    def fail_publish(*args, **kwargs):
        raise PermissionError("simulated publication failure")

    monkeypatch.setattr(storage.os, "replace" if overwrite else "link", fail_publish)
    with pytest.raises(PermissionError, match="publication"):
        storage.write_snapshot(snapshot(snapshot_data), path, overwrite=overwrite)
    if overwrite:
        assert path.read_bytes() == b"original evidence"
        assert list(tmp_path.iterdir()) == [path]
    else:
        assert list(tmp_path.iterdir()) == []


def test_failed_fsync_never_publishes_partial_file(snapshot_data, tmp_path, monkeypatch):
    from irsnapshot import storage

    def disk_full(_):
        raise OSError("simulated full disk")

    monkeypatch.setattr(storage.os, "fsync", disk_full)
    with pytest.raises(OSError, match="full disk"):
        storage.write_snapshot(snapshot(snapshot_data), tmp_path / "snapshot.json")
    assert list(tmp_path.iterdir()) == []


def test_mutated_models_revalidated_before_write(snapshot_data, tmp_path):
    from irsnapshot.storage import write_snapshot

    invalid = snapshot(snapshot_data)
    invalid.processes[0].pid = -1
    with pytest.raises(ValidationError):
        write_snapshot(invalid, tmp_path / "snapshot.json")
    assert list(tmp_path.iterdir()) == []


def test_missing_input_and_output_directory_raise_io_errors(snapshot_data, tmp_path):
    from irsnapshot.storage import load_snapshot, write_snapshot

    with pytest.raises(FileNotFoundError):
        load_snapshot(tmp_path / "missing.json")
    with pytest.raises(FileNotFoundError):
        write_snapshot(snapshot(snapshot_data), tmp_path / "missing" / "snapshot.json")


def test_size_limit_applies_to_read_and_write(snapshot_data, tmp_path, monkeypatch):
    from irsnapshot import storage

    path = tmp_path / "large.json"
    path.write_text(json.dumps(snapshot_data), encoding="utf-8")
    original = path.read_bytes()
    monkeypatch.setattr(storage, "MAX_SNAPSHOT_BYTES", 16)
    with pytest.raises(storage.SnapshotValidationError, match="size"):
        storage.load_snapshot(path)
    with pytest.raises(storage.SnapshotValidationError, match="size"):
        storage.write_snapshot(snapshot(snapshot_data), path, overwrite=True)
    assert path.read_bytes() == original


def test_no_clobber_does_not_follow_existing_symlink(snapshot_data, tmp_path):
    from irsnapshot.storage import write_snapshot

    real = tmp_path / "real.json"
    real.write_bytes(b"original evidence")
    alias = tmp_path / "alias.json"
    try:
        alias.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable in this test environment")
    with pytest.raises(FileExistsError):
        write_snapshot(snapshot(snapshot_data), alias)
    assert real.read_bytes() == b"original evidence"
    assert alias.is_symlink()
