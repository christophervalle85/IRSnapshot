"""Explicit opt-in smoke test against the current Windows endpoint."""
import struct
import sys

import pytest

from irsnapshot.models import CollectorName, SystemSnapshot
from irsnapshot.pipeline import collect_snapshot
from irsnapshot.storage import load_snapshot, write_snapshot


@pytest.mark.windows_live
@pytest.mark.skipif(sys.platform != "win32" or struct.calcsize("P") != 8,
                    reason="live collection requires 64-bit Windows")
def test_live_read_only_snapshot_round_trip(tmp_path):
    snapshot = collect_snapshot()
    validated = SystemSnapshot.model_validate(snapshot)
    assert {run.collector for run in validated.collector_runs} == set(CollectorName)
    assert len(validated.collector_runs) == 7
    assert validated.system is not None and validated.system.hostname
    assert validated.processes
    destination = tmp_path / "live.snapshot.json"
    write_snapshot(validated, destination)
    assert load_snapshot(destination).snapshot_id == validated.snapshot_id
