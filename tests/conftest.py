"""Independent synthetic evidence shared by contract tests."""

import json
from pathlib import Path

import pytest


@pytest.fixture
def snapshot_data():
    path = Path(__file__).resolve().parents[1] / "samples" / "benign.snapshot.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def process_factory():
    from datetime import UTC, datetime
    from uuid import UUID
    from irsnapshot.models import ProcessArtifact

    def make(pid, ppid=None, name=None, created_at=datetime(2026, 9, 17, 14, tzinfo=UTC), **kwargs):
        return ProcessArtifact(
            artifact_id=UUID(int=1000 + pid), pid=pid, ppid=ppid, name=name,
            observed_at=datetime(2026, 9, 17, 14, 5, tzinfo=UTC),
            created_at=created_at, **kwargs,
        )
    return make
