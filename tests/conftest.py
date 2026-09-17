"""Independent synthetic evidence shared by contract tests."""

import json
from pathlib import Path

import pytest


@pytest.fixture
def snapshot_data():
    path = Path(__file__).resolve().parents[1] / "samples" / "benign.snapshot.json"
    return json.loads(path.read_text(encoding="utf-8"))
