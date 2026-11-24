"""Shared test fixtures for worker artifact correlation."""

from collections.abc import Callable
from pathlib import Path

import pytest


@pytest.fixture
def correlation_args(tmp_path: Path) -> Callable[[str], list[str]]:
    """Build command arguments for a worker artifact correlation test."""

    def build(worker_ids_json: str) -> list[str]:
        return [
            "worker_artifact_correlation.py",
            "--api-url",
            "https://api.github.com",
            "--repository",
            "oxfa/niamodretlif",
            "--run-id",
            "123",
            "--batch-id",
            "batch-123-attempt-1",
            "--worker-ids-json",
            worker_ids_json,
            "--destination",
            str(tmp_path),
        ]

    return build
