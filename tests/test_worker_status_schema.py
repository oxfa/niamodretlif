"""Focused validation for exact worker status and identity fields."""

from __future__ import annotations

from pathlib import Path

import pytest

from domain_pipeline.handoff_io import write_yaml
from domain_pipeline.worker.status.store import WorkerStatusStore


def _status_payload() -> dict[str, object]:
    return {
        "batch_id": "batch-1",
        "worker_id": "worker-1",
        "conclusion": "success",
        "commit_sha_produced": "",
        "timestamps": {
            "started_at": "2026-11-25T00:00:00Z",
            "finished_at": "2026-11-25T00:00:01Z",
        },
        "retry_count": 0,
        "failure_reason": None,
    }


def _write_status(tmp_path: Path, value: dict[str, object]) -> Path:
    path = tmp_path / "status.yaml"
    write_yaml(path, value)
    return path


def test_worker_status_accepts_exact_terminal_shape(tmp_path: Path) -> None:
    path = _write_status(tmp_path, _status_payload())

    payload = WorkerStatusStore().read_status(
        path, batch_id="batch-1", worker_id="worker-1"
    )

    assert payload["conclusion"] == "success"


def test_worker_status_rejects_unknown_fields(tmp_path: Path) -> None:
    payload = _status_payload()
    payload["source_id"] = "source"
    path = _write_status(tmp_path, payload)

    with pytest.raises(ValueError, match="invalid worker status fields"):
        WorkerStatusStore().read_status(
            path, batch_id="batch-1", worker_id="worker-1"
        )


def test_worker_status_rejects_identity_mismatch(tmp_path: Path) -> None:
    path = _write_status(tmp_path, _status_payload())

    with pytest.raises(ValueError, match="identity mismatch"):
        WorkerStatusStore().read_status(
            path, batch_id="batch-1", worker_id="worker-2"
        )
