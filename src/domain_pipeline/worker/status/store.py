"""Worker-status YAML persistence owner."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from domain_pipeline.handoff_io import read_yaml, write_yaml

from domain_pipeline.paths.layout import PathLayout, WorkflowStatePathLayout
from domain_pipeline.prepare.assignment import relative_path


def _relative_workflow_paths() -> WorkflowStatePathLayout:
    """Return repo-relative workflow path ownership."""
    return PathLayout(Path(".")).workflow_state


class WorkerStatusStore:
    """Read and write worker status YAML through workflow paths."""

    def status_path(
        self,
        *,
        batch_id: str,
        worker_id: str,
        state_root: Path,
    ) -> Path:
        """Return the resolved status path for one worker."""
        return state_root / _relative_workflow_paths().worker_status_path(
            batch_id=batch_id,
            worker_id=worker_id,
        ).relative_to(Path("."))

    def status_relative_path(self, *, batch_id: str, worker_id: str) -> str:
        """Return the repo-relative status path for one worker."""
        return relative_path(
            _relative_workflow_paths()
            .worker_status_path(
                batch_id=batch_id,
                worker_id=worker_id,
            )
            .relative_to(Path("."))
        )

    def read_status(
        self, path: Path, *, batch_id: str, worker_id: str
    ) -> dict[str, Any]:
        """Read one worker status object and require its requested identity."""
        payload = read_yaml(path)
        if not isinstance(payload, dict):
            raise ValueError(f"status file {path} must contain a YAML mapping")
        expected_fields = {
            "batch_id",
            "worker_id",
            "conclusion",
            "commit_sha_produced",
            "timestamps",
            "retry_count",
            "failure_reason",
        }
        if set(payload) != expected_fields:
            raise ValueError(f"invalid worker status fields in {path}")
        if not isinstance(payload["batch_id"], str) or not isinstance(
            payload["worker_id"], str
        ):
            raise ValueError(f"invalid worker status identity fields in {path}")
        if payload["conclusion"] not in {"in_progress", "success", "failure"}:
            raise ValueError(f"unsupported worker status conclusion in {path}")
        if payload.get("batch_id") != batch_id or payload.get("worker_id") != worker_id:
            raise ValueError(f"worker status identity mismatch: {path}")
        if not isinstance(payload["commit_sha_produced"], str):
            raise ValueError(f"invalid worker status commit SHA in {path}")
        retry_count = payload["retry_count"]
        if not isinstance(retry_count, int) or isinstance(retry_count, bool) or retry_count < 0:
            raise ValueError(f"invalid worker status retry count in {path}")
        if payload["failure_reason"] is not None and not isinstance(
            payload["failure_reason"], str
        ):
            raise ValueError(f"invalid worker status failure reason in {path}")
        timestamps = payload["timestamps"]
        if not isinstance(timestamps, dict) or set(timestamps) != {
            "started_at",
            "finished_at",
        }:
            raise ValueError(f"invalid worker status timestamps in {path}")
        if not isinstance(timestamps["started_at"], str) or not timestamps[
            "started_at"
        ]:
            raise ValueError(f"invalid worker status start time in {path}")
        finished_at = timestamps["finished_at"]
        if finished_at is not None and not isinstance(finished_at, str):
            raise ValueError(f"invalid worker status finish time in {path}")
        conclusion = payload["conclusion"]
        if conclusion == "in_progress":
            if finished_at is not None or payload["failure_reason"] is not None:
                raise ValueError(f"invalid in-progress worker status in {path}")
        elif not isinstance(finished_at, str) or not finished_at:
            raise ValueError(f"terminal worker status is missing finish time in {path}")
        elif conclusion == "success" and payload["failure_reason"] is not None:
            raise ValueError(f"successful worker status carries a failure in {path}")
        elif conclusion == "failure" and not payload["failure_reason"]:
            raise ValueError(f"failed worker status is missing its reason in {path}")
        return payload

    def write_status(self, path: Path, payload: dict[str, Any]) -> None:
        """Write one worker status YAML object."""
        path.parent.mkdir(parents=True, exist_ok=True)
        write_yaml(path, payload)
