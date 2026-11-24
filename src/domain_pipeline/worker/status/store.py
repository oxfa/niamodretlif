"""Worker-status YAML persistence owner."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from domain_pipeline.handoff_io import read_yaml, write_yaml
from domain_pipeline.pipeline_run.format_version import PIPELINE_RUN_FORMAT_VERSION

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
        version = payload.get("automation_format_version")
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version != PIPELINE_RUN_FORMAT_VERSION
        ):
            raise ValueError(f"unsupported worker status format version in {path}")
        if payload.get("conclusion") not in {"in_progress", "success", "failure"}:
            raise ValueError(f"unsupported worker status conclusion in {path}")
        if payload.get("batch_id") != batch_id or payload.get("worker_id") != worker_id:
            raise ValueError(f"worker status identity mismatch: {path}")
        return payload

    def write_status(self, path: Path, payload: dict[str, Any]) -> None:
        """Write one worker status YAML object."""
        path.parent.mkdir(parents=True, exist_ok=True)
        write_yaml(path, payload)
