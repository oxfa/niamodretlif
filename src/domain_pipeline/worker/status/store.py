"""Worker-status JSON persistence owner."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from domain_pipeline.paths.layout import PathLayout, WorkflowPathLayout
from domain_pipeline.prepare.assignment import relative_path


def _relative_workflow_paths() -> WorkflowPathLayout:
    """Return repo-relative workflow path ownership."""
    return PathLayout(Path(".")).workflow


class WorkerStatusStore:
    """Read and write worker status JSON through workflow paths."""

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

    def read_status(self, path: Path) -> dict[str, Any]:
        """Read one worker status JSON object."""
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"status file {path} must contain a JSON object")
        return payload

    def write_status(self, path: Path, payload: dict[str, Any]) -> None:
        """Write one worker status JSON object."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
