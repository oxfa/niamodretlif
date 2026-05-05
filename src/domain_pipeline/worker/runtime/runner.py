"""Worker workflow-step execution owner."""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from domain_pipeline.prepare.worker_manifest import (
    load_prepare_worker_manifest_for_worker,
)
from domain_pipeline.worker.runtime.executor import run_prepared_pipeline_async
from domain_pipeline.worker.status.lifecycle import (
    STATUS_FAILURE,
    STATUS_SUCCESS,
    WorkerStatusLifecycle,
)
from domain_pipeline.worker.status.store import WorkerStatusStore

log = logging.getLogger(__name__)


def run_prepared_pipeline(
    runtime_config: dict[str, Any],
    *,
    runtime_identity: dict[str, str],
    max_runtime_seconds: float | None = None,
    prepared_metadata: dict[str, Any] | None = None,
) -> int:
    """Run one workflow-owned runtime payload from a prepared pipeline-run manifest."""
    try:
        return asyncio.run(
            run_prepared_pipeline_async(
                runtime_config,
                runtime_identity=runtime_identity,
                max_runtime_seconds=max_runtime_seconds,
                prepared_metadata=prepared_metadata,
            )
        )
    except ValueError as exc:
        log.error("%s", exc)
        return 2


class WorkerBatchRunner:
    """Run one prepared worker manifest and return the workflow payload."""

    def __init__(
        self,
        *,
        status_store: WorkerStatusStore | None = None,
        status_lifecycle: WorkerStatusLifecycle | None = None,
    ) -> None:
        self.status_store = status_store or WorkerStatusStore()
        self.status_lifecycle = status_lifecycle or WorkerStatusLifecycle(
            store=self.status_store
        )

    def run(
        self,
        *,
        batch_id: str,
        worker_id: str,
        source_root: Path,
        state_root: Path,
        max_runtime_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Process one worker from its prepare-owned runtime manifest."""
        prepare_manifest = load_prepare_worker_manifest_for_worker(
            batch_id=batch_id,
            worker_id=worker_id,
            state_root=state_root,
        )
        if prepare_manifest is None:
            return {
                "automation_format_version": 2,
                "batch_id": batch_id,
                "worker_id": worker_id,
                "participates": False,
                "overall_conclusion": "skipped",
            }

        status_path = self.status_store.status_path(
            batch_id=batch_id,
            worker_id=worker_id,
            state_root=state_root,
        )
        if not status_path.exists():
            self.status_lifecycle.initialize(
                batch_id=batch_id,
                worker_id=worker_id,
                state_root=state_root,
            )
        overall_conclusion = STATUS_SUCCESS
        worker_paths = prepare_manifest.resolve_paths(state_root)
        result_root = worker_paths["result_root"]
        log_path = prepare_manifest.resolve_log_path(state_root)
        self._clear_worker_runtime_outputs(
            worker_paths=worker_paths,
        )
        error_reason: str | None = None
        conclusion = STATUS_SUCCESS
        try:
            with self._capture_root_logs_to_file(log_path), self._pushd(result_root):
                run_payload = prepare_manifest.runtime_spec.to_runtime_payload(
                    source_root=source_root,
                    state_root=state_root,
                )
                exit_code = run_prepared_pipeline(
                    run_payload,
                    runtime_identity=prepare_manifest.runtime_spec.config_identity.model_dump(
                        mode="json"
                    ),
                    max_runtime_seconds=max_runtime_seconds,
                    prepared_metadata=prepare_manifest.prepared_metadata.to_runtime_payload(),
                )
            if exit_code != 0:
                raise RuntimeError(f"pipeline exited with status {exit_code}")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            overall_conclusion = STATUS_FAILURE
            conclusion = STATUS_FAILURE
            error_reason = str(exc)
            logging.getLogger(__name__).exception("Worker %s failed", worker_id)
        return {
            "automation_format_version": 2,
            "batch_id": batch_id,
            "worker_id": worker_id,
            "participates": True,
            "overall_conclusion": overall_conclusion,
            "conclusion": conclusion,
            "error_reason": error_reason,
            "status_path": self.status_store.status_relative_path(
                batch_id=batch_id, worker_id=worker_id
            ),
        }

    @contextmanager
    def _pushd(self, path: Path) -> Iterator[None]:
        original = Path.cwd()
        path.mkdir(parents=True, exist_ok=True)
        os.chdir(path)
        try:
            yield
        finally:
            os.chdir(original)

    def _clear_worker_runtime_outputs(
        self,
        *,
        worker_paths: dict[str, Path],
    ) -> None:
        """Remove stale worker-local sidecars while keeping the handoff stub."""
        cleanup_paths = [
            worker_paths["filtered"].parent.parent,
            worker_paths["terminal_rows"].parent,
            worker_paths["cache"].parent,
        ]
        for cleanup_path in cleanup_paths:
            if cleanup_path.exists():
                shutil.rmtree(cleanup_path)

    @contextmanager
    def _capture_root_logs_to_file(self, log_path: Path) -> Iterator[None]:
        """Mirror root-logger output into one worker log file during execution."""
        log_path.parent.mkdir(parents=True, exist_ok=True)
        root_logger = logging.getLogger()
        file_handler = logging.FileHandler(log_path, mode="w", encoding="utf-8")
        if root_logger.handlers:
            template_handler = root_logger.handlers[0]
            file_handler.setLevel(template_handler.level)
            if template_handler.formatter is not None:
                file_handler.setFormatter(template_handler.formatter)
        else:
            file_handler.setLevel(root_logger.level)
            file_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )
        root_logger.addHandler(file_handler)
        try:
            yield
        finally:
            file_handler.flush()
            root_logger.removeHandler(file_handler)
            file_handler.close()


def run_worker(
    *,
    batch_id: str,
    worker_id: str,
    source_root: Path,
    state_root: Path,
    max_runtime_seconds: float | None = None,
) -> dict[str, Any]:
    """Run one prepared worker from the workflow command layer."""
    return WorkerBatchRunner().run(
        batch_id=batch_id,
        worker_id=worker_id,
        source_root=source_root,
        state_root=state_root,
        max_runtime_seconds=max_runtime_seconds,
    )
