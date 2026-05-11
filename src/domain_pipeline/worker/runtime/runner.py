"""Worker workflow-step execution owner."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import os
import shutil
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from domain_pipeline.prepare.prepare_to_worker_manifest import (
    load_prepare_worker_manifest_for_worker,
)
from domain_pipeline.worker.ip_location.providers import FatalIPLocationCredentialError
from domain_pipeline.worker.runtime.executor import run_prepared_pipeline_async
from domain_pipeline.worker.status.lifecycle import (
    STATUS_FAILURE,
    STATUS_SUCCESS,
    WorkerStatusLifecycle,
    WorkerStatusFailureRequest,
    WorkerStatusIdentity,
)
from domain_pipeline.worker.status.store import WorkerStatusStore

log = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class WorkerRunRequest:
    """Inputs needed to run one prepared worker manifest."""

    batch_id: str
    worker_id: str
    source_root: Path
    state_root: Path
    max_runtime_seconds: float | None = None


@dataclasses.dataclass(frozen=True)
class WorkerRunOutcome:
    """Runtime conclusion fields for one worker execution."""

    overall_conclusion: str
    conclusion: str
    error_reason: str | None


class WorkerRuntimeExecutionError(RuntimeError):
    """Raised for expected worker runtime execution failures."""


def run_prepared_pipeline(
    runtime_config: dict[str, Any],
    *,
    max_runtime_seconds: float | None = None,
    prepared_metadata: dict[str, Any] | None = None,
) -> int:
    """Run one workflow-owned runtime payload from a prepared pipeline-run manifest."""
    try:
        return asyncio.run(
            run_prepared_pipeline_async(
                runtime_config,
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

    def run(self, request: WorkerRunRequest) -> dict[str, Any]:
        """Process one worker from its prepare-owned runtime manifest."""
        try:
            prepare_manifest = load_prepare_worker_manifest_for_worker(
                batch_id=request.batch_id,
                worker_id=request.worker_id,
                state_root=request.state_root,
            )
        except ValueError as exc:
            error_reason = str(exc)
            status_path = self.status_lifecycle.record_failure(
                WorkerStatusFailureRequest(
                    identity=WorkerStatusIdentity(
                        request.batch_id,
                        request.worker_id,
                        request.state_root,
                    ),
                    failure_reason=error_reason,
                )
            )
            log.exception("Worker %s manifest validation failed", request.worker_id)
            return {
                "automation_format_version": 2,
                "batch_id": request.batch_id,
                "worker_id": request.worker_id,
                "participates": True,
                "overall_conclusion": STATUS_FAILURE,
                "conclusion": STATUS_FAILURE,
                "error_reason": error_reason,
                "status_path": status_path,
            }
        if prepare_manifest is None:
            return {
                "automation_format_version": 2,
                "batch_id": request.batch_id,
                "worker_id": request.worker_id,
                "participates": False,
                "overall_conclusion": "skipped",
            }
        return self.run_manifest(request, prepare_manifest)

    def run_manifest(
        self, request: WorkerRunRequest, prepare_manifest: Any
    ) -> dict[str, Any]:
        """Run one already-loaded worker manifest."""
        status_path = self.status_store.status_path(
            batch_id=request.batch_id,
            worker_id=request.worker_id,
            state_root=request.state_root,
        )
        if not status_path.exists():
            self.status_lifecycle.initialize(
                batch_id=request.batch_id,
                worker_id=request.worker_id,
                state_root=request.state_root,
            )
        worker_paths = prepare_manifest.resolve_paths(request.state_root)
        result_root = worker_paths["result_root"]
        log_path = prepare_manifest.resolve_log_path(request.state_root)
        self._clear_worker_runtime_outputs(
            worker_paths=worker_paths,
        )
        outcome = self._run_manifest_payload(
            request=request,
            prepare_manifest=prepare_manifest,
            result_root=result_root,
            log_path=log_path,
        )
        return {
            "automation_format_version": 2,
            "batch_id": request.batch_id,
            "worker_id": request.worker_id,
            "participates": True,
            "overall_conclusion": outcome.overall_conclusion,
            "conclusion": outcome.conclusion,
            "error_reason": outcome.error_reason,
            "status_path": self.status_store.status_relative_path(
                batch_id=request.batch_id, worker_id=request.worker_id
            ),
        }

    def _run_manifest_payload(
        self,
        *,
        request: WorkerRunRequest,
        prepare_manifest: Any,
        result_root: Path,
        log_path: Path,
    ) -> WorkerRunOutcome:
        overall_conclusion = STATUS_SUCCESS
        error_reason: str | None = None
        conclusion = STATUS_SUCCESS
        try:
            with self._capture_root_logs_to_file(log_path), self._pushd(result_root):
                self._execute_manifest_runtime(
                    request=request,
                    prepare_manifest=prepare_manifest,
                )
        except WorkerRuntimeExecutionError as exc:
            overall_conclusion = STATUS_FAILURE
            conclusion = STATUS_FAILURE
            error_reason = str(exc)
            logging.getLogger(__name__).exception("Worker %s failed", request.worker_id)
        return WorkerRunOutcome(
            overall_conclusion=overall_conclusion,
            conclusion=conclusion,
            error_reason=error_reason,
        )

    def _execute_manifest_runtime(
        self,
        *,
        request: WorkerRunRequest,
        prepare_manifest: Any,
    ) -> None:
        """Run one manifest payload and surface expected runtime failures."""
        try:
            run_payload = prepare_manifest.runtime_spec.to_runtime_payload(
                source_root=request.source_root,
                state_root=request.state_root,
            )
        except ValueError as exc:
            raise WorkerRuntimeExecutionError(str(exc)) from exc
        try:
            exit_code = run_prepared_pipeline(
                run_payload,
                max_runtime_seconds=request.max_runtime_seconds,
                prepared_metadata=prepare_manifest.prepared_metadata.to_runtime_payload(),
            )
        except FatalIPLocationCredentialError as exc:
            raise WorkerRuntimeExecutionError(str(exc)) from exc
        except asyncio.TimeoutError as exc:
            max_runtime = request.max_runtime_seconds
            reason = "pipeline exceeded max runtime seconds"
            if max_runtime is not None:
                reason = f"{reason}: {max_runtime}"
            raise WorkerRuntimeExecutionError(reason) from exc
        if exit_code != 0:
            raise WorkerRuntimeExecutionError(
                f"pipeline exited with status {exit_code}"
            )

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
        WorkerRunRequest(
            batch_id=batch_id,
            worker_id=worker_id,
            source_root=source_root,
            state_root=state_root,
            max_runtime_seconds=max_runtime_seconds,
        )
    )
