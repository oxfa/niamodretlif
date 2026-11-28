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
    PreparedRuntimeMetadata,
    PrepareWorkerManifest,
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
    error_reason: str | None
    status_recording_error: str | None = None


class WorkerRuntimeExecutionError(RuntimeError):
    """Raised for expected worker runtime execution failures."""


def run_prepared_pipeline(
    runtime_config: dict[str, Any],
    *,
    prepared_metadata: PreparedRuntimeMetadata,
    max_runtime_seconds: float | None = None,
) -> int:
    """Run one workflow-owned runtime payload from a prepared pipeline-run manifest."""
    return asyncio.run(
        run_prepared_pipeline_async(
            runtime_config,
            max_runtime_seconds=max_runtime_seconds,
            prepared_metadata=prepared_metadata,
        )
    )


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
        except Exception as exc:
            error_reason = self._redact_error_reason(
                str(exc).strip() or exc.__class__.__name__
            )
            log.error(
                "Worker %s manifest loading failed: %s",
                request.worker_id,
                error_reason,
            )
            status_path, status_recording_error = self._record_failure_best_effort(
                request=request,
                failure_reason=error_reason,
            )
            return self._failure_payload(
                request,
                error_reason,
                status_path,
                status_recording_error=status_recording_error,
            )
        return self.run_manifest(request, prepare_manifest)

    def run_manifest(
        self, request: WorkerRunRequest, prepare_manifest: PrepareWorkerManifest
    ) -> dict[str, Any]:
        """Run one already-loaded worker manifest."""
        log_path: Path | None = None
        try:
            status_path = self.status_store.status_path(
                batch_id=request.batch_id,
                worker_id=request.worker_id,
                state_root=request.state_root,
            )
            if status_path.exists():
                self.status_store.read_status(
                    status_path,
                    batch_id=request.batch_id,
                    worker_id=request.worker_id,
                )
            else:
                initialized = self.status_lifecycle.initialize(
                    batch_id=request.batch_id,
                    worker_id=request.worker_id,
                    state_root=request.state_root,
                )
                if initialized["conclusion"] == STATUS_FAILURE:
                    reason = str(initialized.get("failure_reason") or "worker initialization failed")
                    return self._failure_payload(
                        request,
                        reason,
                        initialized.get("status_path"),
                        status_recording_error=initialized.get(
                            "status_recording_error"
                        ),
                    )
            worker_paths = prepare_manifest.resolve_paths(request.state_root)
            result_root = worker_paths["result_root"]
            log_path = prepare_manifest.resolve_log_path(request.state_root)
            self._clear_worker_runtime_outputs(worker_paths=worker_paths)
            outcome = self._run_manifest_payload(
                request=request,
                prepare_manifest=prepare_manifest,
                result_root=result_root,
                log_path=log_path,
            )
        except Exception as exc:
            reason = self._redact_error_reason(
                str(exc).strip() or exc.__class__.__name__
            )
            logging.getLogger(__name__).error(
                "Worker %s setup failed: %s", request.worker_id, reason
            )
            status_path, status_recording_error = self._record_failure_best_effort(
                request=request,
                failure_reason=reason,
            )
            if log_path is not None:
                self._append_worker_log_best_effort(
                    log_path, f"Worker {request.worker_id} setup failed: {reason}"
                )
            return self._failure_payload(
                request,
                reason,
                status_path,
                status_recording_error=status_recording_error,
            )
        payload = {
            "batch_id": request.batch_id,
            "worker_id": request.worker_id,
            "overall_conclusion": outcome.overall_conclusion,
            "error_reason": outcome.error_reason,
            "status_path": self.status_store.status_relative_path(
                batch_id=request.batch_id, worker_id=request.worker_id
            ),
        }
        if outcome.status_recording_error:
            payload["status_recording_error"] = outcome.status_recording_error
        return payload

    @staticmethod
    def _failure_payload(
        request: WorkerRunRequest,
        reason: str,
        status_path: str | None,
        *,
        status_recording_error: str | None = None,
    ) -> dict[str, Any]:
        """Return one consistently shaped failed worker result."""
        payload = {
            "batch_id": request.batch_id,
            "worker_id": request.worker_id,
            "overall_conclusion": STATUS_FAILURE,
            "error_reason": reason,
            "status_path": status_path,
        }
        if status_recording_error:
            payload["status_recording_error"] = status_recording_error
        return payload

    def _run_manifest_payload(
        self,
        *,
        request: WorkerRunRequest,
        prepare_manifest: PrepareWorkerManifest,
        result_root: Path,
        log_path: Path,
    ) -> WorkerRunOutcome:
        error_reason: str | None = None
        status_recording_error: str | None = None
        try:
            with self._capture_root_logs_to_file(log_path), self._pushd(result_root):
                try:
                    self._execute_manifest_runtime(
                        request=request,
                        prepare_manifest=prepare_manifest,
                    )
                except Exception as exc:
                    error_reason = self._redact_error_reason(
                        str(exc).strip() or exc.__class__.__name__
                    )
                    logging.getLogger(__name__).error(
                        "Worker %s failed: %s", request.worker_id, error_reason
                    )
                    _, status_recording_error = self._record_failure_best_effort(
                        request=request,
                        failure_reason=error_reason,
                    )
        except Exception as exc:
            capture_reason = self._redact_error_reason(
                str(exc).strip() or exc.__class__.__name__
            )
            if error_reason is None:
                error_reason = capture_reason
                logging.getLogger(__name__).error(
                    "Worker %s setup failed: %s", request.worker_id, error_reason
                )
                _, status_recording_error = self._record_failure_best_effort(
                    request=request,
                    failure_reason=error_reason,
                )
                self._append_worker_log_best_effort(
                    log_path,
                    f"Worker {request.worker_id} setup failed: {error_reason}",
                )
            else:
                logging.getLogger(__name__).error(
                    "Worker %s logging cleanup also failed: %s",
                    request.worker_id,
                    capture_reason,
                )
                self._append_worker_log_best_effort(
                    log_path,
                    f"Worker {request.worker_id} logging cleanup also failed: {capture_reason}",
                )
        return WorkerRunOutcome(
            overall_conclusion=STATUS_FAILURE if error_reason else STATUS_SUCCESS,
            error_reason=error_reason,
            status_recording_error=status_recording_error,
        )

    def _execute_manifest_runtime(
        self,
        *,
        request: WorkerRunRequest,
        prepare_manifest: PrepareWorkerManifest,
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
                prepared_metadata=prepare_manifest.prepared_metadata,
            )
        except FatalIPLocationCredentialError as exc:
            raise WorkerRuntimeExecutionError(str(exc)) from exc
        except asyncio.TimeoutError as exc:
            max_runtime = request.max_runtime_seconds
            reason = "pipeline exceeded max runtime seconds"
            if max_runtime is not None:
                reason = f"{reason}: {max_runtime}"
            raise WorkerRuntimeExecutionError(reason) from exc
        except Exception as exc:
            reason = str(exc).strip() or exc.__class__.__name__
            raise WorkerRuntimeExecutionError(reason) from exc
        if exit_code != 0:
            raise WorkerRuntimeExecutionError(
                f"pipeline exited with status {exit_code}"
            )

    @staticmethod
    def _redact_error_reason(reason: str) -> str:
        """Remove configured IP-location credentials from worker failure text."""
        redacted = reason
        env_token = os.environ.get("IP_LOCATION_IPINFO_TOKEN", "").strip()
        if env_token:
            redacted = redacted.replace(env_token, "[REDACTED]")
        return redacted

    def _record_failure_best_effort(
        self,
        *,
        request: WorkerRunRequest,
        failure_reason: str,
    ) -> tuple[str | None, str | None]:
        """Preserve the execution cause when failure-status persistence also fails."""
        try:
            status_path = self.status_lifecycle.record_failure(
                WorkerStatusFailureRequest(
                    identity=WorkerStatusIdentity(
                        request.batch_id,
                        request.worker_id,
                        request.state_root,
                    ),
                    failure_reason=failure_reason,
                )
            )
            return status_path, None
        except Exception as exc:
            status_error = self._redact_error_reason(
                str(exc).strip() or exc.__class__.__name__
            )
            logging.getLogger(__name__).error(
                "Worker %s could not record failure status: %s",
                request.worker_id,
                status_error,
            )
            return None, status_error

    @staticmethod
    def _append_worker_log_best_effort(log_path: Path, message: str) -> None:
        """Append a failure detail when root-log capture could not be established."""
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as log_file:
                log_file.write(message.rstrip() + "\n")
        except OSError as exc:
            logging.getLogger(__name__).error(
                "Could not append worker diagnostic log %s: %s",
                log_path,
                str(exc).strip() or exc.__class__.__name__,
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
            worker_paths["review"].parent.parent,
            worker_paths["domain_results"].parent,
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
