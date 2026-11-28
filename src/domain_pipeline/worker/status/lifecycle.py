"""Worker-status lifecycle owner."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from domain_pipeline.worker.worker_to_aggregate_manifest import (
    WorkerAggregateManifest,
    load_prepare_worker_manifest_or_error,
    write_worker_aggregate_manifest,
)
from domain_pipeline.worker.status.store import WorkerStatusStore

STATUS_IN_PROGRESS = "in_progress"
STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


@dataclasses.dataclass(frozen=True)
class WorkerStatusIdentity:
    """Worker status identity and state root."""

    batch_id: str
    worker_id: str
    state_root: Path


@dataclasses.dataclass(frozen=True)
class WorkerStatusPayloadRequest:
    """Inputs needed to build one workflow-visible worker status payload."""

    template: dict[str, Any]
    output_commit_sha: str
    push_retry_count: int
    finished_at: str | None
    conclusion: str
    failure_reason: str | None


@dataclasses.dataclass(frozen=True)
class WorkerStatusFinalizeRequest:
    """Request to finalize one worker status file."""

    identity: WorkerStatusIdentity
    output_commit_sha: str
    push_retry_count: int
    fallback_conclusion: str | None = None
    fallback_failure_reason: str | None = None
    finished_at: str | None = None


@dataclasses.dataclass(frozen=True)
class WorkerStatusFailureRequest:
    """Request to write a terminal worker failure status."""

    identity: WorkerStatusIdentity
    failure_reason: str
    finished_at: str | None = None


class WorkerStatusLifecycle:
    """Initialize, finalize, and record worker status files."""

    def __init__(self, *, store: WorkerStatusStore | None = None) -> None:
        self.store = store or WorkerStatusStore()

    def initialize(
        self,
        *,
        batch_id: str,
        worker_id: str,
        state_root: Path,
    ) -> dict[str, Any]:
        """Write one in-progress worker status for a prepared worker."""
        identity = WorkerStatusIdentity(batch_id, worker_id, state_root)
        status_path = self.store.status_path(
            batch_id=batch_id,
            worker_id=worker_id,
            state_root=state_root,
        )
        prepare_manifest, failure_reason = self._load_prepare_manifest_for_identity(
            identity
        )
        if failure_reason:
            try:
                status_path = self.record_failure(
                    WorkerStatusFailureRequest(
                        identity=identity,
                        failure_reason=failure_reason,
                    )
                )
            except Exception as status_exc:
                return {
                    "batch_id": batch_id,
                    "worker_id": worker_id,
                    "conclusion": STATUS_FAILURE,
                    "failure_reason": failure_reason,
                    "status_path": None,
                    "status_recording_error": (
                        str(status_exc).strip() or status_exc.__class__.__name__
                    ),
                }
            return {
                "batch_id": batch_id,
                "worker_id": worker_id,
                "conclusion": STATUS_FAILURE,
                "failure_reason": failure_reason,
                "status_path": status_path,
            }
        if prepare_manifest is None:
            raise RuntimeError("prepare worker manifest loader returned no manifest")
        if status_path.exists():
            self.store.read_status(
                status_path, batch_id=batch_id, worker_id=worker_id
            )

        worker_aggregate_manifest = (
            WorkerAggregateManifest.initialized_from_prepare_worker_manifest(
                prepare_manifest
            )
        )
        worker_aggregate_manifest_path = write_worker_aggregate_manifest(
            worker_aggregate_manifest,
            state_root=state_root,
        )
        template = self._status_template(batch_id=batch_id, worker_id=worker_id)
        try:
            self.store.write_status(
                status_path,
                self._status_payload_from_template(
                    WorkerStatusPayloadRequest(
                        template=template,
                        output_commit_sha="",
                        push_retry_count=0,
                        finished_at=None,
                        conclusion=STATUS_IN_PROGRESS,
                        failure_reason=None,
                    )
                ),
            )
        except Exception as status_exc:
            failure_reason = (
                "unable to initialize worker status: "
                + (str(status_exc).strip() or status_exc.__class__.__name__)
            )
            try:
                self.record_failure(
                    WorkerStatusFailureRequest(
                        identity=identity,
                        failure_reason=failure_reason,
                    )
                )
                status_recording_error = None
                result_status_path: str | None = self.store.status_relative_path(
                    batch_id=batch_id, worker_id=worker_id
                )
            except Exception as failure_status_exc:
                status_recording_error = (
                    str(failure_status_exc).strip()
                    or failure_status_exc.__class__.__name__
                )
                result_status_path = None
            return {
                "batch_id": batch_id,
                "worker_id": worker_id,
                "conclusion": STATUS_FAILURE,
                "failure_reason": failure_reason,
                "status_path": result_status_path,
                "status_recording_error": status_recording_error,
            }
        return {
            "batch_id": batch_id,
            "worker_id": worker_id,
            "conclusion": STATUS_SUCCESS,
            "status_path": self.store.status_relative_path(
                batch_id=batch_id, worker_id=worker_id
            ),
            "worker_aggregate_manifest_path": str(
                worker_aggregate_manifest_path.relative_to(state_root).as_posix()
            ),
        }

    def finalize(self, request: WorkerStatusFinalizeRequest) -> list[str]:
        """Finalize one worker status file after processing."""
        prepare_manifest, failure_reason = self._load_prepare_manifest_for_identity(
            request.identity
        )
        if failure_reason:
            self.record_failure(
                WorkerStatusFailureRequest(
                    identity=request.identity,
                    failure_reason=failure_reason,
                    finished_at=request.finished_at,
                )
            )
            raise ValueError(failure_reason)
        if prepare_manifest is None:
            raise RuntimeError("prepare worker manifest loader returned no manifest")
        status_path = self.store.status_path(
            batch_id=request.identity.batch_id,
            worker_id=request.identity.worker_id,
            state_root=request.identity.state_root,
        )
        if not status_path.is_file():
            if request.fallback_conclusion == STATUS_FAILURE:
                failure_reason = (
                    request.fallback_failure_reason
                    or "worker status was missing during failure finalization"
                )
                return [
                    self.record_failure(
                        WorkerStatusFailureRequest(
                            identity=request.identity,
                            failure_reason=failure_reason,
                            finished_at=request.finished_at,
                        )
                    )
                ]
            raise FileNotFoundError(
                f"worker status file is missing during finalization: {status_path}"
            )
        existing_payload = self.store.read_status(
            status_path,
            batch_id=request.identity.batch_id,
            worker_id=request.identity.worker_id,
        )
        self.store.write_status(
            status_path,
            self._finalized_status_payload(request, existing_payload),
        )
        return [
            self.store.status_relative_path(
                batch_id=request.identity.batch_id,
                worker_id=request.identity.worker_id,
            )
        ]

    def _load_prepare_manifest_for_identity(
        self, identity: WorkerStatusIdentity
    ) -> tuple[Any | None, str]:
        """Load the prepare manifest for one worker status identity."""
        return load_prepare_worker_manifest_or_error(
            batch_id=identity.batch_id,
            worker_id=identity.worker_id,
            state_root=identity.state_root,
        )

    def _finalized_status_payload(
        self,
        request: WorkerStatusFinalizeRequest,
        existing_payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Return the terminal status payload for finalization."""
        conclusion = str(existing_payload["conclusion"])
        failure_reason = existing_payload.get("failure_reason")
        if conclusion == STATUS_IN_PROGRESS:
            conclusion = request.fallback_conclusion or STATUS_FAILURE
            if conclusion not in {STATUS_SUCCESS, STATUS_FAILURE}:
                raise ValueError(
                    f"unsupported worker fallback conclusion: {conclusion!r}"
                )
            failure_reason = (
                (
                    request.fallback_failure_reason
                    or "worker status finalized without a terminal runtime result"
                )
                if conclusion == STATUS_FAILURE
                else None
            )
        return self._status_payload_from_template(
            WorkerStatusPayloadRequest(
                template={
                    "batch_id": request.identity.batch_id,
                    "worker_id": request.identity.worker_id,
                    "started_at": existing_payload["timestamps"]["started_at"],
                },
                output_commit_sha=request.output_commit_sha,
                push_retry_count=request.push_retry_count,
                finished_at=request.finished_at or utc_now(),
                conclusion=conclusion,
                failure_reason=failure_reason,
            )
        )

    def _status_template(self, *, batch_id: str, worker_id: str) -> dict[str, Any]:
        return {
            "batch_id": batch_id,
            "worker_id": worker_id,
            "conclusion": STATUS_IN_PROGRESS,
            "started_at": utc_now(),
        }

    def _status_payload_from_template(
        self, request: WorkerStatusPayloadRequest
    ) -> dict[str, Any]:
        return {
            "batch_id": request.template["batch_id"],
            "worker_id": request.template["worker_id"],
            "conclusion": request.conclusion,
            "commit_sha_produced": request.output_commit_sha,
            "timestamps": {
                "started_at": request.template["started_at"],
                "finished_at": request.finished_at,
            },
            "retry_count": request.push_retry_count,
            "failure_reason": request.failure_reason,
        }

    def record_failure(self, request: WorkerStatusFailureRequest) -> str:
        """Write a terminal worker failure status without trusting manifest paths."""
        finished_timestamp = request.finished_at or utc_now()
        status_path = self.store.status_path(
            batch_id=request.identity.batch_id,
            worker_id=request.identity.worker_id,
            state_root=request.identity.state_root,
        )
        template = self._status_template(
            batch_id=request.identity.batch_id,
            worker_id=request.identity.worker_id,
        )
        if status_path.exists():
            existing_payload = self.store.read_status(
                status_path,
                batch_id=request.identity.batch_id,
                worker_id=request.identity.worker_id,
            )
            started_at = existing_payload.get("timestamps", {}).get("started_at")
            if started_at is not None:
                template["started_at"] = started_at
        self.store.write_status(
            status_path,
            self._status_payload_from_template(
                WorkerStatusPayloadRequest(
                    template=template,
                    output_commit_sha="",
                    push_retry_count=0,
                    finished_at=finished_timestamp,
                    conclusion=STATUS_FAILURE,
                    failure_reason=request.failure_reason,
                )
            ),
        )
        return self.store.status_relative_path(
            batch_id=request.identity.batch_id, worker_id=request.identity.worker_id
        )


def initialize_worker_statuses(
    *,
    batch_id: str,
    worker_id: str,
    state_root: Path,
) -> dict[str, Any]:
    """Initialize one worker status from the workflow command layer."""
    return WorkerStatusLifecycle().initialize(
        batch_id=batch_id,
        worker_id=worker_id,
        state_root=state_root,
    )


def finalize_worker_statuses(request: WorkerStatusFinalizeRequest) -> list[str]:
    """Finalize one worker status from the workflow command layer."""
    return WorkerStatusLifecycle().finalize(request)


