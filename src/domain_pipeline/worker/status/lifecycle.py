"""Worker-status lifecycle owner."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from domain_pipeline.prepare.prepare_to_aggregate_manifest import (
    load_prepare_aggregate_manifest_for_batch,
)
from domain_pipeline.worker.worker_to_aggregate_manifest import (
    WorkerAggregateManifest,
    load_prepare_worker_manifest_or_error,
    worker_aggregate_manifest_paths,
    write_worker_aggregate_manifest,
)
from domain_pipeline.worker.status.store import WorkerStatusStore

PIPELINE_RUN_FORMAT_VERSION = 2
WORKER_STATUS_VERSION = 2
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


@dataclasses.dataclass(frozen=True)
class WorkerStatusMaterializeIncompleteRequest:
    """Request to materialize missing or in-progress statuses."""

    batch_id: str
    state_root: Path
    failure_reason: str
    finished_at: str | None = None


@dataclasses.dataclass(frozen=True)
class WorkerHandoffState:
    """Worker aggregate handoff ids discovered during incomplete-status handling."""

    missing_worker_ids: list[str]
    extra_worker_ids: list[str]


class WorkerStatusLifecycle:
    """Initialize, finalize, and materialize worker status files."""

    def __init__(self, *, store: WorkerStatusStore | None = None) -> None:
        self.store = store or WorkerStatusStore()

    def initialize(
        self,
        *,
        batch_id: str,
        worker_id: str,
        state_root: Path,
    ) -> dict[str, Any]:
        """Write one in-progress worker status when a worker manifest exists."""
        identity = WorkerStatusIdentity(batch_id, worker_id, state_root)
        prepare_manifest, failure_reason = self._load_prepare_manifest_for_identity(
            identity
        )
        if failure_reason:
            status_path = self.record_failure(
                WorkerStatusFailureRequest(
                    identity=identity,
                    failure_reason=failure_reason,
                )
            )
            return {
                "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
                "batch_id": batch_id,
                "worker_id": worker_id,
                "participates": True,
                "conclusion": STATUS_FAILURE,
                "failure_reason": failure_reason,
                "status_path": status_path,
            }
        if prepare_manifest is None:
            return {
                "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
                "batch_id": batch_id,
                "worker_id": worker_id,
                "participates": False,
            }

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
        status_path = self.store.status_path(
            batch_id=batch_id,
            worker_id=worker_id,
            state_root=state_root,
        )
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
        return {
            "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
            "batch_id": batch_id,
            "worker_id": worker_id,
            "participates": True,
            "status_path": self.store.status_relative_path(
                batch_id=batch_id, worker_id=worker_id
            ),
            "worker_aggregate_manifest_path": str(
                worker_aggregate_manifest_path.relative_to(state_root).as_posix()
            ),
        }

    def finalize(self, request: WorkerStatusFinalizeRequest) -> list[str]:
        """Finalize one worker status file after processing."""
        if not self._worker_manifest_exists_for_finalize(request):
            return []
        status_path = self.store.status_path(
            batch_id=request.identity.batch_id,
            worker_id=request.identity.worker_id,
            state_root=request.identity.state_root,
        )
        if not status_path.is_file():
            return []
        existing_payload = self.store.read_status(status_path)
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

    def _worker_manifest_exists_for_finalize(
        self, request: WorkerStatusFinalizeRequest
    ) -> bool:
        """Return whether a worker status should be finalized."""
        prepare_manifest, failure_reason = self._load_prepare_manifest_for_identity(
            request.identity
        )
        if failure_reason:
            status_path = self.store.status_path(
                batch_id=request.identity.batch_id,
                worker_id=request.identity.worker_id,
                state_root=request.identity.state_root,
            )
            if not status_path.is_file():
                self.record_failure(
                    WorkerStatusFailureRequest(
                        identity=request.identity,
                        failure_reason=failure_reason,
                    )
                )
            return True
        return prepare_manifest is not None

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
            conclusion = request.fallback_conclusion or STATUS_SUCCESS
            failure_reason = (
                request.fallback_failure_reason
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

    def materialize_incomplete(
        self, request: WorkerStatusMaterializeIncompleteRequest
    ) -> dict[str, Any]:
        """Rewrite missing or in-progress worker statuses to terminal failure."""
        prepare_aggregate_manifest = load_prepare_aggregate_manifest_for_batch(
            batch_id=request.batch_id, state_root=request.state_root
        )
        handoff_state = self._handoff_state(
            batch_id=request.batch_id,
            state_root=request.state_root,
            expected_worker_ids=set(prepare_aggregate_manifest.worker_ids),
        )
        written_paths = self._write_incomplete_statuses(
            request=request,
            worker_ids=prepare_aggregate_manifest.worker_ids,
            finished_timestamp=request.finished_at or utc_now(),
        )
        return {
            "batch_id": request.batch_id,
            "written_paths": written_paths,
            "written_count": len(written_paths),
            "missing_worker_aggregate_manifest_worker_ids": (
                handoff_state.missing_worker_ids
            ),
            "extra_worker_aggregate_manifest_worker_ids": handoff_state.extra_worker_ids,
        }

    def _handoff_state(
        self,
        *,
        batch_id: str,
        state_root: Path,
        expected_worker_ids: set[str],
    ) -> WorkerHandoffState:
        """Return missing and extra worker aggregate handoff ids."""
        discovered_worker_ids = {
            manifest_path.parent.name
            for manifest_path in worker_aggregate_manifest_paths(
                batch_id=batch_id,
                state_root=state_root,
            )
        }
        return WorkerHandoffState(
            missing_worker_ids=sorted(expected_worker_ids - discovered_worker_ids),
            extra_worker_ids=sorted(discovered_worker_ids - expected_worker_ids),
        )

    def _write_incomplete_statuses(
        self,
        *,
        request: WorkerStatusMaterializeIncompleteRequest,
        worker_ids: list[str],
        finished_timestamp: str,
    ) -> list[str]:
        """Write failure statuses for missing or in-progress workers."""
        written_paths: list[str] = []
        for worker_id in worker_ids:
            status_path = self.store.status_path(
                batch_id=request.batch_id,
                worker_id=worker_id,
                state_root=request.state_root,
            )
            existing_payload: dict[str, Any] | None = None
            if status_path.exists():
                existing_payload = self.store.read_status(status_path)
                if existing_payload.get("conclusion") in {
                    STATUS_SUCCESS,
                    STATUS_FAILURE,
                }:
                    continue
            template = self._status_template(
                batch_id=request.batch_id, worker_id=worker_id
            )
            if existing_payload is not None:
                started_at = existing_payload.get("timestamps", {}).get("started_at")
                if started_at is not None:
                    template["started_at"] = started_at
            else:
                template["started_at"] = finished_timestamp
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
            written_paths.append(
                self.store.status_relative_path(
                    batch_id=request.batch_id, worker_id=worker_id
                )
            )
        return written_paths

    def _status_template(self, *, batch_id: str, worker_id: str) -> dict[str, Any]:
        return {
            "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
            "status_version": WORKER_STATUS_VERSION,
            "batch_id": batch_id,
            "worker_id": worker_id,
            "conclusion": STATUS_IN_PROGRESS,
            "started_at": utc_now(),
        }

    def _status_payload_from_template(
        self, request: WorkerStatusPayloadRequest
    ) -> dict[str, Any]:
        return {
            "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
            "status_version": WORKER_STATUS_VERSION,
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
            existing_payload = self.store.read_status(status_path)
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


def materialize_incomplete_statuses(
    request: WorkerStatusMaterializeIncompleteRequest,
) -> dict[str, Any]:
    """Materialize terminal statuses for workers that did not complete."""
    return WorkerStatusLifecycle().materialize_incomplete(request)
