"""Worker-status lifecycle owner."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from domain_pipeline.prepare.aggregate_manifest import (
    load_prepare_aggregate_manifest_for_batch,
)
from domain_pipeline.prepare.worker_manifest import (
    load_prepare_worker_manifest_for_worker,
)
from domain_pipeline.worker.aggregate_manifest import (
    WorkerAggregateManifest,
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
        prepare_manifest = load_prepare_worker_manifest_for_worker(
            batch_id=batch_id,
            worker_id=worker_id,
            state_root=state_root,
        )
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
                template=template,
                output_commit_sha="",
                push_retry_count=0,
                finished_at=None,
                conclusion=STATUS_IN_PROGRESS,
                failure_reason=None,
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

    def finalize(
        self,
        *,
        batch_id: str,
        worker_id: str,
        state_root: Path,
        output_commit_sha: str,
        push_retry_count: int,
        fallback_conclusion: str | None = None,
        fallback_failure_reason: str | None = None,
        finished_at: str | None = None,
    ) -> list[str]:
        """Finalize one worker status file after processing."""
        if (
            load_prepare_worker_manifest_for_worker(
                batch_id=batch_id, worker_id=worker_id, state_root=state_root
            )
            is None
        ):
            return []
        status_path = self.store.status_path(
            batch_id=batch_id,
            worker_id=worker_id,
            state_root=state_root,
        )
        if not status_path.is_file():
            return []
        existing_payload = self.store.read_status(status_path)
        finished_timestamp = finished_at or utc_now()
        conclusion = str(existing_payload["conclusion"])
        failure_reason = existing_payload.get("failure_reason")
        if conclusion == STATUS_IN_PROGRESS:
            conclusion = fallback_conclusion or STATUS_SUCCESS
            failure_reason = (
                fallback_failure_reason if conclusion == STATUS_FAILURE else None
            )
        self.store.write_status(
            status_path,
            {
                "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
                "status_version": WORKER_STATUS_VERSION,
                "batch_id": batch_id,
                "worker_id": worker_id,
                "conclusion": conclusion,
                "commit_sha_produced": output_commit_sha,
                "timestamps": {
                    "started_at": existing_payload["timestamps"]["started_at"],
                    "finished_at": finished_timestamp,
                },
                "retry_count": push_retry_count,
                "failure_reason": failure_reason,
            },
        )
        return [self.store.status_relative_path(batch_id=batch_id, worker_id=worker_id)]

    def materialize_incomplete(
        self,
        *,
        batch_id: str,
        state_root: Path,
        failure_reason: str,
        finished_at: str | None = None,
    ) -> dict[str, Any]:
        """Rewrite missing or in-progress worker statuses to terminal failure."""
        written_paths: list[str] = []
        finished_timestamp = finished_at or utc_now()
        prepare_aggregate_manifest = load_prepare_aggregate_manifest_for_batch(
            batch_id=batch_id, state_root=state_root
        )
        discovered_worker_ids = {
            manifest_path.parent.name
            for manifest_path in worker_aggregate_manifest_paths(
                batch_id=batch_id,
                state_root=state_root,
            )
        }
        expected_worker_ids = set(prepare_aggregate_manifest.worker_ids)
        missing_handoff_worker_ids = sorted(expected_worker_ids - discovered_worker_ids)
        extra_handoff_worker_ids = sorted(discovered_worker_ids - expected_worker_ids)
        for worker_id in prepare_aggregate_manifest.worker_ids:
            status_path = self.store.status_path(
                batch_id=batch_id,
                worker_id=worker_id,
                state_root=state_root,
            )
            existing_payload: dict[str, Any] | None = None
            if status_path.exists():
                existing_payload = self.store.read_status(status_path)
                if existing_payload.get("conclusion") in {
                    STATUS_SUCCESS,
                    STATUS_FAILURE,
                }:
                    continue
            template = self._status_template(batch_id=batch_id, worker_id=worker_id)
            if existing_payload is not None:
                started_at = existing_payload.get("timestamps", {}).get("started_at")
                if started_at is not None:
                    template["started_at"] = started_at
            else:
                template["started_at"] = finished_timestamp
            self.store.write_status(
                status_path,
                self._status_payload_from_template(
                    template=template,
                    output_commit_sha="",
                    push_retry_count=0,
                    finished_at=finished_timestamp,
                    conclusion=STATUS_FAILURE,
                    failure_reason=failure_reason,
                ),
            )
            written_paths.append(
                self.store.status_relative_path(batch_id=batch_id, worker_id=worker_id)
            )
        return {
            "batch_id": batch_id,
            "written_paths": written_paths,
            "written_count": len(written_paths),
            "missing_worker_aggregate_manifest_worker_ids": missing_handoff_worker_ids,
            "extra_worker_aggregate_manifest_worker_ids": extra_handoff_worker_ids,
        }

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
        self,
        *,
        template: dict[str, Any],
        output_commit_sha: str,
        push_retry_count: int,
        finished_at: str | None,
        conclusion: str,
        failure_reason: str | None,
    ) -> dict[str, Any]:
        return {
            "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
            "status_version": WORKER_STATUS_VERSION,
            "batch_id": template["batch_id"],
            "worker_id": template["worker_id"],
            "conclusion": conclusion,
            "commit_sha_produced": output_commit_sha,
            "timestamps": {
                "started_at": template["started_at"],
                "finished_at": finished_at,
            },
            "retry_count": push_retry_count,
            "failure_reason": failure_reason,
        }


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


def finalize_worker_statuses(
    *,
    batch_id: str,
    worker_id: str,
    state_root: Path,
    output_commit_sha: str,
    push_retry_count: int,
    fallback_conclusion: str | None = None,
    fallback_failure_reason: str | None = None,
    finished_at: str | None = None,
) -> list[str]:
    """Finalize one worker status from the workflow command layer."""
    return WorkerStatusLifecycle().finalize(
        batch_id=batch_id,
        worker_id=worker_id,
        state_root=state_root,
        output_commit_sha=output_commit_sha,
        push_retry_count=push_retry_count,
        fallback_conclusion=fallback_conclusion,
        fallback_failure_reason=fallback_failure_reason,
        finished_at=finished_at,
    )


def materialize_incomplete_statuses(
    *,
    batch_id: str,
    state_root: Path,
    failure_reason: str,
    finished_at: str | None = None,
) -> dict[str, Any]:
    """Materialize terminal statuses for workers that did not complete."""
    return WorkerStatusLifecycle().materialize_incomplete(
        batch_id=batch_id,
        state_root=state_root,
        failure_reason=failure_reason,
        finished_at=finished_at,
    )
