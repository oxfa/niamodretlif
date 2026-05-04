"""Aggregate readiness barrier owner."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from domain_pipeline.prepare.aggregate_manifest import (
    load_prepare_aggregate_manifest_for_batch,
)
from domain_pipeline.worker.aggregate_manifest import (
    load_worker_aggregate_manifest,
    worker_aggregate_manifest_paths,
)
from domain_pipeline.worker.status.lifecycle import STATUS_FAILURE, STATUS_IN_PROGRESS
from domain_pipeline.worker.status.store import WorkerStatusStore

logger = logging.getLogger(__name__)


class AggregateReadinessChecker:
    """Validate whether one batch is ready for aggregate processing."""

    def __init__(self, *, status_store: WorkerStatusStore | None = None) -> None:
        self.status_store = status_store or WorkerStatusStore()

    def validate(self, batch_id: str, *, state_root: Path) -> dict[str, Any]:
        """Return barrier readiness information for one batch."""
        prepare_manifest = load_prepare_aggregate_manifest_for_batch(
            batch_id=batch_id, state_root=state_root
        )
        manifest_paths = worker_aggregate_manifest_paths(
            batch_id=batch_id,
            state_root=state_root,
        )
        discovered_worker_ids = {
            manifest_path.parent.name for manifest_path in manifest_paths
        }
        expected_worker_ids = set(prepare_manifest.worker_ids)
        extra_worker_ids = discovered_worker_ids - expected_worker_ids
        if extra_worker_ids:
            raise ValueError(
                "prepare aggregate worker ids do not match restored worker aggregate manifests: "
                f"expected={sorted(expected_worker_ids)} discovered={sorted(discovered_worker_ids)}"
            )
        worker_ids = list(prepare_manifest.worker_ids)
        missing_status_paths = []
        in_progress_status_paths = []
        status_payloads = []
        for worker_id in worker_ids:
            status_path = self.status_store.status_path(
                batch_id=batch_id,
                worker_id=worker_id,
                state_root=state_root,
            )
            if not status_path.exists():
                missing_status_paths.append(
                    self.status_store.status_relative_path(
                        batch_id=batch_id, worker_id=worker_id
                    )
                )
                continue
            payload = json.loads(status_path.read_text(encoding="utf-8"))
            status_payloads.append(payload)
            if payload["conclusion"] == STATUS_IN_PROGRESS:
                in_progress_status_paths.append(
                    self.status_store.status_relative_path(
                        batch_id=batch_id, worker_id=worker_id
                    )
                )
        if missing_status_paths or in_progress_status_paths:
            logger.debug(
                "Aggregate readiness for batch %s is not ready: missing=%s in_progress=%s",
                batch_id,
                missing_status_paths,
                in_progress_status_paths,
            )
            return {
                "state": "not_ready",
                "batch_id": batch_id,
                "missing_status_paths": missing_status_paths,
                "in_progress_status_paths": in_progress_status_paths,
            }
        status_by_worker_id = {
            str(payload["worker_id"]): payload for payload in status_payloads
        }
        missing_handoff_worker_ids = sorted(expected_worker_ids - discovered_worker_ids)
        unresolved_missing_handoff_worker_ids = [
            worker_id
            for worker_id in missing_handoff_worker_ids
            if status_by_worker_id[worker_id]["conclusion"] != STATUS_FAILURE
        ]
        if unresolved_missing_handoff_worker_ids:
            raise ValueError(
                "prepare aggregate worker ids do not match restored worker aggregate manifests: "
                f"missing={unresolved_missing_handoff_worker_ids}"
            )
        handoffs_by_worker_id = {
            manifest_path.parent.name: load_worker_aggregate_manifest(manifest_path)
            for manifest_path in manifest_paths
        }
        if any(payload["conclusion"] == STATUS_FAILURE for payload in status_payloads):
            logger.info(
                "Aggregate readiness for batch %s resolved to ready_failed with %d statuses",
                batch_id,
                len(status_payloads),
            )
            return {
                "state": "ready_failed",
                "batch_id": batch_id,
                "worker_ids": worker_ids,
                "status_payloads": status_payloads,
            }
        unfinalized_handoff_worker_ids = [
            worker_id
            for worker_id in worker_ids
            if not handoffs_by_worker_id[worker_id].handoff_finalized
        ]
        if unfinalized_handoff_worker_ids:
            return {
                "state": "not_ready",
                "batch_id": batch_id,
                "unfinalized_handoff_worker_ids": unfinalized_handoff_worker_ids,
            }
        logger.info(
            "Aggregate readiness for batch %s resolved to ready_success with %d statuses",
            batch_id,
            len(status_payloads),
        )
        return {
            "state": "ready_success",
            "batch_id": batch_id,
            "worker_ids": worker_ids,
            "status_payloads": status_payloads,
        }


def validate_aggregate_readiness(batch_id: str, *, state_root: Path) -> dict[str, Any]:
    """Validate whether a batch is ready for aggregate execution."""
    return AggregateReadinessChecker().validate(batch_id, state_root=state_root)
