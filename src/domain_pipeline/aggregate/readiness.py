"""Aggregate readiness barrier owner."""

from __future__ import annotations

import dataclasses
import json
import logging
from pathlib import Path
from typing import Any

from domain_pipeline.prepare.prepare_to_aggregate_manifest import (
    load_prepare_aggregate_manifest_for_batch,
)
from domain_pipeline.worker.worker_to_aggregate_manifest import (
    load_worker_aggregate_manifest,
    worker_aggregate_manifest_paths,
)
from domain_pipeline.worker.status.lifecycle import STATUS_FAILURE, STATUS_IN_PROGRESS
from domain_pipeline.worker.status.store import WorkerStatusStore

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class AggregateStatusBarrier:
    """Worker status payloads and blocking status paths for aggregate readiness."""

    missing_status_paths: list[str]
    in_progress_status_paths: list[str]
    status_payloads: list[dict[str, Any]]

    @property
    def blocked(self) -> bool:
        """Return whether missing or in-progress statuses block aggregation."""
        return bool(self.missing_status_paths or self.in_progress_status_paths)


@dataclasses.dataclass
class AggregateStatusBarrierBuilder:
    """Mutable status barrier state while scanning worker statuses."""

    missing_status_paths: list[str] = dataclasses.field(default_factory=list)
    in_progress_status_paths: list[str] = dataclasses.field(default_factory=list)
    status_payloads: list[dict[str, Any]] = dataclasses.field(default_factory=list)

    def build(self) -> AggregateStatusBarrier:
        """Return an immutable status barrier snapshot."""
        return AggregateStatusBarrier(
            missing_status_paths=self.missing_status_paths,
            in_progress_status_paths=self.in_progress_status_paths,
            status_payloads=self.status_payloads,
        )


class AggregateReadinessChecker:
    """Validate whether one batch is ready for aggregate processing."""

    def __init__(self, *, status_store: WorkerStatusStore | None = None) -> None:
        self.status_store = status_store or WorkerStatusStore()

    def validate(self, batch_id: str, *, state_root: Path) -> dict[str, Any]:
        """Return barrier readiness information for one batch."""
        prepare_manifest = load_prepare_aggregate_manifest_for_batch(
            batch_id=batch_id, state_root=state_root
        )
        manifest_paths = self.worker_manifest_paths(batch_id, state_root=state_root)
        discovered_worker_ids = self.discovered_worker_ids(manifest_paths)
        expected_worker_ids = set(prepare_manifest.worker_ids)
        worker_ids = list(prepare_manifest.worker_ids)
        self.validate_manifest_id_set(
            expected_worker_ids=expected_worker_ids,
            discovered_worker_ids=discovered_worker_ids,
        )
        status_barrier = self.status_barrier(
            batch_id=batch_id, worker_ids=worker_ids, state_root=state_root
        )
        if status_barrier.blocked:
            logger.debug(
                "Aggregate readiness for batch %s is not ready: missing=%s in_progress=%s",
                batch_id,
                status_barrier.missing_status_paths,
                status_barrier.in_progress_status_paths,
            )
            return {
                "state": "not_ready",
                "batch_id": batch_id,
                "missing_status_paths": status_barrier.missing_status_paths,
                "in_progress_status_paths": status_barrier.in_progress_status_paths,
            }
        status_by_worker_id = {
            str(payload["worker_id"]): payload
            for payload in status_barrier.status_payloads
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
        handoffs_by_worker_id = self.handoffs_by_worker_id(manifest_paths)
        if any(
            payload["conclusion"] == STATUS_FAILURE
            for payload in status_barrier.status_payloads
        ):
            logger.info(
                "Aggregate readiness for batch %s resolved to ready_failed with %d statuses",
                batch_id,
                len(status_barrier.status_payloads),
            )
            return {
                "state": "ready_failed",
                "batch_id": batch_id,
                "worker_ids": worker_ids,
                "status_payloads": status_barrier.status_payloads,
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
            len(status_barrier.status_payloads),
        )
        return {
            "state": "ready_success",
            "batch_id": batch_id,
            "worker_ids": worker_ids,
            "status_payloads": status_barrier.status_payloads,
        }

    def worker_manifest_paths(self, batch_id: str, *, state_root: Path) -> list[Path]:
        """Return restored worker aggregate manifest paths for one batch."""
        return worker_aggregate_manifest_paths(batch_id=batch_id, state_root=state_root)

    def discovered_worker_ids(self, manifest_paths: list[Path]) -> set[str]:
        """Return worker ids discovered from aggregate handoff paths."""
        return {manifest_path.parent.name for manifest_path in manifest_paths}

    def validate_manifest_id_set(
        self,
        *,
        expected_worker_ids: set[str],
        discovered_worker_ids: set[str],
    ) -> None:
        """Reject aggregate handoffs for worker ids not in the prepare manifest."""
        extra_worker_ids = discovered_worker_ids - expected_worker_ids
        if extra_worker_ids:
            raise ValueError(
                "prepare aggregate worker ids do not match restored worker aggregate manifests: "
                f"expected={sorted(expected_worker_ids)} discovered={sorted(discovered_worker_ids)}"
            )

    def status_barrier(
        self, *, batch_id: str, worker_ids: list[str], state_root: Path
    ) -> AggregateStatusBarrier:
        """Return status payloads and not-ready status blockers."""
        builder = AggregateStatusBarrierBuilder()
        for worker_id in worker_ids:
            self.collect_worker_status(
                batch_id=batch_id,
                worker_id=worker_id,
                state_root=state_root,
                builder=builder,
            )
        return builder.build()

    def collect_worker_status(
        self,
        *,
        batch_id: str,
        worker_id: str,
        state_root: Path,
        builder: AggregateStatusBarrierBuilder,
    ) -> None:
        """Collect one worker status payload or not-ready blocker."""
        status_path = self.status_store.status_path(
            batch_id=batch_id,
            worker_id=worker_id,
            state_root=state_root,
        )
        relative_status_path = self.status_store.status_relative_path(
            batch_id=batch_id, worker_id=worker_id
        )
        if not status_path.exists():
            builder.missing_status_paths.append(relative_status_path)
            return
        payload = json.loads(status_path.read_text(encoding="utf-8"))
        builder.status_payloads.append(payload)
        if payload["conclusion"] == STATUS_IN_PROGRESS:
            builder.in_progress_status_paths.append(relative_status_path)

    def handoffs_by_worker_id(self, manifest_paths: list[Path]) -> dict[str, Any]:
        """Return loaded worker aggregate handoffs keyed by worker id."""
        return {
            manifest_path.parent.name: load_worker_aggregate_manifest(manifest_path)
            for manifest_path in manifest_paths
        }


def validate_aggregate_readiness(batch_id: str, *, state_root: Path) -> dict[str, Any]:
    """Validate whether a batch is ready for aggregate execution."""
    return AggregateReadinessChecker().validate(batch_id, state_root=state_root)
