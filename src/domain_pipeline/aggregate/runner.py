"""Aggregate batch coordination owner."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import shutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from domain_pipeline.aggregate.cache_merge import AggregateCacheMerger
from domain_pipeline.aggregate.log_merge import AggregateLogMerger
from domain_pipeline.aggregate.output_merge import AggregateOutputMerger
from domain_pipeline.aggregate.readiness import AggregateReadinessChecker
from domain_pipeline.paths import PathLayout, WorkflowPathLayout
from domain_pipeline.prepare.prepare_to_aggregate_manifest import (
    PrepareAggregateManifest,
    load_prepare_aggregate_manifest_for_batch,
)
from domain_pipeline.prepare.assignment import relative_path
from domain_pipeline.worker.worker_to_aggregate_manifest import (
    WorkerAggregateManifest,
    load_worker_aggregate_manifest_for_worker,
)
from domain_pipeline.worker.output.invariants import DuplicateOutputInvariantError
from domain_pipeline.worker.status.lifecycle import (
    PIPELINE_RUN_FORMAT_VERSION,
    STATUS_FAILURE,
)
from domain_pipeline.worker.status.store import WorkerStatusStore

logger = logging.getLogger(__name__)


def _relative_workflow_paths() -> WorkflowPathLayout:
    """Return repo-relative workflow path ownership."""
    return PathLayout(Path(".")).workflow


class AggregateBatchRunner:
    """Coordinate aggregate readiness, output merge, cache merge, logs, and markers."""

    def __init__(
        self,
        *,
        readiness_checker: AggregateReadinessChecker | None = None,
        output_merger: AggregateOutputMerger | None = None,
        cache_merger: AggregateCacheMerger | None = None,
        log_merger: AggregateLogMerger | None = None,
        status_store: WorkerStatusStore | None = None,
    ) -> None:
        self.status_store = status_store or WorkerStatusStore()
        self.readiness_checker = readiness_checker or AggregateReadinessChecker(
            status_store=self.status_store
        )
        self.output_merger = output_merger or AggregateOutputMerger()
        self.cache_merger = cache_merger or AggregateCacheMerger()
        self.log_merger = log_merger or AggregateLogMerger()

    def run(
        self,
        *,
        batch_id: str,
        state_root: Path,
    ) -> dict[str, Any]:
        """Aggregate one fully completed batch from JSON handoff payloads."""
        readiness = self.readiness_checker.validate(batch_id, state_root=state_root)
        prepare_manifest = load_prepare_aggregate_manifest_for_batch(
            batch_id=batch_id, state_root=state_root
        )
        worker_ids = list(readiness.get("worker_ids", []))
        final_output_paths = prepare_manifest.resolve_paths(state_root)
        worker_manifests = self._worker_aggregate_manifests(
            batch_id=batch_id,
            worker_ids=worker_ids,
            state_root=state_root,
            require_all=readiness["state"] == "ready_success",
        )
        self._log_start(
            batch_id=batch_id,
            readiness=readiness,
            prepare_manifest=prepare_manifest,
        )
        if readiness["state"] == "ready_failed":
            return self._handle_failed_ready_batch(
                batch_id=batch_id,
                state_root=state_root,
                final_output_paths=final_output_paths,
                worker_manifests=worker_manifests,
                readiness=readiness,
            )
        if readiness["state"] != "ready_success":
            return readiness
        status_payloads = readiness["status_payloads"]
        try:
            self.output_merger.merge_host_value_payloads(
                [
                    ("prepare", prepare_manifest.preparation_filtered_output_values),
                    *[
                        (manifest.worker_id, manifest.filtered_output_values)
                        for manifest in worker_manifests
                        if manifest.handoff_finalized
                    ],
                ],
                final_output_paths["filtered"],
            )
            self.output_merger.merge_host_value_payloads(
                [
                    (manifest.worker_id, manifest.unactionable_output_values)
                    for manifest in worker_manifests
                    if manifest.handoff_finalized
                ],
                final_output_paths["unactionable"],
            )
            self.output_merger.merge_audit_payloads(
                [
                    *[
                        (manifest.worker_id, manifest.terminal_rows)
                        for manifest in worker_manifests
                        if manifest.handoff_finalized
                    ],
                    ("prepare", prepare_manifest.preparation_terminal_rows),
                ],
                final_output_paths["audit"],
            )
            self.output_merger.merge_review_payloads(
                [
                    *[
                        (manifest.worker_id, manifest.review_output_rows)
                        for manifest in worker_manifests
                        if manifest.handoff_finalized
                    ],
                    ("prepare", prepare_manifest.preparation_review_output_rows),
                ],
                final_output_paths["review"],
            )
        except DuplicateOutputInvariantError as exc:
            return self._handle_duplicate_output(
                exc=exc,
                batch_id=batch_id,
                state_root=state_root,
                final_output_paths=final_output_paths,
                worker_manifests=worker_manifests,
            )
        cache_merge_summary = self._merge_cache(
            batch_id=batch_id,
            source_paths=self._materialize_worker_cache_payloads(
                batch_id=batch_id,
                state_root=state_root,
                worker_manifests=worker_manifests,
            ),
            target_path=final_output_paths["cache"],
        )
        summary_counts = Counter(payload["conclusion"] for payload in status_payloads)
        self._merge_logs(
            batch_id=batch_id,
            worker_manifests=worker_manifests,
            target_path=final_output_paths["log"],
        )
        self._log_output_summaries(
            batch_id=batch_id, final_output_paths=final_output_paths
        )
        self._cleanup_worker_state(batch_id=batch_id, state_root=state_root)

        logger.info(
            "Aggregate completed batch %s with summary_counts=%s",
            batch_id,
            dict(summary_counts),
        )
        return {
            "state": "aggregated",
            "cache_merge_summary": cache_merge_summary,
            "final_output_paths": {
                "filtered": prepare_manifest.aggregate_output_spec.filtered,
                "unactionable": prepare_manifest.aggregate_output_spec.unactionable,
                "review": prepare_manifest.aggregate_output_spec.review,
            },
            "final_state_paths": {
                "cache": prepare_manifest.aggregate_output_spec.cache,
            },
            "final_debug_paths": {
                "raw_audit": prepare_manifest.aggregate_output_spec.audit,
                "runtime_log": prepare_manifest.aggregate_output_spec.log,
            },
        }

    def _handle_failed_ready_batch(
        self,
        *,
        batch_id: str,
        state_root: Path,
        final_output_paths: dict[str, Path],
        worker_manifests: list[WorkerAggregateManifest],
        readiness: dict[str, Any],
    ) -> dict[str, Any]:
        logger.debug(
            "Aggregate failed batch %s status payloads=%s",
            batch_id,
            json.dumps(readiness["status_payloads"], sort_keys=True),
        )
        cache_merge_summary = self._merge_cache(
            batch_id=batch_id,
            source_paths=self._materialize_worker_cache_payloads(
                batch_id=batch_id,
                state_root=state_root,
                worker_manifests=worker_manifests,
            ),
            target_path=final_output_paths["cache"],
        )
        failed_statuses = [
            payload
            for payload in readiness["status_payloads"]
            if payload["conclusion"] == STATUS_FAILURE
        ]
        failure_payload = {
            "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
            "batch_id": batch_id,
            "failed_status_count": len(failed_statuses),
            "written_at": utc_now(),
        }
        self._write_json(
            state_root
            / _relative_workflow_paths()
            .aggregate_failed_marker_path(batch_id=batch_id)
            .relative_to(Path(".")),
            failure_payload,
        )
        return {
            "state": "failed",
            "failed_statuses": failed_statuses,
            "cache_merge_summary": cache_merge_summary,
        }

    def _handle_duplicate_output(
        self,
        *,
        exc: DuplicateOutputInvariantError,
        batch_id: str,
        state_root: Path,
        final_output_paths: dict[str, Path],
        worker_manifests: list[WorkerAggregateManifest],
    ) -> dict[str, Any]:
        cache_merge_summary = self._merge_cache(
            batch_id=batch_id,
            source_paths=self._materialize_worker_cache_payloads(
                batch_id=batch_id,
                state_root=state_root,
                worker_manifests=worker_manifests,
            ),
            target_path=final_output_paths["cache"],
        )
        failure_payload = {
            "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
            "batch_id": batch_id,
            "failed_status_count": 0,
            "written_at": utc_now(),
            "failure_reason": str(exc),
            "duplicate_output": {
                "output_kind": exc.output_kind,
                "duplicate_key": exc.duplicate_key,
                "context": exc.context,
            },
        }
        self._write_json(
            state_root
            / _relative_workflow_paths()
            .aggregate_failed_marker_path(batch_id=batch_id)
            .relative_to(Path(".")),
            failure_payload,
        )
        logger.error("Aggregate duplicate invariant for batch %s: %s", batch_id, exc)
        return {
            "state": "failed",
            "failed_statuses": [],
            "failure_reason": str(exc),
            "cache_merge_summary": cache_merge_summary,
            "duplicate_output": {
                "output_kind": exc.output_kind,
                "duplicate_key": exc.duplicate_key,
                "context": exc.context,
            },
        }

    def _merge_cache(
        self,
        *,
        batch_id: str,
        source_paths: list[Path],
        target_path: Path,
    ) -> dict[str, Any]:
        cache_merge_summary = self.cache_merger.merge(
            source_paths=source_paths,
            target_path=target_path,
        )
        logger.info(
            "Aggregate cache merge for batch %s: candidates=%d merged=%d "
            "missing=%d invalid=%d final=%s",
            batch_id,
            cache_merge_summary["candidate_cache_count"],
            cache_merge_summary["merged_cache_count"],
            cache_merge_summary["missing_cache_count"],
            cache_merge_summary["invalid_cache_count"],
            cache_merge_summary["final_cache_path"],
        )
        return cache_merge_summary

    def _merge_logs(
        self,
        *,
        batch_id: str,
        worker_manifests: list[WorkerAggregateManifest],
        target_path: Path,
    ) -> None:
        logger.debug(
            "Aggregate log merge for batch %s starting: candidates=%d target=%s",
            batch_id,
            len(worker_manifests),
            relative_path(target_path),
        )
        self.log_merger.merge_texts(
            log_texts=[
                manifest.log_text
                for manifest in worker_manifests
                if manifest.handoff_finalized
            ],
            target_path=target_path,
        )
        final_log_summary = self._path_debug_summary(target_path)
        logger.debug(
            "Aggregate log merge for batch %s completed: path=%s exists=%s bytes=%s",
            batch_id,
            final_log_summary["path"],
            final_log_summary["exists"],
            final_log_summary.get("bytes", 0),
        )

    def _worker_aggregate_manifests(
        self,
        *,
        batch_id: str,
        worker_ids: list[str],
        state_root: Path,
        require_all: bool,
    ) -> list[WorkerAggregateManifest]:
        manifests: list[WorkerAggregateManifest] = []
        for worker_id in worker_ids:
            manifest = load_worker_aggregate_manifest_for_worker(
                batch_id=batch_id,
                worker_id=worker_id,
                state_root=state_root,
            )
            if manifest is None:
                if not require_all:
                    continue
                raise ValueError(
                    "worker aggregate manifest is required before aggregate execution: "
                    f"batch_id={batch_id} worker_id={worker_id}"
                )
            manifests.append(manifest)
        return manifests

    def _materialize_worker_cache_payloads(
        self,
        *,
        batch_id: str,
        state_root: Path,
        worker_manifests: list[WorkerAggregateManifest],
    ) -> list[Path]:
        cache_root = (
            PathLayout(state_root)
            .workflow.aggregate_marker_root(batch_id=batch_id)
            .joinpath("worker_cache_payloads")
        )
        if cache_root.exists():
            shutil.rmtree(cache_root)
        cache_root.mkdir(parents=True, exist_ok=True)
        source_paths: list[Path] = []
        for manifest in worker_manifests:
            cache_path = cache_root / f"{manifest.worker_id}.sqlite3"
            source_paths.append(cache_path)
            if (
                not manifest.handoff_finalized
                or manifest.cache_snapshot_mode == "missing"
                or manifest.cache_sqlite_base64 is None
            ):
                continue
            try:
                payload = base64.b64decode(
                    manifest.cache_sqlite_base64.encode("ascii"),
                    validate=True,
                )
                if manifest.cache_sha256 is not None:
                    digest = hashlib.sha256(payload).hexdigest()
                    if digest != manifest.cache_sha256:
                        payload = b"invalid cache payload checksum"
            except (binascii.Error, ValueError, TypeError):
                payload = b"invalid cache payload base64"
            cache_path.write_bytes(payload)
        return source_paths

    def _cleanup_worker_state(self, *, batch_id: str, state_root: Path) -> None:
        workflow_paths = PathLayout(state_root).workflow
        cleanup_paths = [
            workflow_paths.batch_root(batch_id=batch_id),
            workflow_paths.worker_state_batch_root(batch_id=batch_id),
            workflow_paths.worker_status_batch_root(batch_id=batch_id),
        ]
        for cleanup_path in cleanup_paths:
            if cleanup_path.exists():
                shutil.rmtree(cleanup_path)

    def _log_start(
        self,
        *,
        batch_id: str,
        readiness: dict[str, Any],
        prepare_manifest: PrepareAggregateManifest,
    ) -> None:
        logger.debug(
            "Aggregate batch %s starting with readiness=%s derived_paths=%s",
            batch_id,
            readiness["state"],
            json.dumps(
                {
                    "final_filtered_path": prepare_manifest.aggregate_output_spec.filtered,
                    "final_unactionable_path": (
                        prepare_manifest.aggregate_output_spec.unactionable
                    ),
                    "final_review_path": prepare_manifest.aggregate_output_spec.review,
                    "final_audit_path": prepare_manifest.aggregate_output_spec.audit,
                    "final_log_path": prepare_manifest.aggregate_output_spec.log,
                    "final_cache_path": prepare_manifest.aggregate_output_spec.cache,
                    "preparation_review_row_count": len(
                        prepare_manifest.preparation_review_output_rows
                    ),
                    "preparation_terminal_row_count": len(
                        prepare_manifest.preparation_terminal_rows
                    ),
                },
                sort_keys=True,
            ),
        )

    def _log_output_summaries(
        self, *, batch_id: str, final_output_paths: dict[str, Path]
    ) -> None:
        logger.debug(
            "Aggregate output summaries for batch %s: %s",
            batch_id,
            json.dumps(
                {
                    "final_filtered": self._path_debug_summary(
                        final_output_paths["filtered"]
                    ),
                    "final_unactionable": self._path_debug_summary(
                        final_output_paths["unactionable"]
                    ),
                    "final_review": self._path_debug_summary(
                        final_output_paths["review"]
                    ),
                    "final_audit": self._path_debug_summary(
                        final_output_paths["audit"]
                    ),
                    "final_log": self._path_debug_summary(final_output_paths["log"]),
                    "final_cache": self._path_debug_summary(
                        final_output_paths["cache"]
                    ),
                },
                sort_keys=True,
            ),
        )

    def _path_debug_summary(self, path: Path) -> dict[str, Any]:
        summary: dict[str, Any] = {"path": relative_path(path), "exists": path.exists()}
        if not path.exists():
            return summary
        if path.is_dir():
            summary["kind"] = "directory"
            return summary
        summary["kind"] = "file"
        summary["bytes"] = path.stat().st_size
        if path.suffix in {".txt", ".jsonl", ".csv", ".log", ".json"}:
            with path.open("r", encoding="utf-8") as handle:
                summary["line_count"] = sum(1 for _ in handle)
        return summary

    def _write_json(self, path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def aggregate_batch(
    *,
    batch_id: str,
    state_root: Path,
) -> dict[str, Any]:
    """Run aggregate batch execution."""
    return AggregateBatchRunner().run(
        batch_id=batch_id,
        state_root=state_root,
    )
