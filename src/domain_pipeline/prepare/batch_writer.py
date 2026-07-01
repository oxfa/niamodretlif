"""Prepare-step batch planning and artifact writing owner."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from domain_pipeline.prepare.prepare_to_aggregate_manifest import (
    PrepareAggregateManifest,
)
from domain_pipeline.prepare.assignment import (
    PIPELINE_RUN_FORMAT_VERSION,
    PreparedBatchPlanningInputs,
    PreparedWorkerManifest,
    WorkerAssignmentPlanner,
    WorkerManifestBuildRequest,
    aggregate_output_spec_from_config,
    prepare_aggregate_manifest_relative_path,
    prepare_worker_manifest_relative_path,
    relative_path,
)
from domain_pipeline.prepare.models import PreparedHostEntry, PreparedInputSet
from domain_pipeline.prepare.planner import PreparationPlanner
from domain_pipeline.worker.output.manager import txt_output_value
from domain_pipeline.worker.output.rows import ReviewRowProjector


@dataclass
class PreparedBatch:
    """All committed batch artifacts written by the prepare step."""

    batch_id: str
    config_name: str
    prepare_aggregate_manifest: PrepareAggregateManifest
    worker_manifests: list[PreparedWorkerManifest]
    preparation_filtered_output_values: list[str]
    preparation_review_rows: list[dict[str, Any]]
    preparation_terminal_rows: list[dict[str, Any]]


@dataclass(frozen=True)
class _WorkerAssignmentArtifacts:
    worker_source_entries: dict[str, dict[str, list[PreparedHostEntry]]]
    worker_manifests: list[PreparedWorkerManifest]


class PreparedBatchWriter:
    """Write prepare-owned worker and aggregate JSON handoffs."""

    def __init__(
        self,
        *,
        assignment_planner: WorkerAssignmentPlanner | None = None,
        preparation_planner: PreparationPlanner | None = None,
    ) -> None:
        self.assignment_planner = assignment_planner or WorkerAssignmentPlanner()
        self.preparation_planner = preparation_planner

    def prepare_batch(
        self,
        *,
        source_root: Path,
        config_path: Path,
        worker_ids: list[str],
        batch_id: str,
    ) -> PreparedBatch:
        """Build one committed batch worth of manifests and aggregate partials."""
        preparation_planner = self.preparation_planner or PreparationPlanner(
            source_root=source_root
        )
        prepared_inputs = preparation_planner.prepare(config_path=config_path)
        return self.from_prepared_inputs(
            prepared_inputs=prepared_inputs,
            worker_ids=worker_ids,
            batch_id=batch_id,
        )

    def from_prepared_inputs(
        self,
        *,
        prepared_inputs: PreparedInputSet,
        worker_ids: list[str],
        batch_id: str,
    ) -> PreparedBatch:
        """Build a batch from already-prepared input metadata."""
        config_name = str(prepared_inputs.config["config_name"])
        planning_inputs = self.assignment_planner.planning_inputs_from_prepared(
            prepared_inputs
        )
        assignment_artifacts = self._build_worker_assignment_artifacts(
            planning_inputs=planning_inputs,
            prepared_inputs=prepared_inputs,
            worker_ids=worker_ids,
            batch_id=batch_id,
        )

        matched_manual_hosts = {
            entry.entry.host
            for source_entries in assignment_artifacts.worker_source_entries.values()
            for entries in source_entries.values()
            for entry in entries
            if entry.provenance.manually_selected_for_filtered
        }
        preparation_review_rows = [
            row
            for row in prepared_inputs.preparation_review_rows
            if row["host"] not in matched_manual_hosts
        ]
        preparation_terminal_rows = [
            row
            for row in prepared_inputs.preparation_terminal_rows
            if row["host"] not in matched_manual_hosts
        ]
        preparation_filtered_output_values = sorted(
            txt_output_value(row)
            for row in preparation_terminal_rows
            if row.get("route") == "filtered"
        )
        review_row_projector = ReviewRowProjector()
        return PreparedBatch(
            batch_id=batch_id,
            config_name=config_name,
            prepare_aggregate_manifest=PrepareAggregateManifest(
                automation_format_version=PIPELINE_RUN_FORMAT_VERSION,
                batch_id=batch_id,
                aggregate_output_spec=aggregate_output_spec_from_config(
                    prepared_inputs.config
                ),
                worker_ids=[
                    manifest.worker_id
                    for manifest in assignment_artifacts.worker_manifests
                ],
                preparation_filtered_output_values=preparation_filtered_output_values,
                preparation_review_output_rows=[
                    cast(dict[str, str], dict(review_row_projector.project(row)))
                    for row in preparation_review_rows
                ],
                preparation_terminal_rows=[
                    dict(row) for row in preparation_terminal_rows
                ],
            ),
            worker_manifests=assignment_artifacts.worker_manifests,
            preparation_filtered_output_values=preparation_filtered_output_values,
            preparation_review_rows=preparation_review_rows,
            preparation_terminal_rows=preparation_terminal_rows,
        )

    def _build_worker_assignment_artifacts(
        self,
        *,
        planning_inputs: PreparedBatchPlanningInputs,
        prepared_inputs: PreparedInputSet,
        worker_ids: list[str],
        batch_id: str,
    ) -> _WorkerAssignmentArtifacts:
        total_work_units = len(planning_inputs.root_plans)
        if (
            total_work_units < 1
            and not prepared_inputs.preparation_terminal_rows
            and prepared_inputs.parsed_source_entry_count < 1
        ):
            raise ValueError("config produced no input lines to process")
        participating_worker_ids = worker_ids[: min(len(worker_ids), total_work_units)]
        if total_work_units > 0 and not participating_worker_ids:
            raise ValueError("at least one worker_id is required to prepare a batch")
        if not participating_worker_ids:
            return _WorkerAssignmentArtifacts(
                worker_source_entries={},
                worker_manifests=[],
            )
        worker_source_entries, worker_root_plans, _worker_entry_counts = (
            self.assignment_planner.assign(
                planning_inputs=planning_inputs,
                worker_ids=participating_worker_ids,
            )
        )
        return _WorkerAssignmentArtifacts(
            worker_source_entries=worker_source_entries,
            worker_manifests=self.assignment_planner.build_worker_manifests(
                WorkerManifestBuildRequest(
                    config=prepared_inputs.config,
                    batch_id=batch_id,
                    worker_ids=participating_worker_ids,
                    worker_source_entries=worker_source_entries,
                    worker_root_plans=worker_root_plans,
                )
            ),
        )

    def write(self, prepared: PreparedBatch, *, state_root: Path) -> list[str]:
        """Write one prepared batch to disk and return committed repo-relative paths."""
        committed_paths: list[str] = []
        aggregate_manifest_path = prepare_aggregate_manifest_relative_path(
            batch_id=prepared.batch_id
        )
        self._write_json(
            state_root / aggregate_manifest_path,
            prepared.prepare_aggregate_manifest.model_dump(mode="json"),
        )
        committed_paths.append(relative_path(aggregate_manifest_path))
        for worker_manifest in prepared.worker_manifests:
            manifest_path = prepare_worker_manifest_relative_path(
                batch_id=prepared.batch_id,
                worker_id=worker_manifest.worker_id,
            )
            self._write_json(
                state_root / manifest_path,
                worker_manifest.manifest.model_dump(mode="json"),
            )
            committed_paths.append(relative_path(manifest_path))
        return sorted(committed_paths)

    def _write_json(self, path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def prepare_batch(
    *,
    source_root: Path,
    config_path: Path,
    worker_ids: list[str],
    batch_id: str,
) -> PreparedBatch:
    """Build one prepared batch from workflow command inputs."""
    return PreparedBatchWriter().prepare_batch(
        source_root=source_root,
        config_path=config_path,
        worker_ids=worker_ids,
        batch_id=batch_id,
    )


def write_prepared_batch(prepared: PreparedBatch, *, state_root: Path) -> list[str]:
    """Persist prepare-owned batch handoff artifacts."""
    return PreparedBatchWriter().write(prepared, state_root=state_root)
