"""Prepare-step batch planning and artifact writing owner."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from domain_pipeline.paths.layout import PathLayout
from domain_pipeline.prepare.assignment import (
    PreparedBatchPlanningInputs,
    PreparedWorkerManifest,
    WorkerAssignmentPlanner,
    WorkerManifestBuildRequest,
    aggregate_output_spec_from_config,
    relative_path,
)
from domain_pipeline.prepare.models import PreparedInputSet
from domain_pipeline.prepare.planner import PreparationPlanner
from domain_pipeline.prepare.prepare_to_aggregate_manifest import (
    ManuallyAddedDomain,
    PrepareAggregateManifest,
    write_prepare_aggregate_handoff,
)
from domain_pipeline.prepare.prepare_to_worker_manifest import (
    write_prepare_worker_handoff,
)
from domain_pipeline.prepare.source_items import SourceItemHandoff


@dataclass
class PreparedBatch:
    """All committed batch artifacts written by the prepare step."""

    batch_id: str
    config_name: str
    prepare_aggregate_manifest: PrepareAggregateManifest
    worker_manifests: list[PreparedWorkerManifest]
    source_item_handoff: SourceItemHandoff


@dataclass(frozen=True)
class _WorkerAssignmentArtifacts:
    worker_manifests: list[PreparedWorkerManifest]


class PreparedBatchWriter:
    """Write prepare-owned worker and aggregate handoffs."""

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
        source_item_handoff = SourceItemHandoff.build(
            batch_id=batch_id,
            prepared_inputs=prepared_inputs,
        )
        valid_source_hosts = source_item_handoff.valid_source_hosts
        manually_added_domains = [
            ManuallyAddedDomain(host=host, registrable_domain=entry.registrable_domain)
            for host, entry in sorted(prepared_inputs.manually_added_entries.items())
            if host not in valid_source_hosts
        ]
        planning_inputs = self.assignment_planner.planning_inputs_from_prepared(
            prepared_inputs
        )
        assignment_artifacts = self._build_worker_assignment_artifacts(
            planning_inputs=planning_inputs,
            prepared_inputs=prepared_inputs,
            worker_ids=worker_ids,
            batch_id=batch_id,
            input_record_count=(
                source_item_handoff.retained_line_count + len(manually_added_domains)
            ),
        )

        return PreparedBatch(
            batch_id=batch_id,
            config_name=config_name,
            prepare_aggregate_manifest=PrepareAggregateManifest(
                batch_id=batch_id,
                config_name=config_name,
                aggregate_output_spec=aggregate_output_spec_from_config(
                    prepared_inputs.config
                ),
                worker_ids=[
                    manifest.worker_id
                    for manifest in assignment_artifacts.worker_manifests
                ],
                excluded_source_hosts=sorted(prepared_inputs.excluded_source_hosts),
                manually_added_domains=manually_added_domains,
                preparation_terminal_rows=prepared_inputs.preparation_terminal_rows,
            ),
            worker_manifests=assignment_artifacts.worker_manifests,
            source_item_handoff=source_item_handoff,
        )

    def _build_worker_assignment_artifacts(
        self,
        *,
        planning_inputs: PreparedBatchPlanningInputs,
        prepared_inputs: PreparedInputSet,
        worker_ids: list[str],
        batch_id: str,
        input_record_count: int,
    ) -> _WorkerAssignmentArtifacts:
        total_work_units = sum(
            plan.entry_count for plan in planning_inputs.root_plans.values()
        )
        if (
            total_work_units < 1
            and not prepared_inputs.preparation_terminal_rows
            and input_record_count < 1
        ):
            raise ValueError("config produced no input lines to process")
        if total_work_units > 0 and not worker_ids:
            raise ValueError("at least one worker_id is required to prepare a batch")
        worker_root_plans, _ = self.assignment_planner.assign(
            planning_inputs=planning_inputs,
            worker_ids=worker_ids,
        )
        return _WorkerAssignmentArtifacts(
            worker_manifests=self.assignment_planner.build_worker_manifests(
                WorkerManifestBuildRequest(
                    config=prepared_inputs.config,
                    batch_id=batch_id,
                    worker_ids=worker_ids,
                    worker_root_plans=worker_root_plans,
                )
            ),
        )

    def write(self, prepared: PreparedBatch, *, state_root: Path) -> list[str]:
        """Write one prepared batch to disk and return committed repo-relative paths."""
        committed_paths = [
            relative_path(path.relative_to(state_root))
            for path in write_prepare_aggregate_handoff(
                prepared.prepare_aggregate_manifest, state_root=state_root
            )
        ]
        paths = PathLayout(state_root).workflow_state
        item_paths = prepared.source_item_handoff.write(
            items_path=paths.batch_source_items_path(batch_id=prepared.batch_id),
            index_path=paths.batch_source_item_index_path(batch_id=prepared.batch_id),
            diagnostics_path=paths.batch_source_item_diagnostics_path(
                batch_id=prepared.batch_id
            ),
        )
        committed_paths.extend(
            relative_path(path.relative_to(state_root)) for path in item_paths
        )
        for worker in prepared.worker_manifests:
            committed_paths.extend(
                relative_path(path.relative_to(state_root))
                for path in write_prepare_worker_handoff(
                    worker.manifest, state_root=state_root
                )
            )
        return sorted(committed_paths)


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
