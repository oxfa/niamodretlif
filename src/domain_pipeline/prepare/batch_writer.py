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
from domain_pipeline.prepare.source_line_index import (
    SourceLineIndex,
    SourceLineReference,
    write_source_line_index,
)
from domain_pipeline.prepare.source_items import SourceItemHandoff
from domain_pipeline.prepare.sources.parser import (
    DomainEntry,
    DomainListParser,
    InputFileFormat,
)
from domain_pipeline.worker.output.rows import PreparationReviewRowProjector


@dataclass
class PreparedBatch:
    """All committed batch artifacts written by the prepare step."""

    batch_id: str
    config_name: str
    prepare_aggregate_manifest: PrepareAggregateManifest
    worker_manifests: list[PreparedWorkerManifest]
    source_input_contents: list[str]
    source_line_index: SourceLineIndex
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
        (
            source_input_contents,
            source_line_index,
            manually_added_domains,
        ) = self.prepare_source_archive(prepared_inputs)
        planning_inputs = self.assignment_planner.planning_inputs_from_prepared(
            prepared_inputs
        )
        assignment_artifacts = self._build_worker_assignment_artifacts(
            planning_inputs=planning_inputs,
            prepared_inputs=prepared_inputs,
            worker_ids=worker_ids,
            batch_id=batch_id,
            input_record_count=sum(
                len(content.splitlines()) for content in source_input_contents
            )
            + len(manually_added_domains),
        )

        preparation_review_rows = prepared_inputs.preparation_review_rows
        preparation_terminal_rows = prepared_inputs.preparation_terminal_rows
        review_row_projector = PreparationReviewRowProjector()
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
                preparation_review_rows=[
                    dict(review_row_projector.project(row))
                    for row in preparation_review_rows
                ],
                preparation_terminal_rows=[
                    dict(row) for row in preparation_terminal_rows
                ],
            ),
            worker_manifests=assignment_artifacts.worker_manifests,
            source_input_contents=source_input_contents,
            source_line_index=source_line_index,
            source_item_handoff=source_item_handoff,
        )

    def prepare_source_archive(
        self, prepared_inputs: PreparedInputSet
    ) -> tuple[list[str], SourceLineIndex, list[ManuallyAddedDomain]]:
        """Archive configured sources and return unmatched manual domains separately."""
        parser = DomainListParser()
        contents, source_formats, references_by_domain = self._collect_source_lines(
            prepared_inputs, parser
        )
        source_hosts = {
            entry.host
            for content, source_format in zip(contents, source_formats, strict=True)
            for line in content.splitlines(keepends=True)
            for entry in parser.parse_source_line_entries(
                line, file_format=InputFileFormat(source_format)
            )
        }
        manually_added_entries = {
            host: entry
            for host, entry in prepared_inputs.manually_added_entries.items()
            if host not in source_hosts
        }
        manually_added_hosts = sorted(manually_added_entries)
        return (
            contents,
            SourceLineIndex(
                source_formats=tuple(source_formats),
                registrable_domain_lines={
                    domain: tuple(references)
                    for domain, references in references_by_domain.items()
                },
            ),
            [
                ManuallyAddedDomain(
                    host=host,
                    registrable_domain=manually_added_entries[host].registrable_domain,
                )
                for host in manually_added_hosts
            ],
        )

    @staticmethod
    def _collect_source_lines(
        prepared_inputs: PreparedInputSet, parser: DomainListParser
    ) -> tuple[list[str], list[str], dict[str, list[SourceLineReference]]]:
        """Archive prepared source lines and index their registrable domains."""
        contents: list[str] = []
        source_formats: list[str] = []
        references_by_domain: dict[str, list[SourceLineReference]] = {}
        for source_ordinal, source_job in enumerate(
            prepared_inputs.source_jobs_by_id.values()
        ):
            configured_format = source_job.config.get("input", {}).get("format", "auto")
            forced_format = None if configured_format == "auto" else configured_format
            file_format, prepared_lines = parser.prepare_source_lines(
                source_job.lines,
                source_name=source_job.input_label,
                forced_format=forced_format,
            )
            source_formats.append(file_format.value)
            retained_lines: list[str] = []
            for prepared_line in prepared_lines:
                retained_lines.append(prepared_line.content)
                line_number = len(retained_lines)
                for registrable_domain in sorted(
                    {
                        entry.registrable_domain
                        for entry in prepared_line.entries
                        if entry.registrable_domain
                    }
                ):
                    references_by_domain.setdefault(str(registrable_domain), []).append(
                        SourceLineReference(
                            source_ordinal=source_ordinal,
                            line_number=line_number,
                        )
                    )
            contents.append("".join(retained_lines))

        return contents, source_formats, references_by_domain

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
        for source_ordinal, content in enumerate(prepared.source_input_contents):
            source_path = paths.batch_source_input_path(
                batch_id=prepared.batch_id, source_ordinal=source_ordinal
            )
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_text(content, encoding="utf-8")
            committed_paths.append(relative_path(source_path.relative_to(state_root)))
        index_path = paths.batch_source_line_index_path(batch_id=prepared.batch_id)
        formats_path = paths.batch_source_formats_path(batch_id=prepared.batch_id)
        write_source_line_index(prepared.source_line_index, index_path, formats_path)
        committed_paths.extend(
            relative_path(path.relative_to(state_root))
            for path in (index_path, formats_path)
        )
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
