"""Prepare-step worker assignment owner."""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain_pipeline.paths.layout import PathLayout, WorkflowStatePathLayout
from domain_pipeline.pipeline_run.format_version import PIPELINE_RUN_FORMAT_VERSION
from domain_pipeline.prepare.models import (
    PreparedInputSet,
    PreparedRootPlan,
)
from domain_pipeline.prepare.prepare_to_aggregate_manifest import (
    AggregateOutputSpec,
)
from domain_pipeline.prepare.prepare_to_worker_manifest import (
    PreparedDelegationRootMetadata,
    PreparedRuntimeMetadata,
    PrepareWorkerManifest,
    WorkerOutputSpec,
    WorkerRuntimeSpec,
)
from domain_pipeline.prepare.sources.parser import DomainEntry

logger = logging.getLogger(__name__)


def _workflow_paths() -> WorkflowStatePathLayout:
    """Return repo-relative workflow path ownership."""
    return PathLayout(Path(".")).workflow_state


def _path_layout() -> PathLayout:
    """Return repo-relative role path ownership."""
    return PathLayout(Path("."))


@dataclass
class PreparedWorkerManifest:
    """One committed prepare-to-worker manifest written by the prepare step."""

    worker_id: str
    manifest: PrepareWorkerManifest


@dataclass(frozen=True)
class PreparedBatchPlanningInputs:
    """All batch-planning inputs collected before worker assignment starts."""

    source_jobs_by_id: dict[str, Any]
    eligible_root_entries: dict[str, list[tuple[str, DomainEntry]]]
    public_suffix_entries: list[tuple[str, DomainEntry]]
    root_plans: dict[str, PreparedRootPlan]


@dataclass(frozen=True)
class WorkerManifestBuildRequest:
    """Inputs needed to build prepare-to-worker manifests for one batch."""

    config: dict[str, Any]
    batch_id: str
    worker_ids: list[str]
    worker_source_entries: dict[str, dict[str, list[DomainEntry]]]
    worker_root_plans: dict[str, dict[str, PreparedRootPlan]]
    source_jobs_by_id: dict[str, Any]


def relative_path(path: Path) -> str:
    """Return the repo-relative path representation stored in manifests."""
    return path.as_posix()


def _validate_publish_output_path(output_path: Path, *, field_name: str) -> str:
    """Return one safe repo-relative publish path."""
    if (
        not output_path.parts
        or output_path == Path(".")
        or output_path.is_absolute()
        or "\\" in output_path.as_posix()
        or ".." in output_path.parts
    ):
        raise ValueError(
            f"output.{field_name} paths must be relative paths inside the publish "
            "worktree"
        )
    return output_path.as_posix()


def aggregate_output_spec_from_config(config: dict[str, Any]) -> AggregateOutputSpec:
    """Return manifest-persisted aggregate paths derived during preparation."""
    enabled_sources = [
        source for source in config["sources"] if source.get("enabled", True)
    ]
    if not enabled_sources:
        raise ValueError("config must include at least one enabled source")
    output_config = config["output"]
    config_name = str(config["config_name"])
    aggregate_paths = _path_layout().aggregate_paths(
        config_name=config_name,
    )
    filtered_outputs = []
    for configured_output in output_config.get("filtered", []):
        filtered_outputs.append(
            {
                "path": _validate_publish_output_path(
                    Path(str(configured_output["path"])),
                    field_name="filtered[].path",
                ),
                "format": configured_output["format"],
            }
        )
    return AggregateOutputSpec(
        filtered=filtered_outputs,
        unactionable=_validate_publish_output_path(
            Path(str(output_config["unactionable"])),
            field_name="unactionable",
        ),
        review=_validate_publish_output_path(
            Path(str(output_config["review"])),
            field_name="review",
        ),
        audit=relative_path(aggregate_paths.raw_audit),
        log=relative_path(aggregate_paths.runtime_log),
        cache=relative_path(aggregate_paths.cache),
    )


class WorkerAssignmentPlanner:
    """Assign prepared roots to worker-owned runtime bundles."""

    def planning_inputs_from_prepared(
        self, prepared_inputs: PreparedInputSet
    ) -> PreparedBatchPlanningInputs:
        """Project prepared inputs into worker-planning inputs."""
        eligible_root_entries, public_suffix_entries = (
            prepared_inputs.split_entries_for_planning()
        )
        return PreparedBatchPlanningInputs(
            source_jobs_by_id=prepared_inputs.source_jobs_by_id,
            eligible_root_entries=eligible_root_entries,
            public_suffix_entries=public_suffix_entries,
            root_plans=prepared_inputs.root_plans,
        )

    def assign(
        self,
        *,
        planning_inputs: PreparedBatchPlanningInputs,
        worker_ids: list[str],
    ) -> tuple[
        dict[str, dict[str, list[DomainEntry]]],
        dict[str, dict[str, PreparedRootPlan]],
        Counter,
    ]:
        """Assign prepared entries across workers while keeping each root atomic."""
        worker_source_entries: dict[str, dict[str, list[DomainEntry]]] = {
            worker_id: defaultdict(list) for worker_id in worker_ids
        }
        worker_root_plans: dict[str, dict[str, PreparedRootPlan]] = {
            worker_id: {} for worker_id in worker_ids
        }
        worker_root_counts: Counter = Counter()

        def assign_root(worker_id: str, registrable_domain: str) -> None:
            for source_id, entry in self._ordered_entries_for_root(
                planning_inputs, registrable_domain
            ):
                worker_source_entries[worker_id][source_id].append(entry)
            worker_root_plans[worker_id][registrable_domain] = (
                planning_inputs.root_plans[registrable_domain]
            )
            worker_root_counts[worker_id] += 1
            plan = planning_inputs.root_plans[registrable_domain]
            logger.debug(
                "Batch preparation assigned root=%s status=%s worker=%s",
                registrable_domain,
                plan.status,
                worker_id,
            )

        for registrable_domain in sorted(planning_inputs.root_plans):
            worker_id = min(
                worker_ids,
                key=lambda current_worker_id: (
                    worker_root_counts[current_worker_id],
                    current_worker_id,
                ),
            )
            assign_root(worker_id, registrable_domain)

        self._log_summary(
            worker_ids=worker_ids,
            worker_root_counts=worker_root_counts,
        )
        return worker_source_entries, worker_root_plans, worker_root_counts

    def build_worker_manifests(
        self, request: WorkerManifestBuildRequest
    ) -> list[PreparedWorkerManifest]:
        """Return the committed prepare-to-worker manifests for participating workers."""
        manifests: list[PreparedWorkerManifest] = []
        for worker_id in request.worker_ids:
            selected_runtime_source_id_values = set(
                request.worker_source_entries[worker_id]
            )
            selected_runtime_source_id_values.update(
                plan.delegation_config_source_id
                for plan in request.worker_root_plans[worker_id].values()
            )
            manifests.append(
                PreparedWorkerManifest(
                    worker_id=worker_id,
                    manifest=PrepareWorkerManifest(
                        automation_format_version=PIPELINE_RUN_FORMAT_VERSION,
                        worker_id=worker_id,
                        batch_id=request.batch_id,
                        runtime_spec=self._build_worker_runtime_spec(
                            config=request.config,
                            batch_id=request.batch_id,
                            worker_id=worker_id,
                            selected_runtime_source_id_values=(
                                selected_runtime_source_id_values
                            ),
                        ),
                        prepared_metadata=self._prepared_runtime_metadata_from_assignment(
                            source_entries=request.worker_source_entries[worker_id],
                            root_plans=request.worker_root_plans[worker_id],
                        ),
                    ),
                )
            )
        return manifests

    def _build_worker_runtime_spec(
        self,
        *,
        config: dict[str, Any],
        batch_id: str,
        worker_id: str,
        selected_runtime_source_id_values: set[str],
    ) -> WorkerRuntimeSpec:
        config_name = str(config["config_name"])
        worker_paths = _path_layout().worker_paths(
            batch_id=batch_id,
            worker_id=worker_id,
            config_name=config_name,
        )
        source_configs: list[dict[str, Any]] = []
        for source_config in config["sources"]:
            if (
                not source_config["enabled"]
                or source_config["id"] not in selected_runtime_source_id_values
            ):
                continue
            selected_source = json.loads(json.dumps(source_config))
            selected_source["output"] = {
                "directory": relative_path(worker_paths.output_directory)
            }
            source_configs.append(selected_source)
        included_runtime_source_id_values = {
            str(source["id"]) for source in source_configs
        }
        missing_runtime_source_id_values = sorted(
            selected_runtime_source_id_values - included_runtime_source_id_values
        )
        if missing_runtime_source_id_values:
            raise ValueError(
                "worker runtime spec references unavailable configured sources: "
                + ", ".join(missing_runtime_source_id_values)
            )
        return WorkerRuntimeSpec.model_validate(
            {
                "config_name": config_name,
                "cache": {
                    "cache_file": relative_path(worker_paths.cache),
                    "baseline_cache_file": relative_path(
                        _workflow_paths().runtime_cache_path()
                    ),
                    "delegation_ttl_days": json.loads(
                        json.dumps(config["cache"]["delegation_ttl_days"])
                    ),
                    "host_resolution_ttl_days": json.loads(
                        json.dumps(config["cache"]["host_resolution_ttl_days"])
                    ),
                },
                "runtime": json.loads(json.dumps(config.get("runtime", {}))),
                "sources": source_configs,
                "output_spec": WorkerOutputSpec(
                    result_root=relative_path(worker_paths.result_root),
                    unactionable=relative_path(worker_paths.unactionable),
                    review=relative_path(worker_paths.review),
                    terminal_rows=relative_path(worker_paths.terminal_rows),
                    cache=relative_path(worker_paths.cache),
                ).model_dump(mode="json"),
                "debug_log_path": relative_path(worker_paths.debug_log),
            },
        )

    def _prepared_runtime_metadata_from_assignment(
        self,
        *,
        source_entries: dict[str, list[DomainEntry]],
        root_plans: dict[str, PreparedRootPlan],
    ) -> PreparedRuntimeMetadata:
        entries_by_root: dict[str, list[DomainEntry]] = defaultdict(list)
        for entries in source_entries.values():
            for entry in entries:
                if entry.registrable_domain is not None:
                    entries_by_root[entry.registrable_domain].append(entry)
        missing_roots = sorted(set(entries_by_root) - set(root_plans))
        if missing_roots:
            raise ValueError(
                "worker assignment missing delegation root metadata for "
                + ", ".join(missing_roots)
            )
        extra_roots = sorted(set(root_plans) - set(entries_by_root))
        if extra_roots:
            raise ValueError(
                "worker assignment has delegation root metadata without entries for "
                + ", ".join(extra_roots)
            )
        for registrable_domain, entries in entries_by_root.items():
            plan = root_plans[registrable_domain]
            if plan.entry_count != len(entries):
                raise ValueError(
                    "delegation root entry_count mismatch for "
                    f"{registrable_domain}: metadata={plan.entry_count} "
                    f"entries={len(entries)}"
                )
            if not plan.delegation_config_source_id:
                raise ValueError(
                    "delegation root "
                    f"{registrable_domain} is missing delegation config source"
                )
        return PreparedRuntimeMetadata(
            delegation_roots={
                registrable_domain: PreparedDelegationRootMetadata(
                    delegation_config_source_id=root_plans[
                        registrable_domain
                    ].delegation_config_source_id,
                    delegation_behavior_fingerprint=root_plans[
                        registrable_domain
                    ].delegation_behavior_fingerprint,
                )
                for registrable_domain in sorted(entries_by_root)
            },
        )

    def _ordered_entries_for_root(
        self,
        planning_inputs: PreparedBatchPlanningInputs,
        registrable_domain: str,
    ) -> list[tuple[str, DomainEntry]]:
        source_order_by_id = self._source_order_by_id(planning_inputs.source_jobs_by_id)
        return sorted(
            planning_inputs.eligible_root_entries[registrable_domain],
            key=lambda entry: (
                source_order_by_id[entry[0]],
                entry[1].host,
            ),
        )

    @staticmethod
    def _source_order_by_id(source_jobs_by_id: dict[str, Any]) -> dict[str, int]:
        """Return source-order indexes from the prepared source-job mapping."""
        return {
            source_id: source_index
            for source_index, source_id in enumerate(source_jobs_by_id)
        }

    def _log_summary(
        self,
        *,
        worker_ids: list[str],
        worker_root_counts: Counter,
    ) -> None:
        worker_summaries = [
            {
                "worker_id": worker_id,
                "delegation_root_count": worker_root_counts[worker_id],
            }
            for worker_id in worker_ids
        ]
        logger.debug("Batch preparation worker totals=%s", worker_summaries)
