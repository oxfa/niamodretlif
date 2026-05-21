"""Prepare-step worker assignment owner."""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain_pipeline.prepare.prepare_to_aggregate_manifest import (
    AggregateOutputSpec,
)
from domain_pipeline.prepare.prepare_to_worker_manifest import (
    PrepareWorkerManifest,
    PreparedDelegationRootMetadata,
    PreparedHostEntryMetadata,
    PreparedRuntimeMetadata,
    WorkerOutputSpec,
    WorkerRuntimeSpec,
)
from domain_pipeline.paths.layout import PathLayout, WorkflowPathLayout
from domain_pipeline.prepare.models import (
    PreparedHostEntry,
    PreparedInputSet,
    PreparedRootPlan,
)

PIPELINE_RUN_FORMAT_VERSION = 2
logger = logging.getLogger(__name__)


def _workflow_paths() -> WorkflowPathLayout:
    """Return repo-relative workflow path ownership."""
    return PathLayout(Path(".")).workflow


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
    eligible_root_entries: dict[str, list[PreparedHostEntry]]
    public_suffix_entries: list[PreparedHostEntry]
    root_plans: dict[str, PreparedRootPlan]


@dataclass(frozen=True)
class WorkerManifestBuildRequest:
    """Inputs needed to build prepare-to-worker manifests for one batch."""

    config: dict[str, Any]
    batch_id: str
    worker_ids: list[str]
    worker_source_entries: dict[str, dict[str, list[PreparedHostEntry]]]
    worker_root_plans: dict[str, dict[str, PreparedRootPlan]]


def relative_path(path: Path) -> str:
    """Return the repo-relative path representation stored in manifests."""
    return path.as_posix()


def prepare_aggregate_manifest_relative_path(*, batch_id: str) -> Path:
    """Return the committed prepare-to-aggregate manifest path for one batch."""
    return _path_layout().batch_paths(batch_id=batch_id).prepare_aggregate_manifest


def prepare_worker_manifest_relative_path(*, batch_id: str, worker_id: str) -> Path:
    """Return the committed prepare-to-worker manifest path for one worker."""
    return (
        _path_layout()
        .batch_paths(batch_id=batch_id)
        .prepare_worker_manifest(worker_id=worker_id)
    )


def aggregate_output_spec_from_config(config: dict[str, Any]) -> AggregateOutputSpec:
    """Return manifest-persisted aggregate paths derived during preparation."""
    enabled_sources = [
        source for source in config["sources"] if source.get("enabled", True)
    ]
    if not enabled_sources:
        raise ValueError("config must include at least one enabled source")
    output_directory = Path(str(enabled_sources[0]["output"]["directory"]))
    config_name = str(config["config_name"])
    aggregate_paths = _path_layout().aggregate_paths(
        config_name=config_name,
        output_directory=output_directory,
    )
    return AggregateOutputSpec(
        filtered=relative_path(aggregate_paths.filtered),
        unactionable=relative_path(aggregate_paths.unactionable),
        review=relative_path(aggregate_paths.review),
        audit=relative_path(aggregate_paths.raw_audit),
        log=relative_path(aggregate_paths.runtime_log),
        cache=relative_path(aggregate_paths.cache),
    )


def prepared_entry_payload(entry: PreparedHostEntry) -> dict[str, Any]:
    """Serialize one root-owned prepared host entry for worker runtime."""
    return {
        "host": entry.entry.host,
        "input_name": entry.entry.semantics.input_name,
        "source_id": entry.position.source_id,
        "input_kind": entry.entry.semantics.input_kind,
        "apex_scope": entry.entry.semantics.apex_scope,
        "source_format": entry.entry.semantics.source_format,
        "manual_filter_pass": entry.provenance.manual_filter_pass,
        "manual_add": entry.provenance.manual_add,
        "source_id_override": entry.provenance.source_id_override,
        "source_input_label_override": entry.provenance.source_input_label_override,
        "source_ids": list(entry.provenance.source_ids),
        "source_input_labels": list(entry.provenance.source_input_labels),
    }


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
        dict[str, dict[str, list[PreparedHostEntry]]],
        dict[str, dict[str, PreparedRootPlan]],
        Counter,
    ]:
        """Assign prepared entries across workers while keeping each root atomic."""
        worker_source_entries: dict[str, dict[str, list[PreparedHostEntry]]] = {
            worker_id: defaultdict(list) for worker_id in worker_ids
        }
        worker_root_plans: dict[str, dict[str, PreparedRootPlan]] = {
            worker_id: {} for worker_id in worker_ids
        }
        worker_entry_counts: Counter = Counter()
        worker_root_counts: Counter = Counter()
        root_entry_counts = {
            registrable_domain: len(entries)
            for registrable_domain, entries in planning_inputs.eligible_root_entries.items()
        }

        def assign_root(worker_id: str, registrable_domain: str) -> None:
            for prepared_entry in self._ordered_entries_for_root(
                planning_inputs, registrable_domain
            ):
                worker_source_entries[worker_id][
                    prepared_entry.position.source_id
                ].append(prepared_entry)
            worker_root_plans[worker_id][registrable_domain] = (
                planning_inputs.root_plans[registrable_domain]
            )
            worker_entry_counts[worker_id] += root_entry_counts[registrable_domain]
            worker_root_counts[worker_id] += 1
            plan = planning_inputs.root_plans[registrable_domain]
            logger.debug(
                "Batch preparation assigned root=%s status=%s worker=%s entry_count=%d",
                registrable_domain,
                plan.status,
                worker_id,
                root_entry_counts[registrable_domain],
            )

        for registrable_domain in sorted(
            planning_inputs.root_plans,
            key=lambda root: (-root_entry_counts[root], root),
        ):
            worker_id = min(
                worker_ids,
                key=lambda current_worker_id: (
                    worker_entry_counts[current_worker_id],
                    worker_root_counts[current_worker_id],
                    current_worker_id,
                ),
            )
            assign_root(worker_id, registrable_domain)

        self._log_summary(
            worker_ids=worker_ids,
            worker_root_plans=worker_root_plans,
            worker_entry_counts=worker_entry_counts,
        )
        return worker_source_entries, worker_root_plans, worker_entry_counts

    def build_worker_manifests(
        self, request: WorkerManifestBuildRequest
    ) -> list[PreparedWorkerManifest]:
        """Return the committed prepare-to-worker manifests for participating workers."""
        manifests: list[PreparedWorkerManifest] = []
        for worker_id in request.worker_ids:
            if not request.worker_source_entries[worker_id]:
                continue
            selected_source_ids = set(request.worker_source_entries[worker_id])
            selected_source_ids.update(
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
                            selected_source_ids=selected_source_ids,
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
        selected_source_ids: set[str],
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
                or source_config["id"] not in selected_source_ids
            ):
                continue
            selected_source = json.loads(json.dumps(source_config))
            selected_source["output"]["directory"] = relative_path(
                worker_paths.output_directory
            )
            source_configs.append(selected_source)
        included_source_ids = {str(source["id"]) for source in source_configs}
        missing_source_ids = sorted(selected_source_ids - included_source_ids)
        if missing_source_ids:
            raise ValueError(
                "worker runtime spec references unavailable configured sources: "
                + ", ".join(missing_source_ids)
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
                    filtered=relative_path(worker_paths.filtered),
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
        source_entries: dict[str, list[PreparedHostEntry]],
        root_plans: dict[str, PreparedRootPlan],
    ) -> PreparedRuntimeMetadata:
        entries_by_root: dict[str, list[PreparedHostEntry]] = defaultdict(list)
        for entries in source_entries.values():
            for entry in entries:
                if entry.entry.registrable_domain:
                    entries_by_root[entry.entry.registrable_domain].append(entry)
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
            public_suffixes = {entry.entry.semantics.public_suffix for entry in entries}
            if len(public_suffixes) != 1:
                raise ValueError(
                    "delegation root "
                    f"{registrable_domain} has inconsistent public suffix metadata"
                )
        return PreparedRuntimeMetadata(
            delegation_roots={
                registrable_domain: PreparedDelegationRootMetadata(
                    public_suffix=entries[0].entry.semantics.public_suffix,
                    delegation_config_source_id=(
                        root_plans[registrable_domain].delegation_config_source_id
                    ),
                    delegation_behavior_fingerprint=(
                        root_plans[registrable_domain].delegation_behavior_fingerprint
                    ),
                    host_entries=[
                        PreparedHostEntryMetadata(**prepared_entry_payload(entry))
                        for entry in sorted(
                            entries,
                            key=lambda current: (
                                current.position.source_index,
                                current.position.line_index,
                                current.entry.host,
                            ),
                        )
                    ],
                )
                for registrable_domain, entries in sorted(entries_by_root.items())
            },
        )

    def _ordered_entries_for_root(
        self,
        planning_inputs: PreparedBatchPlanningInputs,
        registrable_domain: str,
    ) -> list[PreparedHostEntry]:
        return sorted(
            planning_inputs.eligible_root_entries[registrable_domain],
            key=lambda entry: (
                entry.position.source_index,
                entry.position.line_index,
                entry.entry.host,
            ),
        )

    def _log_summary(
        self,
        *,
        worker_ids: list[str],
        worker_root_plans: dict[str, dict[str, PreparedRootPlan]],
        worker_entry_counts: Counter,
    ) -> None:
        worker_summaries = [
            {
                "worker_id": worker_id,
                "entry_count": worker_entry_counts[worker_id],
                "delegation_root_count": len(worker_root_plans[worker_id]),
            }
            for worker_id in worker_ids
        ]
        logger.debug("Batch preparation worker totals=%s", worker_summaries)
