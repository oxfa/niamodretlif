"""Prepare-step worker assignment owner."""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain_pipeline.prepare.aggregate_manifest import (
    AggregateOutputSpec,
    ConfigIdentity as AggregateConfigIdentity,
)
from domain_pipeline.prepare.worker_manifest import (
    ConfigIdentity as WorkerConfigIdentity,
    PrepareWorkerManifest,
    PreparedRuntimeMetadata,
    WorkerOutputSpec,
    WorkerRuntimeSpec,
)
from domain_pipeline.paths import PathLayout, WorkflowPathLayout
from domain_pipeline.prepare.models import (
    PreparedHostEntry,
    PreparedInputSet,
    PreparedRootPlan,
    root_plan_runtime_payload,
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


def worker_config_identity_from_config(config: dict[str, Any]) -> WorkerConfigIdentity:
    """Return the worker-manifest config identity captured during preparation."""
    config_path = Path(str(config["config_path"]))
    return WorkerConfigIdentity(
        config_name=str(config["config_name"]),
        config_path=str(config_path),
        config_file_name=config_path.name,
    )


def aggregate_config_identity_from_config(
    config: dict[str, Any],
) -> AggregateConfigIdentity:
    """Return the aggregate-manifest config identity captured during preparation."""
    config_path = Path(str(config["config_path"]))
    return AggregateConfigIdentity(
        config_name=str(config["config_name"]),
        config_path=str(config_path),
        config_file_name=config_path.name,
    )


def aggregate_output_spec_from_config(config: dict[str, Any]) -> AggregateOutputSpec:
    """Return manifest-persisted aggregate paths derived during preparation."""
    output_directory = Path(str(config["sources"][0]["output"]["directory"]))
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
    """Serialize one prepared entry for the worker runtime fast path."""
    return {
        "host": entry.entry.host,
        "input_name": entry.entry.input_name,
        "registrable_domain": entry.entry.registrable_domain,
        "public_suffix": entry.entry.public_suffix,
        "is_public_suffix_input": entry.entry.is_public_suffix_input,
        "input_kind": entry.entry.input_kind,
        "apex_scope": entry.entry.apex_scope,
        "source_format": entry.entry.source_format,
        "raw_line": entry.raw_line,
        "line_index": entry.line_index,
        "manual_filter_pass": entry.manual_filter_pass,
        "manual_add": entry.manual_add,
        "source_id_override": entry.source_id_override,
        "source_input_label_override": entry.source_input_label_override,
        "source_ids": list(entry.source_ids),
        "source_input_labels": list(entry.source_input_labels),
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
                worker_source_entries[worker_id][prepared_entry.source_id].append(
                    prepared_entry
                )
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
        self,
        *,
        config: dict[str, Any],
        batch_id: str,
        worker_ids: list[str],
        worker_source_entries: dict[str, dict[str, list[PreparedHostEntry]]],
        worker_root_plans: dict[str, dict[str, PreparedRootPlan]],
    ) -> list[PreparedWorkerManifest]:
        """Return the committed prepare-to-worker manifests for participating workers."""
        manifests: list[PreparedWorkerManifest] = []
        for worker_id in worker_ids:
            if not worker_source_entries[worker_id]:
                continue
            manifests.append(
                PreparedWorkerManifest(
                    worker_id=worker_id,
                    manifest=PrepareWorkerManifest.from_assignment(
                        automation_format_version=PIPELINE_RUN_FORMAT_VERSION,
                        worker_id=worker_id,
                        batch_id=batch_id,
                        runtime_spec=self._build_worker_runtime_spec(
                            config=config,
                            batch_id=batch_id,
                            worker_id=worker_id,
                            selected_source_ids=set(worker_source_entries[worker_id]),
                        ),
                        prepared_metadata=self._prepared_runtime_metadata_from_assignment(
                            source_entries=worker_source_entries[worker_id],
                            root_plans=worker_root_plans[worker_id],
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
        config_identity = worker_config_identity_from_config(config)
        config_name = config_identity.config_name
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
        return WorkerRuntimeSpec(
            config_identity=config_identity,
            cache={
                "cache_file": relative_path(worker_paths.cache),
                "baseline_cache_file": relative_path(
                    _workflow_paths().runtime_cache_path()
                ),
                "classification_ttl_days": json.loads(
                    json.dumps(config["cache"]["classification_ttl_days"])
                ),
                "dns_host_resolution_ttl_days": json.loads(
                    json.dumps(config["cache"]["dns_host_resolution_ttl_days"])
                ),
                "dns_ttl_days": config["cache"]["dns_ttl_days"],
            },
            runtime=json.loads(json.dumps(config.get("runtime", {}))),
            sources=source_configs,
            output_spec=WorkerOutputSpec(
                result_root=relative_path(worker_paths.result_root),
                filtered=relative_path(worker_paths.filtered),
                unactionable=relative_path(worker_paths.unactionable),
                review=relative_path(worker_paths.review),
                terminal_rows=relative_path(worker_paths.terminal_rows),
                cache=relative_path(worker_paths.cache),
            ),
            debug_log_path=relative_path(worker_paths.debug_log),
        )

    def _prepared_sources_payload(
        self,
        *,
        source_entries: dict[str, list[PreparedHostEntry]],
    ) -> dict[str, Any]:
        sources_payload: dict[str, Any] = {}
        for source_id, entries in sorted(
            source_entries.items(),
            key=lambda item: (item[1][0].source_index, item[0]),
        ):
            ordered_entries = list(entries)
            sources_payload[source_id] = {
                "source_index": ordered_entries[0].source_index,
                "entries": [prepared_entry_payload(entry) for entry in ordered_entries],
            }
        return sources_payload

    def _prepared_runtime_metadata_from_assignment(
        self,
        *,
        source_entries: dict[str, list[PreparedHostEntry]],
        root_plans: dict[str, PreparedRootPlan],
    ) -> PreparedRuntimeMetadata:
        sources_payload = self._prepared_sources_payload(source_entries=source_entries)
        return PreparedRuntimeMetadata(
            prepared_source_ids=sorted(sources_payload),
            sources=sources_payload,
            delegation_roots={
                registrable_domain: root_plan_runtime_payload(plan)
                for registrable_domain, plan in sorted(root_plans.items())
            },
            terminal_rows=[],
        )

    def _ordered_entries_for_root(
        self,
        planning_inputs: PreparedBatchPlanningInputs,
        registrable_domain: str,
    ) -> list[PreparedHostEntry]:
        return sorted(
            planning_inputs.eligible_root_entries[registrable_domain],
            key=lambda entry: (entry.source_index, entry.line_index, entry.entry.host),
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
