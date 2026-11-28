"""Prepare-step worker assignment owner."""

from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain_pipeline.paths.layout import PathLayout, WorkflowStatePathLayout
from domain_pipeline.prepare.models import (
    PreparedInputSet,
    PreparedRootPlan,
)
from domain_pipeline.prepare.prepare_to_aggregate_manifest import (
    AggregateOutputSpec,
)
from domain_pipeline.prepare.prepare_to_worker_manifest import (
    PreparedDelegationRootWork,
    PreparedInputDomainWork,
    PreparedManualRoutingProfile,
    PreparedRuntimeMetadata,
    PrepareWorkerManifest,
    WorkerOutputSpec,
    WorkerRuntimeSpec,
)

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
    """Source-blind root work collected before worker assignment starts."""

    root_plans: dict[str, PreparedRootPlan]


@dataclass(frozen=True)
class WorkerManifestBuildRequest:
    """Inputs needed to build prepare-to-worker manifests for one batch."""

    config: dict[str, Any]
    batch_id: str
    worker_ids: list[str]
    worker_root_plans: dict[str, dict[str, PreparedRootPlan]]


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
        return PreparedBatchPlanningInputs(
            root_plans=prepared_inputs.root_plans,
        )

    def assign(
        self,
        *,
        planning_inputs: PreparedBatchPlanningInputs,
        worker_ids: list[str],
    ) -> tuple[dict[str, dict[str, PreparedRootPlan]], Counter]:
        """Assign roots atomically by descending unique input-domain work count."""
        worker_root_plans: dict[str, dict[str, PreparedRootPlan]] = {
            worker_id: {} for worker_id in worker_ids
        }
        worker_domain_counts: Counter = Counter()
        if planning_inputs.root_plans and not worker_ids:
            raise ValueError("at least one worker_id is required to assign roots")

        ordered_roots = sorted(
            planning_inputs.root_plans.items(),
            key=lambda item: (-item[1].entry_count, item[0]),
        )
        for registrable_domain, plan in ordered_roots:
            worker_id = min(
                worker_ids,
                key=lambda current_worker_id: (
                    worker_domain_counts[current_worker_id],
                    current_worker_id,
                ),
            )
            worker_root_plans[worker_id][registrable_domain] = plan
            worker_domain_counts[worker_id] += plan.entry_count
            logger.debug(
                "Batch preparation assigned root=%s input_domains=%d worker=%s",
                registrable_domain,
                plan.entry_count,
                worker_id,
            )

        self._log_summary(
            worker_ids=worker_ids,
            worker_root_plans=worker_root_plans,
            worker_domain_counts=worker_domain_counts,
        )
        return worker_root_plans, worker_domain_counts

    def build_worker_manifests(
        self, request: WorkerManifestBuildRequest
    ) -> list[PreparedWorkerManifest]:
        """Return the committed prepare-to-worker manifests for participating workers."""
        manifests: list[PreparedWorkerManifest] = []
        for worker_id in request.worker_ids:
            manifests.append(
                PreparedWorkerManifest(
                    worker_id=worker_id,
                    manifest=PrepareWorkerManifest(
                        worker_id=worker_id,
                        batch_id=request.batch_id,
                        runtime_spec=self._build_worker_runtime_spec(
                            config=request.config,
                            batch_id=request.batch_id,
                            worker_id=worker_id,
                        ),
                        prepared_metadata=self._prepared_runtime_metadata_from_assignment(
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
    ) -> WorkerRuntimeSpec:
        config_name = str(config["config_name"])
        worker_paths = _path_layout().worker_paths(
            batch_id=batch_id,
            worker_id=worker_id,
            config_name=config_name,
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
                "output_spec": WorkerOutputSpec(
                    result_root=relative_path(worker_paths.result_root),
                    unactionable=relative_path(worker_paths.unactionable),
                    review=relative_path(worker_paths.review),
                    domain_results=relative_path(worker_paths.domain_results),
                    cache=relative_path(worker_paths.cache),
                ).model_dump(mode="json"),
                "debug_log_path": relative_path(worker_paths.debug_log),
            },
        )

    def _prepared_runtime_metadata_from_assignment(
        self,
        *,
        root_plans: dict[str, PreparedRootPlan],
    ) -> PreparedRuntimeMetadata:
        return PreparedRuntimeMetadata(
            delegation_roots={
                registrable_domain: PreparedDelegationRootWork(
                    delegation_profile=plan.delegation_profile,
                    input_domains={
                        input_domain: PreparedInputDomainWork(
                            manual_routing=PreparedManualRoutingProfile(
                                manually_selected_for_filtered=(
                                    input_plan.manual_routing.manually_selected_for_filtered
                                ),
                                manually_added=(
                                    input_plan.manual_routing.manually_added
                                ),
                            ),
                            **(
                                {"host_resolution_profile": input_plan.host_resolution_profile}
                                if input_plan.host_resolution_profile is not None
                                else {}
                            ),
                            **(
                                {"ip_location_profile": input_plan.ip_location_profile}
                                if input_plan.ip_location_profile is not None
                                else {}
                            ),
                        )
                        for input_domain, input_plan in sorted(
                            plan.input_domains.items()
                        )
                    },
                )
                for registrable_domain, plan in sorted(root_plans.items())
            },
        )

    def _log_summary(
        self,
        *,
        worker_ids: list[str],
        worker_root_plans: dict[str, dict[str, PreparedRootPlan]],
        worker_domain_counts: Counter,
    ) -> None:
        worker_summaries = [
            {
                "worker_id": worker_id,
                "delegation_root_count": len(worker_root_plans[worker_id]),
                "input_domain_count": worker_domain_counts[worker_id],
            }
            for worker_id in worker_ids
        ]
        logger.debug("Batch preparation worker totals=%s", worker_summaries)
