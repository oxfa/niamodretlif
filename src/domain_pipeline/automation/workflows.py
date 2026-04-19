"""Batch orchestration, worker processing, and aggregation helpers."""

# pylint: disable=too-many-lines

from __future__ import annotations

import csv
import json
import logging
import os
import shutil
import sqlite3
from collections import Counter, defaultdict
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, cast

from domain_pipeline.io.output_manager import csv_row_signature, write_review_rows
from domain_pipeline.output_invariants import DuplicateOutputInvariantError
from domain_pipeline.path_layout import (
    aggregate_done_marker_path,
    aggregate_failed_marker_path,
    aggregate_input_review_path as layout_aggregate_input_review_path,
    aggregate_input_terminal_rows_path as layout_aggregate_input_terminal_rows_path,
    batch_manifest_path as layout_batch_manifest_path,
    current_pointer_path,
    debug_artifacts_root,
    runtime_cache_path,
    runtime_log_path,
    runtime_raw_audit_path,
    workflow_state_root,
    worker_bundle_path as layout_worker_bundle_path,
    worker_cache_path,
    worker_dead_path,
    worker_filtered_path,
    worker_log_path,
    worker_publish_output_root,
    worker_review_path,
    worker_state_root,
    worker_status_path as layout_worker_status_path,
    worker_terminal_rows_path,
)
from domain_pipeline.preparation import (
    PreparedHostEntry,
    PreparedInputSet,
    PreparedRootPlan,
    prepare_inputs,
)
from domain_pipeline.runtime.app import run_prepared_pipeline
from domain_pipeline.runtime.history import (
    PipelineCache,
    ROOT_CLASSIFICATION_TABLE,
)
from domain_pipeline.runtime.pure_helpers import REVIEW_OUTPUT_COLUMNS, ReviewOutputRow
from domain_pipeline.automation.manifests import (
    AggregateOutputSpec,
    BatchManifest,
    ConfigIdentity,
    PreparedRuntimeMetadata,
    WorkerBundleManifest,
    WorkerOutputSpec,
    WorkerRuntimeSpec,
    load_batch_manifest,
    load_worker_bundle_manifest,
)

AUTOMATION_FORMAT_VERSION = 2
WORKER_STATUS_VERSION = 2
DEFAULT_WORKER_RUNTIME_BUDGET_SECONDS = 19800
WORKER_BUNDLE_BASENAME = "worker-bundle.json"
BATCH_MANIFEST_BASENAME = "batch-manifest.json"
STATUS_IN_PROGRESS = "in_progress"
STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"
logger = logging.getLogger(__name__)


@dataclass
class PreparedWorkerBundle:
    """One committed worker bundle written by prepare_batch."""

    worker_id: str
    manifest: WorkerBundleManifest


@dataclass
class PreparedBatch:
    """All committed batch artifacts written by prepare_batch."""

    batch_id: str
    config_name: str
    batch_manifest: BatchManifest
    worker_bundles: list[PreparedWorkerBundle]
    preparation_review_rows: list[dict[str, Any]]
    preparation_terminal_rows: list[dict[str, Any]]


@dataclass(frozen=True)
class PreparedBatchPlanningInputs:
    """All batch-planning inputs collected before worker assignment starts."""

    source_jobs_by_id: dict[str, Any]
    eligible_root_entries: dict[str, list[PreparedHostEntry]]
    public_suffix_entries: list[PreparedHostEntry]
    root_plans: dict[str, PreparedRootPlan]


def batch_id_from_run(run_id: str | int, run_attempt: str | int) -> str:
    """Return the deterministic batch identifier for one orchestrator run."""
    return f"batch-{run_id}-attempt-{run_attempt}"


def default_worker_ids(worker_count: int) -> list[str]:
    """Return stable worker identities for one configured worker slot count."""
    if worker_count < 1:
        raise ValueError("worker_count must be at least 1")
    return [f"worker-{index:02d}" for index in range(1, worker_count + 1)]


def _parse_optional_positive_int(
    raw_value: str | None, *, field_name: str
) -> int | None:
    if raw_value is None:
        return None
    stripped = str(raw_value).strip()
    if not stripped:
        return None
    try:
        parsed = int(stripped)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an integer") from exc
    if parsed < 1:
        raise ValueError(f"{field_name} must be at least 1")
    return parsed


def validate_run_settings(
    *,
    worker_count: int,
    max_parallel_workers_raw: str | None,
    worker_runtime_seconds_raw: str | None,
) -> dict[str, Any]:
    """Validate and normalize workflow settings used by the trusted automation run."""
    worker_ids = default_worker_ids(worker_count)
    max_parallel_workers = _parse_optional_positive_int(
        max_parallel_workers_raw,
        field_name="AUTOMATION_MAX_PARALLEL_WORKERS",
    )
    if max_parallel_workers is None:
        max_parallel_workers = worker_count
    if max_parallel_workers > worker_count:
        raise ValueError(
            "AUTOMATION_MAX_PARALLEL_WORKERS must not exceed worker_count "
            f"({max_parallel_workers} > {worker_count})"
        )
    worker_runtime_budget_seconds = _parse_optional_positive_int(
        worker_runtime_seconds_raw,
        field_name="PIPELINE_MAX_RUNTIME_SECONDS",
    )
    if worker_runtime_budget_seconds is None:
        worker_runtime_budget_seconds = DEFAULT_WORKER_RUNTIME_BUDGET_SECONDS
    if worker_runtime_budget_seconds > DEFAULT_WORKER_RUNTIME_BUDGET_SECONDS:
        raise ValueError(
            "PIPELINE_MAX_RUNTIME_SECONDS must be less than or equal to "
            f"{DEFAULT_WORKER_RUNTIME_BUDGET_SECONDS}"
        )
    return {
        "worker_count": worker_count,
        "worker_ids": worker_ids,
        "max_parallel_workers": max_parallel_workers,
        "worker_runtime_budget_seconds": worker_runtime_budget_seconds,
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_dump(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _sorted_dict_rows(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _relative(path: Path) -> str:
    return path.as_posix()


def _resolve_from_root(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_json_dump(payload), encoding="utf-8")


def _batch_manifest_path(*, batch_id: str) -> Path:
    """Return the committed batch-manifest path for one batch."""
    return layout_batch_manifest_path(Path("."), batch_id=batch_id).relative_to(
        Path(".")
    )


def _worker_bundle_path(*, batch_id: str, worker_id: str) -> Path:
    """Return the committed worker-bundle path for one worker."""
    return layout_worker_bundle_path(
        Path("."),
        batch_id=batch_id,
        worker_id=worker_id,
    ).relative_to(Path("."))


def _aggregate_input_review_path(*, batch_id: str) -> Path:
    """Return the committed prepare-owned review partial path."""
    return layout_aggregate_input_review_path(
        Path("."),
        batch_id=batch_id,
    ).relative_to(Path("."))


def _aggregate_input_terminal_rows_path(*, batch_id: str) -> Path:
    """Return the committed prepare-owned terminal-row partial path."""
    return layout_aggregate_input_terminal_rows_path(
        Path("."),
        batch_id=batch_id,
    ).relative_to(Path("."))


def _worker_status_path(*, batch_id: str, worker_id: str) -> Path:
    """Return the worker status path."""
    return layout_worker_status_path(
        Path("."),
        batch_id=batch_id,
        worker_id=worker_id,
    ).relative_to(Path("."))


def _worker_result_root(*, batch_id: str, worker_id: str) -> Path:
    """Return the worker workflow-state root."""
    return worker_state_root(
        Path("."),
        batch_id=batch_id,
        worker_id=worker_id,
    ).relative_to(Path("."))


def _worker_output_paths(
    *, batch_id: str, worker_id: str, config_name: str
) -> dict[str, Path]:
    """Return per-worker internal-state and debug paths derived from fixed conventions."""
    result_root = _worker_result_root(batch_id=batch_id, worker_id=worker_id)
    return {
        "result_root": result_root,
        "output_directory": worker_publish_output_root(
            Path("."),
            batch_id=batch_id,
            worker_id=worker_id,
        ).relative_to(Path(".")),
        "filtered": worker_filtered_path(
            Path("."),
            batch_id=batch_id,
            worker_id=worker_id,
            config_name=config_name,
        ).relative_to(Path(".")),
        "dead": worker_dead_path(
            Path("."),
            batch_id=batch_id,
            worker_id=worker_id,
            config_name=config_name,
        ).relative_to(Path(".")),
        "review": worker_review_path(
            Path("."),
            batch_id=batch_id,
            worker_id=worker_id,
            config_name=config_name,
        ).relative_to(Path(".")),
        "terminal_rows": worker_terminal_rows_path(
            Path("."),
            batch_id=batch_id,
            worker_id=worker_id,
            config_name=config_name,
        ).relative_to(Path(".")),
        "log": worker_log_path(
            Path("."),
            batch_id=batch_id,
            worker_id=worker_id,
        ).relative_to(Path(".")),
        "cache": worker_cache_path(
            Path("."),
            batch_id=batch_id,
            worker_id=worker_id,
        ).relative_to(Path(".")),
    }


def _done_marker_path(*, batch_id: str) -> Path:
    """Return the batch done-marker path."""
    return aggregate_done_marker_path(Path("."), batch_id=batch_id).relative_to(
        Path(".")
    )


def _failed_marker_path(*, batch_id: str) -> Path:
    """Return the batch failed-marker path."""
    return aggregate_failed_marker_path(Path("."), batch_id=batch_id).relative_to(
        Path(".")
    )


def _current_batch_path(*, config_name: str) -> Path:
    """Return the current-batch payload path for one config."""
    return current_pointer_path(Path("."), config_name=config_name).relative_to(
        Path(".")
    )


def _build_prepared_entry_payload(entry: PreparedHostEntry) -> dict[str, Any]:
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
        "source_ids": list(entry.source_ids),
        "source_input_labels": list(entry.source_input_labels),
    }


def _prepared_sources_payload(
    *,
    source_entries: dict[str, list[PreparedHostEntry]],
) -> dict[str, Any]:
    """Return one prepared source payload for worker-local runtime metadata."""
    sources_payload: dict[str, Any] = {}
    for source_id, entries in sorted(
        source_entries.items(),
        key=lambda item: (item[1][0].source_index, item[0]),
    ):
        ordered_entries = sorted(
            entries,
            key=lambda current: (current.line_index, current.entry.host),
        )
        sources_payload[source_id] = {
            "source_index": ordered_entries[0].source_index,
            "entries": [
                _build_prepared_entry_payload(entry) for entry in ordered_entries
            ],
        }
    return sources_payload


def _worker_bundle_paths(*, batch_id: str, state_root: Path) -> list[Path]:
    """Return all committed worker-bundle paths for one batch."""
    bundles_dir = workflow_state_root(state_root) / "batches" / batch_id / "workers"
    if not bundles_dir.is_dir():
        return []
    return sorted(bundles_dir.glob(f"*/{WORKER_BUNDLE_BASENAME}"))


def _load_worker_bundle(
    *,
    batch_id: str,
    worker_id: str,
    state_root: Path,
) -> WorkerBundleManifest | None:
    """Load one worker bundle by convention when it exists."""
    bundle_path = state_root / _worker_bundle_path(
        batch_id=batch_id,
        worker_id=worker_id,
    )
    if not bundle_path.is_file():
        return None
    return load_worker_bundle_manifest(bundle_path)


def _load_batch_manifest(*, batch_id: str, state_root: Path) -> BatchManifest:
    """Load the committed batch manifest for one batch."""
    manifest_path = state_root / _batch_manifest_path(batch_id=batch_id)
    if not manifest_path.is_file():
        raise ValueError(
            f"batch manifest {manifest_path} is required before worker or aggregate execution"
        )
    return load_batch_manifest(manifest_path)


def _config_identity_from_config(config: dict[str, Any]) -> ConfigIdentity:
    """Return the persisted config identity captured during preparation."""
    config_path = Path(str(config["config_path"]))
    return ConfigIdentity(
        config_name=str(config["config_name"]),
        config_path=str(config_path),
        config_file_name=config_path.name,
    )


def _aggregate_output_spec_from_config(config: dict[str, Any]) -> AggregateOutputSpec:
    """Return aggregate-owned final output paths derived during preparation."""
    output_directory = Path(str(config["sources"][0]["output"]["directory"]))
    config_name = str(config["config_name"])
    return AggregateOutputSpec(
        filtered=_relative(output_directory / "filtered" / f"{config_name}.txt"),
        dead=_relative(output_directory / "dead" / f"{config_name}.txt"),
        review=_relative(output_directory / "review" / f"{config_name}.csv"),
        audit=_relative(runtime_raw_audit_path(Path("."), config_name=config_name)),
        log=_relative(runtime_log_path(Path("."), config_name=config_name)),
        cache=_relative(runtime_cache_path(Path("."))),
        current=_relative(_current_batch_path(config_name=config_name)),
    )


def _build_worker_runtime_spec(
    *,
    config: dict[str, Any],
    batch_id: str,
    worker_id: str,
    selected_source_ids: set[str],
) -> WorkerRuntimeSpec:
    """Return one manifest-owned worker runtime spec."""
    config_identity = _config_identity_from_config(config)
    config_name = config_identity.config_name
    worker_paths = _worker_output_paths(
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
        selected_source["output"]["directory"] = _relative(
            worker_paths["output_directory"]
        )
        source_configs.append(selected_source)
    return WorkerRuntimeSpec(
        config_identity=config_identity,
        cache={
            "cache_file": _relative(worker_paths["cache"]),
            "baseline_cache_file": _relative(runtime_cache_path(Path("."))),
            "classification_ttl_days": json.loads(
                json.dumps(config["cache"]["classification_ttl_days"])
            ),
            "dns_ttl_days": config["cache"]["dns_ttl_days"],
        },
        sources=source_configs,
        output_spec=WorkerOutputSpec(
            result_root=_relative(worker_paths["result_root"]),
            filtered=_relative(worker_paths["filtered"]),
            dead=_relative(worker_paths["dead"]),
            review=_relative(worker_paths["review"]),
            terminal_rows=_relative(worker_paths["terminal_rows"]),
            cache=_relative(worker_paths["cache"]),
        ),
        debug_log_path=_relative(worker_paths["log"]),
        runtime_paths={
            "incomplete_manifest_path": _relative(
                worker_state_root(
                    Path("."),
                    batch_id=batch_id,
                    worker_id=worker_id,
                )
                / "incomplete"
                / f"{config_name}-manifest.json"
            ),
            "incomplete_publish_snapshot_root": _relative(
                worker_state_root(
                    Path("."),
                    batch_id=batch_id,
                    worker_id=worker_id,
                )
                / "incomplete"
                / "publish_snapshot"
            ),
            "incomplete_debug_root": _relative(
                debug_artifacts_root(Path("."))
                / "workers"
                / batch_id
                / worker_id
                / "incomplete"
            ),
        },
    )


def _prepared_runtime_metadata_from_assignment(
    *,
    source_entries: dict[str, list[PreparedHostEntry]],
    root_plans: dict[str, PreparedRootPlan],
) -> PreparedRuntimeMetadata:
    """Return one manifest-owned prepared runtime payload for one worker."""
    sources_payload = _prepared_sources_payload(source_entries=source_entries)
    return PreparedRuntimeMetadata(
        prepared_source_ids=sorted(sources_payload),
        sources=sources_payload,
        rdap_roots={
            registrable_domain: {
                "status": plan.status,
                "authoritative_base_url": plan.authoritative_base_url,
            }
            for registrable_domain, plan in sorted(root_plans.items())
        },
        terminal_rows=[],
    )


def _write_audit_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    """Write audit JSONL rows to one path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")))
            handle.write("\n")


def _write_review_partial(path: Path, rows: list[dict[str, Any]]) -> None:
    """Write the prepare-owned review partial, including a header when empty."""
    if rows:
        write_review_rows(path, rows)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=REVIEW_OUTPUT_COLUMNS, extrasaction="ignore"
        )
        writer.writeheader()


def _choose_balanced_worker(
    *,
    worker_ids: list[str],
    entry_counts: Counter,
) -> str:
    """Return the worker with the lightest current prepared-entry count."""
    return min(
        worker_ids,
        key=lambda worker_id: (entry_counts[worker_id], worker_id),
    )


def _log_prepared_assignment_summary(
    *,
    worker_ids: list[str],
    worker_source_entries: dict[str, dict[str, list[PreparedHostEntry]]],
    worker_root_plans: dict[str, dict[str, PreparedRootPlan]],
    worker_entry_counts: Counter,
    worker_root_counts: Counter,
    worker_server_entry_counts: dict[str, Counter],
    worker_server_root_counts: dict[str, Counter],
    roots_by_server: dict[str, list[str]],
) -> None:
    """Emit one compact debug summary of host-weighted RDAP worker assignment."""
    worker_summaries: list[dict[str, Any]] = []
    for worker_id in worker_ids:
        root_plans = worker_root_plans[worker_id]
        public_suffix_count = sum(
            1
            for source_entries in worker_source_entries[worker_id].values()
            for prepared_entry in source_entries
            if prepared_entry.entry.is_public_suffix_input
            or not prepared_entry.entry.registrable_domain
        )
        worker_summaries.append(
            {
                "worker_id": worker_id,
                "entry_count": worker_entry_counts[worker_id],
                "rdap_root_count": worker_root_counts[worker_id],
                "resolved_root_count": sum(
                    1 for plan in root_plans.values() if plan.status == "resolved"
                ),
                "unavailable_root_count": sum(
                    1 for plan in root_plans.values() if plan.status == "unavailable"
                ),
                "unknown_root_count": sum(
                    1 for plan in root_plans.values() if plan.status == "unknown"
                ),
                "public_suffix_entry_count": public_suffix_count,
            }
        )
    logger.debug("Batch preparation worker totals=%s", worker_summaries)

    server_summaries: list[dict[str, Any]] = []
    for authoritative_base_url in sorted(roots_by_server):
        entry_counts = {
            worker_id: worker_server_entry_counts[worker_id][authoritative_base_url]
            for worker_id in worker_ids
            if worker_server_entry_counts[worker_id][authoritative_base_url] > 0
        }
        root_counts = {
            worker_id: worker_server_root_counts[worker_id][authoritative_base_url]
            for worker_id in worker_ids
            if worker_server_root_counts[worker_id][authoritative_base_url] > 0
        }
        if entry_counts or root_counts:
            server_summaries.append(
                {
                    "authoritative_server": authoritative_base_url,
                    "worker_entry_counts": entry_counts,
                    "worker_root_counts": root_counts,
                }
            )
    if server_summaries:
        logger.debug(
            "Batch preparation authoritative server spread=%s", server_summaries
        )


def _planning_inputs_from_prepared(
    prepared_inputs: PreparedInputSet,
) -> PreparedBatchPlanningInputs:
    """Project shared prepared inputs into automation worker-planning inputs."""
    eligible_root_entries, public_suffix_entries = (
        prepared_inputs.split_entries_for_planning()
    )
    return PreparedBatchPlanningInputs(
        source_jobs_by_id=prepared_inputs.source_jobs_by_id,
        eligible_root_entries=eligible_root_entries,
        public_suffix_entries=public_suffix_entries,
        root_plans=prepared_inputs.root_plans,
    )


def _assign_prepared_entries_to_workers(
    *,
    planning_inputs: PreparedBatchPlanningInputs,
    worker_ids: list[str],
) -> tuple[
    dict[str, dict[str, list[PreparedHostEntry]]],
    dict[str, dict[str, PreparedRootPlan]],
    Counter,
]:
    """Assign RDAP-aware prepared entries across workers deterministically.

    Resolved roots are spread within each authoritative RDAP server bucket by
    host count rather than by a global root quota. Unknown and unavailable
    roots still stay atomic per registrable domain and fall back to total host
    load balancing.
    """
    worker_source_entries: dict[str, dict[str, list[PreparedHostEntry]]] = {
        worker_id: defaultdict(list) for worker_id in worker_ids
    }
    worker_root_plans: dict[str, dict[str, PreparedRootPlan]] = {
        worker_id: {} for worker_id in worker_ids
    }
    worker_entry_counts: Counter = Counter()
    worker_root_counts: Counter = Counter()
    worker_server_entry_counts: dict[str, Counter] = {
        worker_id: Counter() for worker_id in worker_ids
    }
    worker_server_root_counts: dict[str, Counter] = {
        worker_id: Counter() for worker_id in worker_ids
    }
    root_entry_counts = {
        registrable_domain: len(entries)
        for registrable_domain, entries in planning_inputs.eligible_root_entries.items()
    }

    def assign_root(worker_id: str, registrable_domain: str) -> None:
        for prepared_entry in sorted(
            planning_inputs.eligible_root_entries[registrable_domain],
            key=lambda current: (
                current.source_index,
                current.line_index,
                current.entry.host,
            ),
        ):
            worker_source_entries[worker_id][prepared_entry.source_id].append(
                prepared_entry
            )
        worker_root_plans[worker_id][registrable_domain] = planning_inputs.root_plans[
            registrable_domain
        ]
        worker_entry_counts[worker_id] += root_entry_counts[registrable_domain]
        worker_root_counts[worker_id] += 1
        plan = planning_inputs.root_plans[registrable_domain]
        logger.debug(
            "Batch preparation assigned root=%s status=%s authoritative_server=%s "
            "worker=%s entry_count=%d",
            registrable_domain,
            plan.status,
            plan.authoritative_base_url or "(none)",
            worker_id,
            root_entry_counts[registrable_domain],
        )

    roots_by_server: dict[str, list[str]] = defaultdict(list)
    unknown_roots: list[str] = []
    unavailable_roots: list[str] = []
    for registrable_domain, plan in sorted(planning_inputs.root_plans.items()):
        if plan.status == "resolved":
            assert plan.authoritative_base_url is not None
            roots_by_server[plan.authoritative_base_url].append(registrable_domain)
        elif plan.status == "unavailable":
            unavailable_roots.append(registrable_domain)
        else:
            unknown_roots.append(registrable_domain)

    for authoritative_base_url in sorted(roots_by_server):
        current_roots = sorted(
            roots_by_server[authoritative_base_url],
            key=lambda registrable_domain: (
                -root_entry_counts[registrable_domain],
                registrable_domain,
            ),
        )
        for registrable_domain in current_roots:
            worker_id = min(
                worker_ids,
                key=lambda current_worker_id, authoritative_server=authoritative_base_url: (
                    worker_server_entry_counts[current_worker_id][authoritative_server],
                    worker_entry_counts[current_worker_id],
                    worker_root_counts[current_worker_id],
                    current_worker_id,
                ),
            )
            assign_root(worker_id, registrable_domain)
            worker_server_entry_counts[worker_id][
                authoritative_base_url
            ] += root_entry_counts[registrable_domain]
            worker_server_root_counts[worker_id][authoritative_base_url] += 1

    for registrable_domain in sorted(unknown_roots):
        worker_id = min(
            worker_ids,
            key=lambda current_worker_id: (
                worker_entry_counts[current_worker_id],
                worker_root_counts[current_worker_id],
                current_worker_id,
            ),
        )
        assign_root(worker_id, registrable_domain)

    for registrable_domain in sorted(unavailable_roots):
        worker_id = _choose_balanced_worker(
            worker_ids=worker_ids,
            entry_counts=worker_entry_counts,
        )
        assign_root(worker_id, registrable_domain)

    for prepared_entry in sorted(
        planning_inputs.public_suffix_entries,
        key=lambda current: (
            current.source_index,
            current.line_index,
            current.entry.host,
        ),
    ):
        worker_id = _choose_balanced_worker(
            worker_ids=worker_ids,
            entry_counts=worker_entry_counts,
        )
        worker_source_entries[worker_id][prepared_entry.source_id].append(
            prepared_entry
        )
        worker_entry_counts[worker_id] += 1
        logger.debug(
            "Batch preparation assigned public-suffix input host=%s worker=%s",
            prepared_entry.entry.host,
            worker_id,
        )
    _log_prepared_assignment_summary(
        worker_ids=worker_ids,
        worker_source_entries=worker_source_entries,
        worker_root_plans=worker_root_plans,
        worker_entry_counts=worker_entry_counts,
        worker_root_counts=worker_root_counts,
        worker_server_entry_counts=worker_server_entry_counts,
        worker_server_root_counts=worker_server_root_counts,
        roots_by_server=roots_by_server,
    )
    return worker_source_entries, worker_root_plans, worker_entry_counts


def _build_worker_bundles(
    *,
    config: dict[str, Any],
    batch_id: str,
    worker_ids: list[str],
    worker_source_entries: dict[str, dict[str, list[PreparedHostEntry]]],
    worker_root_plans: dict[str, dict[str, PreparedRootPlan]],
) -> list[PreparedWorkerBundle]:
    """Return the committed worker bundles for participating workers."""
    bundles: list[PreparedWorkerBundle] = []
    for worker_id in worker_ids:
        if not worker_source_entries[worker_id]:
            continue
        bundles.append(
            PreparedWorkerBundle(
                worker_id=worker_id,
                manifest=WorkerBundleManifest.from_assignment(
                    automation_format_version=AUTOMATION_FORMAT_VERSION,
                    worker_id=worker_id,
                    batch_id=batch_id,
                    runtime_spec=_build_worker_runtime_spec(
                        config=config,
                        batch_id=batch_id,
                        worker_id=worker_id,
                        selected_source_ids=set(worker_source_entries[worker_id]),
                    ),
                    prepared_metadata=_prepared_runtime_metadata_from_assignment(
                        source_entries=worker_source_entries[worker_id],
                        root_plans=worker_root_plans[worker_id],
                    ),
                ),
            )
        )
    return bundles


def prepare_batch(
    *,
    source_root: Path,
    config_path: Path,
    worker_ids: list[str],
    batch_id: str,
) -> PreparedBatch:
    """Build one committed batch worth of worker bundles and aggregate partials."""
    prepared_inputs = prepare_inputs(source_root=source_root, config_path=config_path)
    config_name = str(prepared_inputs.config["config_name"])
    planning_inputs = _planning_inputs_from_prepared(prepared_inputs)
    total_work_units = len(planning_inputs.root_plans) + len(
        planning_inputs.public_suffix_entries
    )
    if total_work_units < 1 and not prepared_inputs.preparation_review_rows:
        raise ValueError("config produced no input lines to process")
    participating_worker_ids = worker_ids[: min(len(worker_ids), total_work_units)]
    if total_work_units > 0 and not participating_worker_ids:
        raise ValueError("at least one worker_id is required to prepare a batch")

    if participating_worker_ids:
        worker_source_entries, worker_root_plans, _worker_entry_counts = (
            _assign_prepared_entries_to_workers(
                planning_inputs=planning_inputs,
                worker_ids=participating_worker_ids,
            )
        )
        worker_bundles = _build_worker_bundles(
            config=prepared_inputs.config,
            batch_id=batch_id,
            worker_ids=participating_worker_ids,
            worker_source_entries=worker_source_entries,
            worker_root_plans=worker_root_plans,
        )
    else:
        worker_source_entries = {}
        worker_bundles = []
    matched_manual_hosts = {
        entry.entry.host
        for source_entries in worker_source_entries.values()
        for entries in source_entries.values()
        for entry in entries
        if entry.manual_filter_pass
    }
    return PreparedBatch(
        batch_id=batch_id,
        config_name=config_name,
        batch_manifest=BatchManifest.from_prepared_batch(
            automation_format_version=AUTOMATION_FORMAT_VERSION,
            batch_id=batch_id,
            config_identity=_config_identity_from_config(prepared_inputs.config),
            aggregate_output_spec=_aggregate_output_spec_from_config(
                prepared_inputs.config
            ),
            worker_ids=[bundle.worker_id for bundle in worker_bundles],
            aggregate_input_review_path=_relative(
                _aggregate_input_review_path(batch_id=batch_id)
            ),
            aggregate_input_terminal_rows_path=_relative(
                _aggregate_input_terminal_rows_path(batch_id=batch_id)
            ),
        ),
        worker_bundles=worker_bundles,
        preparation_review_rows=[
            row
            for row in prepared_inputs.preparation_review_rows
            if row["host"] not in matched_manual_hosts
        ],
        preparation_terminal_rows=[
            row
            for row in prepared_inputs.preparation_terminal_rows
            if row["host"] not in matched_manual_hosts
        ],
    )


def write_prepared_batch(prepared: PreparedBatch, *, state_root: Path) -> list[str]:
    """Write one prepared batch to disk and return the committed path list."""
    committed_paths: list[str] = []
    batch_manifest_path = _batch_manifest_path(batch_id=prepared.batch_id)
    _write_json(
        state_root / batch_manifest_path,
        prepared.batch_manifest.model_dump(mode="json"),
    )
    committed_paths.append(_relative(batch_manifest_path))
    for bundle in prepared.worker_bundles:
        bundle_path = _worker_bundle_path(
            batch_id=prepared.batch_id,
            worker_id=bundle.worker_id,
        )
        _write_json(
            state_root / bundle_path,
            bundle.manifest.model_dump(mode="json"),
        )
        committed_paths.append(_relative(bundle_path))
    review_path = _aggregate_input_review_path(batch_id=prepared.batch_id)
    audit_path = _aggregate_input_terminal_rows_path(batch_id=prepared.batch_id)
    _write_review_partial(state_root / review_path, prepared.preparation_review_rows)
    _write_audit_rows(state_root / audit_path, prepared.preparation_terminal_rows)
    committed_paths.extend([_relative(review_path), _relative(audit_path)])
    return sorted(committed_paths)


@contextmanager
def _pushd(path: Path) -> Iterator[None]:
    original = Path.cwd()
    path.mkdir(parents=True, exist_ok=True)
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(original)


@contextmanager
def _capture_root_logs_to_file(log_path: Path) -> Iterator[None]:
    """Mirror root-logger output into one worker log file during pipeline execution."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    root_logger = logging.getLogger()
    file_handler = logging.FileHandler(log_path, mode="w", encoding="utf-8")
    if root_logger.handlers:
        template_handler = root_logger.handlers[0]
        file_handler.setLevel(template_handler.level)
        if template_handler.formatter is not None:
            file_handler.setFormatter(template_handler.formatter)
    else:
        file_handler.setLevel(root_logger.level)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
    root_logger.addHandler(file_handler)
    try:
        yield
    finally:
        file_handler.flush()
        root_logger.removeHandler(file_handler)
        file_handler.close()


def _status_template_for_worker(
    *,
    batch_id: str,
    worker_id: str,
) -> dict[str, Any]:
    return {
        "automation_format_version": AUTOMATION_FORMAT_VERSION,
        "status_version": WORKER_STATUS_VERSION,
        "batch_id": batch_id,
        "worker_id": worker_id,
        "conclusion": STATUS_IN_PROGRESS,
        "error_reason": None,
        "started_at": _utc_now(),
    }


def _status_payload_from_template(
    *,
    template: dict[str, Any],
    output_commit_sha: str,
    push_retry_count: int,
    finished_at: str | None,
    conclusion: str,
    failure_reason: str | None,
) -> dict[str, Any]:
    payload = {
        "automation_format_version": AUTOMATION_FORMAT_VERSION,
        "status_version": WORKER_STATUS_VERSION,
        "batch_id": template["batch_id"],
        "worker_id": template["worker_id"],
        "conclusion": conclusion,
        "commit_sha_produced": output_commit_sha,
        "timestamps": {
            "started_at": template["started_at"],
            "finished_at": finished_at,
        },
        "retry_count": push_retry_count,
        "failure_reason": failure_reason,
    }
    return payload


def initialize_worker_statuses(
    *,
    batch_id: str,
    worker_id: str,
    state_root: Path,
) -> dict[str, Any]:
    """Write one in-progress worker status when a worker bundle exists."""
    bundle = _load_worker_bundle(
        batch_id=batch_id,
        worker_id=worker_id,
        state_root=state_root,
    )
    if bundle is None:
        return {
            "automation_format_version": AUTOMATION_FORMAT_VERSION,
            "batch_id": batch_id,
            "worker_id": worker_id,
            "participates": False,
        }

    template = _status_template_for_worker(batch_id=batch_id, worker_id=worker_id)
    status_path = state_root / _worker_status_path(
        batch_id=batch_id, worker_id=worker_id
    )
    _write_json(
        status_path,
        _status_payload_from_template(
            template=template,
            output_commit_sha="",
            push_retry_count=0,
            finished_at=None,
            conclusion=STATUS_IN_PROGRESS,
            failure_reason=None,
        ),
    )
    return {
        "automation_format_version": AUTOMATION_FORMAT_VERSION,
        "batch_id": batch_id,
        "worker_id": worker_id,
        "participates": True,
        "status_path": _relative(
            _worker_status_path(batch_id=batch_id, worker_id=worker_id)
        ),
    }


def run_worker(
    *,
    batch_id: str,
    worker_id: str,
    source_root: Path,
    state_root: Path,
    max_runtime_seconds: float | None = None,
) -> dict[str, Any]:
    """Process one worker entirely from its persisted manifest-owned runtime state."""
    bundle = _load_worker_bundle(
        batch_id=batch_id,
        worker_id=worker_id,
        state_root=state_root,
    )
    if bundle is None:
        return {
            "automation_format_version": AUTOMATION_FORMAT_VERSION,
            "batch_id": batch_id,
            "worker_id": worker_id,
            "participates": False,
            "overall_conclusion": "skipped",
        }

    status_path = state_root / _worker_status_path(
        batch_id=batch_id, worker_id=worker_id
    )
    if not status_path.exists():
        initialize_worker_statuses(
            batch_id=batch_id,
            worker_id=worker_id,
            state_root=state_root,
        )
    overall_conclusion = STATUS_SUCCESS
    worker_paths = bundle.resolve_paths(state_root)
    result_root = worker_paths["result_root"]
    log_path = state_root / Path(bundle.runtime_spec.debug_log_path)
    if result_root.exists():
        shutil.rmtree(result_root)
    error_reason: str | None = None
    conclusion = STATUS_SUCCESS
    try:
        with _capture_root_logs_to_file(log_path), _pushd(result_root):
            # Keep worker cwd isolated for incidental relative reads. Output routing
            # comes from the resolved runtime payload rather than cwd side effects.
            exit_code = run_prepared_pipeline(
                bundle.runtime_spec.to_runtime_payload(
                    source_root=source_root,
                    state_root=state_root,
                ),
                runtime_identity=bundle.runtime_spec.config_identity.model_dump(
                    mode="json"
                ),
                max_runtime_seconds=max_runtime_seconds,
                prepared_metadata=bundle.prepared_metadata.to_runtime_payload(),
            )
        if exit_code != 0:
            raise RuntimeError(f"pipeline exited with status {exit_code}")
    except Exception as exc:  # pylint: disable=broad-exception-caught
        overall_conclusion = STATUS_FAILURE
        conclusion = STATUS_FAILURE
        error_reason = str(exc)
        logging.getLogger(__name__).exception("Worker %s failed", worker_id)
    return {
        "automation_format_version": AUTOMATION_FORMAT_VERSION,
        "batch_id": batch_id,
        "worker_id": worker_id,
        "participates": True,
        "overall_conclusion": overall_conclusion,
        "conclusion": conclusion,
        "error_reason": error_reason,
        "status_path": _relative(
            _worker_status_path(batch_id=batch_id, worker_id=worker_id)
        ),
    }


def finalize_worker_statuses(
    *,
    batch_id: str,
    worker_id: str,
    state_root: Path,
    output_commit_sha: str,
    push_retry_count: int,
    fallback_conclusion: str | None = None,
    fallback_failure_reason: str | None = None,
    finished_at: str | None = None,
) -> list[str]:
    """Finalize one worker status file after processing."""
    if (
        _load_worker_bundle(
            batch_id=batch_id, worker_id=worker_id, state_root=state_root
        )
        is None
    ):
        return []
    status_path = state_root / _worker_status_path(
        batch_id=batch_id, worker_id=worker_id
    )
    if not status_path.is_file():
        return []
    existing_payload = json.loads(status_path.read_text(encoding="utf-8"))
    finished_timestamp = finished_at or _utc_now()
    conclusion = str(existing_payload["conclusion"])
    failure_reason = existing_payload.get("failure_reason")
    if conclusion == STATUS_IN_PROGRESS:
        conclusion = fallback_conclusion or STATUS_SUCCESS
        failure_reason = (
            fallback_failure_reason if conclusion == STATUS_FAILURE else None
        )
    _write_json(
        status_path,
        {
            "automation_format_version": AUTOMATION_FORMAT_VERSION,
            "status_version": WORKER_STATUS_VERSION,
            "batch_id": batch_id,
            "worker_id": worker_id,
            "conclusion": conclusion,
            "commit_sha_produced": output_commit_sha,
            "timestamps": {
                "started_at": existing_payload["timestamps"]["started_at"],
                "finished_at": finished_timestamp,
            },
            "retry_count": push_retry_count,
            "failure_reason": failure_reason,
        },
    )
    return [_relative(_worker_status_path(batch_id=batch_id, worker_id=worker_id))]


def materialize_incomplete_statuses(
    *,
    batch_id: str,
    state_root: Path,
    failure_reason: str,
    finished_at: str | None = None,
) -> dict[str, Any]:
    """Rewrite missing or in-progress worker statuses to terminal failure."""
    written_paths: list[str] = []
    finished_timestamp = finished_at or _utc_now()
    batch_manifest = _load_batch_manifest(batch_id=batch_id, state_root=state_root)
    discovered_worker_ids = {
        bundle_path.parent.name
        for bundle_path in _worker_bundle_paths(
            batch_id=batch_id, state_root=state_root
        )
    }
    expected_worker_ids = set(batch_manifest.worker_ids)
    if discovered_worker_ids != expected_worker_ids:
        raise ValueError(
            "batch manifest worker ids do not match restored worker bundles: "
            f"expected={sorted(expected_worker_ids)} discovered={sorted(discovered_worker_ids)}"
        )
    for worker_id in batch_manifest.worker_ids:
        status_path = state_root / _worker_status_path(
            batch_id=batch_id, worker_id=worker_id
        )
        existing_payload: dict[str, Any] | None = None
        if status_path.exists():
            loaded_payload = json.loads(status_path.read_text(encoding="utf-8"))
            if not isinstance(loaded_payload, dict):
                raise ValueError(
                    f"status file {status_path} must contain a JSON object"
                )
            existing_payload = loaded_payload
            if existing_payload.get("conclusion") in {STATUS_SUCCESS, STATUS_FAILURE}:
                continue
        template = _status_template_for_worker(batch_id=batch_id, worker_id=worker_id)
        if existing_payload is not None:
            started_at = existing_payload.get("timestamps", {}).get("started_at")
            if started_at is not None:
                template["started_at"] = started_at
        else:
            template["started_at"] = finished_timestamp
        _write_json(
            status_path,
            _status_payload_from_template(
                template=template,
                output_commit_sha="",
                push_retry_count=0,
                finished_at=finished_timestamp,
                conclusion=STATUS_FAILURE,
                failure_reason=failure_reason,
            ),
        )
        written_paths.append(
            _relative(_worker_status_path(batch_id=batch_id, worker_id=worker_id))
        )
    return {
        "batch_id": batch_id,
        "written_paths": written_paths,
        "written_count": len(written_paths),
    }


def _canonical_row_signature(row: dict[str, Any]) -> str:
    return json.dumps(row, sort_keys=True, separators=(",", ":"))


def _merge_host_txt_files(source_paths: Iterable[Path], target_path: Path) -> None:
    seen_hosts: dict[str, str] = {}
    ordered_hosts: list[str] = []
    for source_path in source_paths:
        if not source_path.exists():
            continue
        for line in source_path.read_text(encoding="utf-8").splitlines():
            host = line.strip()
            if not host:
                continue
            previous_source = seen_hosts.get(host)
            if previous_source is not None:
                raise DuplicateOutputInvariantError(
                    "aggregate_host",
                    host,
                    context={
                        "first_path": previous_source,
                        "duplicate_path": _relative(source_path),
                    },
                )
            seen_hosts[host] = _relative(source_path)
            ordered_hosts.append(host)
    hosts = sorted(ordered_hosts)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(
        "".join(f"{host}\n" for host in hosts),
        encoding="utf-8",
    )


def _merge_audit_files(audit_paths: Iterable[Path], target_path: Path) -> None:
    seen_rows: dict[str, tuple[dict[str, Any], str]] = {}
    for audit_path in audit_paths:
        if not audit_path.exists():
            continue
        for row in _sorted_dict_rows(audit_path):
            signature = _canonical_row_signature(row)
            existing = seen_rows.get(signature)
            if existing is not None:
                raise DuplicateOutputInvariantError(
                    "aggregate_audit_row",
                    str(row.get("host", "")),
                    context={
                        "signature": signature,
                        "first_path": existing[1],
                        "duplicate_path": _relative(audit_path),
                    },
                )
            seen_rows[signature] = (row, _relative(audit_path))
    ordered_rows = sorted(
        [item[0] for item in seen_rows.values()],
        key=lambda current: (
            str(current.get("host", "")),
            _canonical_row_signature(current),
        ),
    )
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with target_path.open("w", encoding="utf-8") as handle:
        for row in ordered_rows:
            json.dump(row, handle, sort_keys=True)
            handle.write("\n")


def _merge_review_files(review_paths: Iterable[Path], target_path: Path) -> None:
    review_path_list = list(review_paths)
    logger.debug(
        "Aggregate review merge starting target=%s source_count=%d",
        target_path,
        len(review_path_list),
    )
    review_rows: list[ReviewOutputRow] = []
    seen_review_rows: dict[str, str] = {}
    for review_path in review_path_list:
        if not review_path.exists():
            logger.debug(
                "Aggregate review merge skipping missing source=%s", review_path
            )
            continue
        with review_path.open("r", encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                normalized_row = _normalize_projected_review_row(row)
                signature = csv_row_signature(normalized_row)
                existing = seen_review_rows.get(signature)
                if existing is not None:
                    raise DuplicateOutputInvariantError(
                        "aggregate_review_row",
                        str(row.get("host", "")),
                        context={
                            "signature": signature,
                            "first_path": existing,
                            "duplicate_path": _relative(review_path),
                        },
                    )
                seen_review_rows[signature] = _relative(review_path)
                review_rows.append(normalized_row)
    if target_path.exists():
        target_path.unlink()
    if review_rows:
        _write_projected_review_rows(target_path, review_rows)
    logger.debug(
        "Aggregate review merge completed target=%s merged_row_count=%d",
        target_path,
        len(review_rows),
    )


def _normalize_projected_review_row(row: dict[str, Any]) -> ReviewOutputRow:
    """Normalize one aggregate review CSV row without reprojecting its values."""
    # Aggregate review inputs already contain REVIEW_OUTPUT_COLUMNS and must
    # preserve the worker/prepared projection exactly as written.
    return cast(
        ReviewOutputRow,
        {column: str(row.get(column, "")) for column in REVIEW_OUTPUT_COLUMNS},
    )


def _write_projected_review_rows(
    review_path: Path, review_rows: list[ReviewOutputRow]
) -> None:
    """Write already-projected aggregate review rows in deterministic order."""
    review_path.parent.mkdir(parents=True, exist_ok=True)
    with review_path.open("w", encoding="utf-8", newline="") as review_handle:
        writer = csv.DictWriter(
            review_handle,
            fieldnames=REVIEW_OUTPUT_COLUMNS,
            extrasaction="ignore",
        )
        writer.writeheader()
        for row in sorted(
            review_rows,
            key=lambda current: (
                current.get("input_name") or current.get("host", ""),
                current.get("host", ""),
            ),
        ):
            writer.writerow(cast(Any, row))


def _merge_log_files(
    *,
    summaries: Iterable[dict[str, Any]],
    state_root: Path,
    target_path: Path,
) -> None:
    sections: list[str] = []
    for payload in summaries:
        log_path = state_root / str(payload["log_path"])
        if log_path.exists():
            worker_text = log_path.read_text(encoding="utf-8").strip()
            if worker_text:
                sections.append(worker_text)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    if sections:
        target_path.write_text("\n\n".join(sections) + "\n", encoding="utf-8")
        return
    target_path.write_text("", encoding="utf-8")


def _choose_cache_row(
    existing: sqlite3.Row | None, candidate: sqlite3.Row
) -> sqlite3.Row:
    if existing is None:
        return candidate
    existing_key = (
        str(existing["checked_at"]),
        str(existing["expires_at"]),
        json.dumps([existing[column] for column in existing.keys()], default=str),
    )
    candidate_key = (
        str(candidate["checked_at"]),
        str(candidate["expires_at"]),
        json.dumps([candidate[column] for column in candidate.keys()], default=str),
    )
    return candidate if candidate_key >= existing_key else existing


def _merge_cache_table(
    *,
    rows_by_key: dict[tuple[str, ...], sqlite3.Row],
    cache_path: Path,
    table_name: str,
    key_columns: tuple[str, ...],
) -> int:
    if not cache_path.exists():
        return 0
    connection = sqlite3.connect(cache_path)
    connection.row_factory = sqlite3.Row
    row_count = 0
    try:
        for row in connection.execute(f"SELECT * FROM {table_name}"):
            row_count += 1
            key = tuple(str(row[column]) for column in key_columns)
            rows_by_key[key] = _choose_cache_row(rows_by_key.get(key), row)
    finally:
        connection.close()
    return row_count


def _worker_cache_paths(
    worker_ids: Iterable[str], *, batch_id: str, config_name: str, state_root: Path
) -> list[Path]:
    """Return worker cache paths for participating workers."""
    return [
        state_root
        / _worker_output_paths(
            batch_id=batch_id,
            worker_id=worker_id,
            config_name=config_name,
        )["cache"]
        for worker_id in worker_ids
    ]


def merge_cache_files(
    *,
    source_paths: Iterable[Path],
    target_path: Path,
) -> dict[str, Any]:
    """Merge deterministic worker cache fragments into the shared cache path."""
    candidate_source_paths = list(source_paths)
    logger.debug(
        "Merging cache databases into %s from %d candidate worker caches",
        target_path,
        len(candidate_source_paths),
    )
    target_cache = PipelineCache.load(target_path)
    target_connection = target_cache._connection  # pylint: disable=protected-access
    rows_by_key: dict[str, dict[tuple[str, ...], sqlite3.Row]] = {
        ROOT_CLASSIFICATION_TABLE: {},
        "dns_history": {},
        "geo_history": {},
    }
    target_root_rows = _merge_cache_table(
        rows_by_key=rows_by_key[ROOT_CLASSIFICATION_TABLE],
        cache_path=target_path,
        table_name=ROOT_CLASSIFICATION_TABLE,
        key_columns=("domain",),
    )
    target_dns_rows = _merge_cache_table(
        rows_by_key=rows_by_key["dns_history"],
        cache_path=target_path,
        table_name="dns_history",
        key_columns=("host", "resolver_key"),
    )
    target_geo_rows = _merge_cache_table(
        rows_by_key=rows_by_key["geo_history"],
        cache_path=target_path,
        table_name="geo_history",
        key_columns=("provider", "ip"),
    )
    logger.debug(
        "Seeded cache merge target %s with root_rows=%d dns_rows=%d geo_rows=%d",
        target_path,
        target_root_rows,
        target_dns_rows,
        target_geo_rows,
    )
    merged_cache_count = 0
    missing_cache_count = 0
    invalid_cache_count = 0
    try:
        for cache_path in candidate_source_paths:
            if not cache_path.exists():
                missing_cache_count += 1
                logger.debug("Skipping missing worker cache %s", cache_path)
                continue
            try:
                source_root_rows = _merge_cache_table(
                    rows_by_key=rows_by_key[ROOT_CLASSIFICATION_TABLE],
                    cache_path=cache_path,
                    table_name=ROOT_CLASSIFICATION_TABLE,
                    key_columns=("domain",),
                )
                source_dns_rows = _merge_cache_table(
                    rows_by_key=rows_by_key["dns_history"],
                    cache_path=cache_path,
                    table_name="dns_history",
                    key_columns=("host", "resolver_key"),
                )
                source_geo_rows = _merge_cache_table(
                    rows_by_key=rows_by_key["geo_history"],
                    cache_path=cache_path,
                    table_name="geo_history",
                    key_columns=("provider", "ip"),
                )
            except sqlite3.DatabaseError as exc:
                invalid_cache_count += 1
                logger.warning("Skipping invalid worker cache %s: %s", cache_path, exc)
                continue
            merged_cache_count += 1
            logger.debug(
                "Merged worker cache %s with root_rows=%d dns_rows=%d geo_rows=%d",
                cache_path,
                source_root_rows,
                source_dns_rows,
                source_geo_rows,
            )
        target_connection.execute(f"DELETE FROM {ROOT_CLASSIFICATION_TABLE}")
        target_connection.execute("DELETE FROM dns_history")
        target_connection.execute("DELETE FROM geo_history")
        for row in rows_by_key[ROOT_CLASSIFICATION_TABLE].values():
            target_connection.execute(
                f"""
                INSERT OR REPLACE INTO {ROOT_CLASSIFICATION_TABLE} (
                    domain, classification, statuses, statuses_complete, checked_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                tuple(row[column] for column in row.keys()),
            )
        for row in rows_by_key["dns_history"].values():
            target_connection.execute(
                """
                INSERT OR REPLACE INTO dns_history (
                    host, resolver_key, a_exists, a_nodata, a_nxdomain, a_timeout,
                    a_servfail, canonical_name, ipv4_addresses, ipv6_addresses,
                    checked_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(row[column] for column in row.keys()),
            )
        for row in rows_by_key["geo_history"].values():
            target_connection.execute(
                """
                INSERT OR REPLACE INTO geo_history (
                    provider, ip, country_code, region_code, region_name, checked_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(row[column] for column in row.keys()),
            )
        target_connection.commit()
        logger.debug(
            "Finished cache merge into %s with root_rows=%d dns_rows=%d geo_rows=%d "
            "merged_cache_count=%d missing_cache_count=%d invalid_cache_count=%d",
            target_path,
            len(rows_by_key[ROOT_CLASSIFICATION_TABLE]),
            len(rows_by_key["dns_history"]),
            len(rows_by_key["geo_history"]),
            merged_cache_count,
            missing_cache_count,
            invalid_cache_count,
        )
    finally:
        target_cache.close()
    return {
        "candidate_cache_count": len(candidate_source_paths),
        "merged_cache_count": merged_cache_count,
        "missing_cache_count": missing_cache_count,
        "invalid_cache_count": invalid_cache_count,
        "final_cache_path": _relative(target_path),
    }


def _path_debug_summary(path: Path) -> dict[str, Any]:
    """Return a small serializable summary for one aggregate input or output path."""
    summary: dict[str, Any] = {"path": _relative(path), "exists": path.exists()}
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


def validate_aggregate_readiness(batch_id: str, *, state_root: Path) -> dict[str, Any]:
    """Return barrier readiness information for one batch."""
    done_marker_path = state_root / _done_marker_path(batch_id=batch_id)
    if done_marker_path.exists():
        logger.info(
            "Aggregate readiness for batch %s resolved to done because %s already exists",
            batch_id,
            _relative(_done_marker_path(batch_id=batch_id)),
        )
        return {"state": "done", "batch_id": batch_id}
    batch_manifest = _load_batch_manifest(batch_id=batch_id, state_root=state_root)
    discovered_worker_ids = {
        bundle.parent.name
        for bundle in _worker_bundle_paths(
            batch_id=batch_id,
            state_root=state_root,
        )
    }
    expected_worker_ids = set(batch_manifest.worker_ids)
    if discovered_worker_ids != expected_worker_ids:
        raise ValueError(
            "batch manifest worker ids do not match restored worker bundles: "
            f"expected={sorted(expected_worker_ids)} discovered={sorted(discovered_worker_ids)}"
        )
    worker_ids = list(batch_manifest.worker_ids)
    missing_status_paths = []
    in_progress_status_paths = []
    status_payloads = []
    for worker_id in worker_ids:
        status_path = _worker_status_path(batch_id=batch_id, worker_id=worker_id)
        resolved_status_path = state_root / status_path
        if not resolved_status_path.exists():
            missing_status_paths.append(_relative(status_path))
            continue
        payload = json.loads(resolved_status_path.read_text(encoding="utf-8"))
        status_payloads.append(payload)
        if payload["conclusion"] == STATUS_IN_PROGRESS:
            in_progress_status_paths.append(_relative(status_path))
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


def aggregate_batch(
    *,
    batch_id: str,
    target_ref: str,
    state_root: Path,
) -> dict[str, Any]:
    """Aggregate one fully completed batch from the persisted batch manifest."""
    readiness = validate_aggregate_readiness(batch_id, state_root=state_root)
    batch_manifest = _load_batch_manifest(batch_id=batch_id, state_root=state_root)
    config_name = batch_manifest.config_identity.config_name
    worker_ids = list(readiness.get("worker_ids", []))
    final_output_paths = batch_manifest.aggregate_output_spec.resolve_paths(state_root)
    worker_output_paths = {
        "filtered": [
            state_root
            / _worker_output_paths(
                batch_id=batch_id,
                worker_id=worker_id,
                config_name=config_name,
            )["filtered"]
            for worker_id in worker_ids
        ],
        "dead": [
            state_root
            / _worker_output_paths(
                batch_id=batch_id,
                worker_id=worker_id,
                config_name=config_name,
            )["dead"]
            for worker_id in worker_ids
        ],
        "terminal_rows": [
            state_root
            / _worker_output_paths(
                batch_id=batch_id,
                worker_id=worker_id,
                config_name=config_name,
            )["terminal_rows"]
            for worker_id in worker_ids
        ],
        "review": [
            state_root
            / _worker_output_paths(
                batch_id=batch_id,
                worker_id=worker_id,
                config_name=config_name,
            )["review"]
            for worker_id in worker_ids
        ],
        "log": [
            state_root
            / _worker_output_paths(
                batch_id=batch_id,
                worker_id=worker_id,
                config_name=config_name,
            )["log"]
            for worker_id in worker_ids
        ],
    }
    preparation_review_path = state_root / Path(
        batch_manifest.aggregate_input_review_path
    )
    preparation_terminal_rows_path = state_root / Path(
        batch_manifest.aggregate_input_terminal_rows_path
    )
    logger.debug(
        "Aggregate batch %s starting with readiness=%s derived_paths=%s",
        batch_id,
        readiness["state"],
        json.dumps(
            {
                "final_filtered_path": _relative(
                    Path(batch_manifest.aggregate_output_spec.filtered)
                ),
                "final_dead_path": _relative(
                    Path(batch_manifest.aggregate_output_spec.dead)
                ),
                "final_review_path": _relative(
                    Path(batch_manifest.aggregate_output_spec.review)
                ),
                "final_audit_path": _relative(
                    Path(batch_manifest.aggregate_output_spec.audit)
                ),
                "final_log_path": _relative(
                    Path(batch_manifest.aggregate_output_spec.log)
                ),
                "final_cache_path": _relative(
                    Path(batch_manifest.aggregate_output_spec.cache)
                ),
                "preparation_review_path": batch_manifest.aggregate_input_review_path,
                "preparation_terminal_rows_path": (
                    batch_manifest.aggregate_input_terminal_rows_path
                ),
            },
            sort_keys=True,
        ),
    )
    if readiness["state"] == "ready_failed":
        logger.debug(
            "Aggregate failed batch %s status payloads=%s",
            batch_id,
            json.dumps(readiness["status_payloads"], sort_keys=True),
        )
        cache_merge_summary = merge_cache_files(
            source_paths=_worker_cache_paths(
                worker_ids,
                batch_id=batch_id,
                config_name=config_name,
                state_root=state_root,
            ),
            target_path=final_output_paths["cache"],
        )
        logger.info(
            "Aggregate cache merge for failed batch %s: candidates=%d merged=%d "
            "missing=%d invalid=%d final=%s",
            batch_id,
            cache_merge_summary["candidate_cache_count"],
            cache_merge_summary["merged_cache_count"],
            cache_merge_summary["missing_cache_count"],
            cache_merge_summary["invalid_cache_count"],
            cache_merge_summary["final_cache_path"],
        )
        failed_statuses = [
            payload
            for payload in readiness["status_payloads"]
            if payload["conclusion"] == STATUS_FAILURE
        ]
        failure_payload = {
            "automation_format_version": AUTOMATION_FORMAT_VERSION,
            "batch_id": batch_id,
            "failed_status_count": len(failed_statuses),
            "written_at": _utc_now(),
        }
        _write_json(
            state_root / _failed_marker_path(batch_id=batch_id), failure_payload
        )
        logger.info(
            "Aggregate marked batch %s failed and wrote %s",
            batch_id,
            _relative(_failed_marker_path(batch_id=batch_id)),
        )
        return {
            "state": "failed",
            "failed_statuses": failed_statuses,
            "cache_merge_summary": cache_merge_summary,
        }
    if readiness["state"] != "ready_success":
        return readiness
    status_payloads = readiness["status_payloads"]
    try:
        _merge_host_txt_files(
            worker_output_paths["filtered"], final_output_paths["filtered"]
        )
        _merge_host_txt_files(worker_output_paths["dead"], final_output_paths["dead"])
        _merge_audit_files(
            [*worker_output_paths["terminal_rows"], preparation_terminal_rows_path],
            final_output_paths["audit"],
        )
        _merge_review_files(
            [*worker_output_paths["review"], preparation_review_path],
            final_output_paths["review"],
        )
    except DuplicateOutputInvariantError as exc:
        cache_merge_summary = merge_cache_files(
            source_paths=_worker_cache_paths(
                worker_ids,
                batch_id=batch_id,
                config_name=config_name,
                state_root=state_root,
            ),
            target_path=final_output_paths["cache"],
        )
        failure_payload = {
            "automation_format_version": AUTOMATION_FORMAT_VERSION,
            "batch_id": batch_id,
            "failed_status_count": 0,
            "written_at": _utc_now(),
            "failure_reason": str(exc),
            "duplicate_output": {
                "output_kind": exc.output_kind,
                "duplicate_key": exc.duplicate_key,
                "context": exc.context,
            },
        }
        _write_json(
            state_root / _failed_marker_path(batch_id=batch_id), failure_payload
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
    cache_merge_summary = merge_cache_files(
        source_paths=_worker_cache_paths(
            worker_ids,
            batch_id=batch_id,
            config_name=config_name,
            state_root=state_root,
        ),
        target_path=final_output_paths["cache"],
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
    summary_counts = Counter(payload["conclusion"] for payload in status_payloads)
    log_summaries = [
        {
            "worker_id": worker_id,
            "log_path": _relative(
                _worker_output_paths(
                    batch_id=batch_id,
                    worker_id=worker_id,
                    config_name=config_name,
                )["log"]
            ),
        }
        for worker_id in worker_ids
    ]
    logger.debug(
        "Aggregate log merge for batch %s starting: candidates=%d target=%s",
        batch_id,
        len(log_summaries),
        _relative(final_output_paths["log"]),
    )
    _merge_log_files(
        summaries=log_summaries,
        state_root=state_root,
        target_path=final_output_paths["log"],
    )
    final_log_summary = _path_debug_summary(final_output_paths["log"])
    logger.debug(
        "Aggregate log merge for batch %s completed: path=%s exists=%s bytes=%s",
        batch_id,
        final_log_summary["path"],
        final_log_summary["exists"],
        final_log_summary.get("bytes", 0),
    )
    logger.debug(
        "Aggregate output summaries for batch %s: %s",
        batch_id,
        json.dumps(
            {
                "final_filtered": _path_debug_summary(final_output_paths["filtered"]),
                "final_dead": _path_debug_summary(final_output_paths["dead"]),
                "final_review": _path_debug_summary(final_output_paths["review"]),
                "final_audit": _path_debug_summary(final_output_paths["audit"]),
                "final_log": final_log_summary,
                "final_cache": _path_debug_summary(final_output_paths["cache"]),
            },
            sort_keys=True,
        ),
    )

    cleanup_paths = [
        workflow_state_root(state_root) / "batches" / batch_id,
        workflow_state_root(state_root) / "workers" / batch_id,
        workflow_state_root(state_root) / "status" / batch_id,
    ]
    # Worker logs live under .debug_artifacts/workers/<batch>/<worker>/logs/worker.log,
    # so merge them before workflow-internal cleanup removes worker state roots.
    for cleanup_path in cleanup_paths:
        if cleanup_path.exists():
            shutil.rmtree(cleanup_path)

    next_turn_payload = {
        "automation_format_version": AUTOMATION_FORMAT_VERSION,
        "batch_id": batch_id,
        "target_ref": target_ref,
        "final_filtered_path": batch_manifest.aggregate_output_spec.filtered,
        "final_dead_path": batch_manifest.aggregate_output_spec.dead,
        "final_review_path": batch_manifest.aggregate_output_spec.review,
        "final_audit_path": batch_manifest.aggregate_output_spec.audit,
        "updated_at": _utc_now(),
    }
    _write_json(
        state_root / Path(batch_manifest.aggregate_output_spec.current),
        next_turn_payload,
    )
    logger.debug(
        "Aggregate next-turn payload for batch %s wrote %s",
        batch_id,
        batch_manifest.aggregate_output_spec.current,
    )

    logger.info(
        "Aggregate completed batch %s with summary_counts=%s",
        batch_id,
        dict(summary_counts),
    )
    return {
        "state": "aggregated",
        "cache_merge_summary": cache_merge_summary,
        "final_output_paths": {
            "filtered": batch_manifest.aggregate_output_spec.filtered,
            "dead": batch_manifest.aggregate_output_spec.dead,
            "review": batch_manifest.aggregate_output_spec.review,
        },
        "final_state_paths": {
            "cache": batch_manifest.aggregate_output_spec.cache,
            "current": batch_manifest.aggregate_output_spec.current,
        },
        "final_debug_paths": {
            "raw_audit": batch_manifest.aggregate_output_spec.audit,
            "runtime_log": batch_manifest.aggregate_output_spec.log,
        },
        "done_marker_payload": {
            "automation_format_version": AUTOMATION_FORMAT_VERSION,
            "batch_id": batch_id,
            "summary_counts": dict(summary_counts),
            "written_at": _utc_now(),
        },
    }


def write_done_marker(
    *,
    state_root: Path,
    batch_id: str,
    done_marker_payload: dict[str, Any],
    aggregate_commit_sha: str,
) -> str:
    """Persist the durable done marker after the aggregate commit SHA is known."""
    payload = dict(done_marker_payload)
    payload["aggregate_commit_sha"] = aggregate_commit_sha
    _write_json(state_root / _done_marker_path(batch_id=batch_id), payload)
    return _relative(_done_marker_path(batch_id=batch_id))
