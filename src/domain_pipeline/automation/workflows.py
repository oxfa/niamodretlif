"""Batch orchestration, worker processing, and aggregation helpers."""

# pylint: disable=too-many-lines

from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import tempfile
import urllib.error
import urllib.request
import zipfile
from collections import Counter, defaultdict
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from domain_pipeline.io.output_manager import write_review_rows
from domain_pipeline.io.parser import (
    DomainListParser,
    InputFileFormat,
    ParsedDomainEntry,
)
from domain_pipeline.runtime.app import run_pipeline
from domain_pipeline.runtime.history import (
    PipelineCache,
    ROOT_CLASSIFICATION_TABLE,
)
from domain_pipeline.runtime.pipeline_runner import build_checker, build_source_jobs
from domain_pipeline.settings.constants import (
    RDAP_MODE_AUTHORITATIVE,
    RDAP_SCHEDULING_AUTO,
)
from domain_pipeline.settings.config import load_config

try:
    import yaml as yaml_module
except ModuleNotFoundError as exc:  # pragma: no cover
    raise RuntimeError("PyYAML is required for automation workflows") from exc


AUTOMATION_FORMAT_VERSION = 2
WORKER_STATUS_VERSION = 2
DEFAULT_MAX_PARALLEL_WORKERS = 18
DEFAULT_WORKER_RUNTIME_BUDGET_SECONDS = 19800
STALE_RECOVERY_GRACE_SECONDS = 900
RESULT_SUMMARY_BASENAME = "result.json"
WORKER_METADATA_ARTIFACT_NAME = "worker-metadata"
PREPARED_METADATA_ARTIFACT_NAME = "prepared-rdap-metadata.json"
STATUS_IN_PROGRESS = "in_progress"
STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"
logger = logging.getLogger(__name__)


@dataclass
class PreparedWorkerPart:
    """One committed worker input part plus its descriptor payload."""

    lines: list[str]
    payload: dict[str, Any]


@dataclass
class PreparedWorkerAssignment:
    """One worker assignment plus the committed source parts it consumes."""

    payload: dict[str, Any]
    parts: list[PreparedWorkerPart]
    prepared_metadata: dict[str, Any] | None = None


@dataclass
class PreparedBatch:
    """The committed manifest plus all committed worker assignments."""

    manifest: dict[str, Any]
    worker_assignments: list[PreparedWorkerAssignment]


@dataclass(frozen=True)
class PreparedBalancingEntry:
    """One parsed entry plus the source metadata needed for batch preparation."""

    source_id: str
    source_index: int
    entry: ParsedDomainEntry
    raw_line: str
    line_index: int


@dataclass(frozen=True)
class PreparedRootPlan:
    """Preparation-time RDAP metadata for one registrable domain."""

    registrable_domain: str
    status: str
    authoritative_base_url: str | None = None


@dataclass(frozen=True)
class PreparedBatchPlanningInputs:
    """All batch-planning inputs collected before worker assignment starts."""

    source_jobs_by_id: dict[str, Any]
    source_formats: dict[str, InputFileFormat]
    eligible_root_entries: dict[str, list[PreparedBalancingEntry]]
    public_suffix_entries: list[PreparedBalancingEntry]
    legacy_jobs: list[tuple[int, Any, InputFileFormat]]
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


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sorted_dict_rows(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _relative(path: Path) -> str:
    return path.as_posix()


def _relative_to_root(path: Path, *, root: Path) -> str:
    if path.is_absolute():
        try:
            return path.relative_to(root).as_posix()
        except ValueError:
            return path.as_posix()
    return path.as_posix()


def _resolve_from_root(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_json_dump(payload), encoding="utf-8")


def _build_batch_manifest(
    *,
    batch_id: str,
    orchestrator_run_id: str,
    orchestrator_run_attempt: str,
    created_timestamp: str,
    source_sha: str | None,
    target_ref: str,
    resolved_config_path: Path,
    source_root: Path,
    config_name: str,
    worker_assignments: list[dict[str, Any]],
    expected_output_paths: list[str],
    expected_status_paths: list[str],
    output_directory: Path,
    cleanup_inputs: list[str],
    next_turn_path: Path,
    done_marker_path: Path,
    failed_marker_path: Path,
    manifest_path: Path,
    worker_runtime_budget_seconds: int,
    stale_recovery_after_seconds: int,
) -> dict[str, Any]:
    expected_worker_identities = [entry["worker_id"] for entry in worker_assignments]
    return {
        "automation_format_version": AUTOMATION_FORMAT_VERSION,
        "batch_id": batch_id,
        "orchestrator": {
            "workflow_run_id": str(orchestrator_run_id),
            "workflow_run_attempt": str(orchestrator_run_attempt),
            "created_at": created_timestamp,
            "source_sha": source_sha,
        },
        "target_ref": target_ref,
        "source_input_path": _relative_to_root(resolved_config_path, root=source_root),
        "config_name": config_name,
        "worker_assignments": worker_assignments,
        "expected_worker_count": len(expected_worker_identities),
        "expected_worker_identities": expected_worker_identities,
        "expected_output_paths": expected_output_paths,
        "expected_status_paths": expected_status_paths,
        "aggregation_inputs": {
            "result_summary_paths": expected_output_paths,
            "final_filtered_path": _relative(
                output_directory / "filtered" / f"{config_name}.txt"
            ),
            "final_dead_path": _relative(
                output_directory / "dead" / f"{config_name}.txt"
            ),
            "final_review_path": _relative(
                output_directory / "review" / f"{config_name}.csv"
            ),
            "final_audit_path": _relative(
                Path("output") / "raw" / f"{config_name}.jsonl"
            ),
            "final_log_path": _relative(
                Path(".tmp") / "runtime" / "logs" / f"{config_name}.log"
            ),
            "final_cache_path": _relative(
                Path(".tmp") / "runtime" / "check-cache.sqlite3"
            ),
        },
        "cleanup_inputs": sorted(set(cleanup_inputs)),
        "next_turn_preparation_inputs": {
            "current_batch_path": _relative(next_turn_path),
        },
        "done_marker_path": _relative(done_marker_path),
        "failed_marker_path": _relative(failed_marker_path),
        "manifest_path": _relative(manifest_path),
        "audit": {
            "manifest_created_at": created_timestamp,
        },
        "worker_runtime_budget_seconds": worker_runtime_budget_seconds,
        "stale_recovery_after_seconds": stale_recovery_after_seconds,
    }


def _balanced_chunked(
    lines: list[str], *, chunk_count: int
) -> Iterator[tuple[int, list[str]]]:
    """Yield non-empty chunks that differ in size by at most one line."""
    if chunk_count < 1:
        raise ValueError("chunk_count must be at least 1")
    if chunk_count > len(lines):
        raise ValueError("chunk_count must not exceed the available line count")

    base_size, remainder = divmod(len(lines), chunk_count)
    start = 0
    for chunk_index in range(chunk_count):
        chunk_size = base_size + (1 if chunk_index < remainder else 0)
        end = start + chunk_size
        yield chunk_index, lines[start:end]
        start = end


def _iter_job_chunks(
    *,
    parser: DomainListParser,
    job: Any,
    part_count: int,
) -> Iterator[tuple[InputFileFormat, int, list[str]]]:
    """Yield validated source parts for one source job."""
    detected_format = parser.detect_file_format(job.lines)
    if detected_format in {InputFileFormat.UNKNOWN, InputFileFormat.MIXED}:
        raise ValueError(
            f"source {job.source_id} from {job.input_label} cannot be split safely "
            f"because it detected {detected_format.value}"
        )
    for chunk_index, chunk_lines in _balanced_chunked(
        job.lines,
        chunk_count=part_count,
    ):
        yield detected_format, chunk_index, chunk_lines


def _job_forced_format(job: Any) -> InputFileFormat | str | None:
    """Return the explicit job format override when one is configured."""
    forced_format_value = str(job.config["input"].get("format", "auto"))
    if forced_format_value == "auto":
        return None
    return InputFileFormat(forced_format_value)


def _validated_job_format(parser: DomainListParser, job: Any) -> InputFileFormat:
    """Return one source format or raise when the source cannot be split safely."""
    forced_format = _job_forced_format(job)
    if forced_format is None:
        detected_format = parser.detect_file_format(job.lines)
    else:
        detected_format = (
            forced_format
            if isinstance(forced_format, InputFileFormat)
            else InputFileFormat(str(forced_format))
        )
    if detected_format in {InputFileFormat.UNKNOWN, InputFileFormat.MIXED}:
        raise ValueError(
            f"source {job.source_id} from {job.input_label} cannot be split safely "
            f"because it detected {detected_format.value}"
        )
    return detected_format


def _rdap_prebalancing_enabled(job: Any) -> bool:
    """Return whether one source should use RDAP-aware preparation."""
    rdap_config = job.config.get("rdap", {})
    return (
        rdap_config.get("mode", RDAP_MODE_AUTHORITATIVE) == RDAP_MODE_AUTHORITATIVE
        and rdap_config.get("scheduling", RDAP_SCHEDULING_AUTO) == RDAP_SCHEDULING_AUTO
    )


def _prepared_entries_for_job(
    *,
    parser: DomainListParser,
    job: Any,
    source_index: int,
    detected_format: InputFileFormat,
) -> list[PreparedBalancingEntry]:
    """Return parser-backed prepared entries for one RDAP-aware source job."""
    records = list(
        parser.process_entry_records(
            job.lines,
            source_name=job.input_label,
            forced_format=detected_format,
        )
    )
    return [
        PreparedBalancingEntry(
            source_id=job.source_id,
            source_index=source_index,
            entry=record.entry,
            raw_line=record.raw_line,
            line_index=record.line_index,
        )
        for record in records
    ]


def _worker_prepared_metadata_path(*, batch_id: str, worker_id: str) -> Path:
    """Return the committed prepared-metadata path for one worker."""
    return (
        Path(".automation")
        / "batches"
        / batch_id
        / "workers"
        / worker_id
        / PREPARED_METADATA_ARTIFACT_NAME
    )


def _build_prepared_entry_payload(entry: PreparedBalancingEntry) -> dict[str, Any]:
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
    }


def _build_worker_prepared_metadata(
    *,
    batch_id: str,
    worker_id: str,
    source_entries: dict[str, list[PreparedBalancingEntry]],
    root_plans: dict[str, PreparedRootPlan],
) -> dict[str, Any]:
    """Return one worker-local prepared metadata payload."""
    sources_payload: dict[str, Any] = {}
    for source_id, entries in sorted(
        source_entries.items(),
        key=lambda item: (item[1][0].source_index, item[0]),
    ):
        ordered_entries = sorted(entries, key=lambda current: current.line_index)
        sources_payload[source_id] = {
            "source_index": ordered_entries[0].source_index,
            "entries": [
                _build_prepared_entry_payload(entry) for entry in ordered_entries
            ],
        }
    return {
        "automation_format_version": AUTOMATION_FORMAT_VERSION,
        "batch_id": batch_id,
        "worker_id": worker_id,
        "sources": sources_payload,
        "rdap_roots": {
            registrable_domain: {
                "status": plan.status,
                "authoritative_base_url": plan.authoritative_base_url,
            }
            for registrable_domain, plan in sorted(root_plans.items())
        },
    }


def _worker_target_counts(worker_ids: list[str], item_count: int) -> dict[str, int]:
    """Return deterministic target counts that differ by at most one item."""
    if not worker_ids:
        raise ValueError("at least one worker_id is required to prepare a batch")
    base_count, remainder = divmod(item_count, len(worker_ids))
    return {
        worker_id: base_count + (1 if index < remainder else 0)
        for index, worker_id in enumerate(worker_ids)
    }


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
    worker_source_entries: dict[str, dict[str, list[PreparedBalancingEntry]]],
    worker_root_plans: dict[str, dict[str, PreparedRootPlan]],
    worker_entry_counts: Counter,
    worker_server_counts: dict[str, Counter],
    roots_by_server: dict[str, list[str]],
) -> None:
    """Emit one compact debug summary of RDAP-aware worker assignment quality."""
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
                "rdap_root_count": len(root_plans),
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
        counts = {
            worker_id: worker_server_counts[worker_id][authoritative_base_url]
            for worker_id in worker_ids
            if worker_server_counts[worker_id][authoritative_base_url] > 0
        }
        if counts:
            server_summaries.append(
                {
                    "authoritative_server": authoritative_base_url,
                    "worker_root_counts": counts,
                }
            )
    if server_summaries:
        logger.debug(
            "Batch preparation authoritative server spread=%s", server_summaries
        )


def _collect_batch_planning_inputs(
    *, parser: DomainListParser, jobs: list[Any]
) -> PreparedBatchPlanningInputs:
    """Return validated source inputs plus RDAP planning metadata."""
    source_jobs_by_id: dict[str, Any] = {}
    source_formats: dict[str, InputFileFormat] = {}
    eligible_root_entries: dict[str, list[PreparedBalancingEntry]] = defaultdict(list)
    public_suffix_entries: list[PreparedBalancingEntry] = []
    legacy_jobs: list[tuple[int, Any, InputFileFormat]] = []
    checker_cache: dict[str, Any] = {}

    for source_index, job in enumerate(jobs):
        detected_format = _validated_job_format(parser, job)
        source_jobs_by_id[job.source_id] = job
        source_formats[job.source_id] = detected_format
        if not _rdap_prebalancing_enabled(job):
            logger.debug(
                "Batch preparation source=%s using legacy chunking "
                "(format=%s line_count=%d)",
                job.source_id,
                detected_format.value,
                len(job.lines),
            )
            legacy_jobs.append((source_index, job, detected_format))
            continue
        prepared_entries = _prepared_entries_for_job(
            parser=parser,
            job=job,
            source_index=source_index,
            detected_format=detected_format,
        )
        logger.debug(
            "Batch preparation source=%s using RDAP-aware balancing "
            "(format=%s parsed_entries=%d)",
            job.source_id,
            detected_format.value,
            len(prepared_entries),
        )
        for prepared_entry in prepared_entries:
            registrable_domain = prepared_entry.entry.registrable_domain
            if prepared_entry.entry.is_public_suffix_input or not registrable_domain:
                public_suffix_entries.append(prepared_entry)
                continue
            eligible_root_entries[registrable_domain].append(prepared_entry)
        if prepared_entries:
            checker_cache[job.source_id] = build_checker(job.config)

    root_plans: dict[str, PreparedRootPlan] = {}
    for registrable_domain, entries in sorted(eligible_root_entries.items()):
        source_id = entries[0].source_id
        checker = checker_cache[source_id]
        try:
            authoritative_base_url = (
                checker._authoritative_base_url(  # pylint: disable=protected-access
                    registrable_domain
                )
            )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.warning(
                "RDAP preparation could not resolve authoritative server for "
                "root=%s source=%s: %s",
                registrable_domain,
                source_id,
                exc,
            )
            root_plans[registrable_domain] = PreparedRootPlan(
                registrable_domain=registrable_domain,
                status="unknown",
            )
            logger.debug(
                "Batch preparation root=%s resolved status=unknown source=%s",
                registrable_domain,
                source_id,
            )
            continue
        if authoritative_base_url is None:
            root_plans[registrable_domain] = PreparedRootPlan(
                registrable_domain=registrable_domain,
                status="unavailable",
            )
            logger.debug(
                "Batch preparation root=%s resolved status=unavailable source=%s",
                registrable_domain,
                source_id,
            )
            continue
        root_plans[registrable_domain] = PreparedRootPlan(
            registrable_domain=registrable_domain,
            status="resolved",
            authoritative_base_url=authoritative_base_url,
        )
        logger.debug(
            "Batch preparation root=%s resolved status=resolved "
            "authoritative_server=%s source=%s",
            registrable_domain,
            authoritative_base_url,
            source_id,
        )
    return PreparedBatchPlanningInputs(
        source_jobs_by_id=source_jobs_by_id,
        source_formats=source_formats,
        eligible_root_entries=eligible_root_entries,
        public_suffix_entries=public_suffix_entries,
        legacy_jobs=legacy_jobs,
        root_plans=root_plans,
    )


def _initialize_assignment_descriptors(
    *,
    worker_ids: list[str],
    batch_id: str,
    config_name: str,
    resolved_config_path: Path,
    source_root: Path,
    cache_config: dict[str, Any],
) -> tuple[
    list[PreparedWorkerAssignment],
    list[dict[str, Any]],
    dict[str, PreparedWorkerAssignment],
    list[str],
    list[str],
    list[str],
]:
    """Return initialized per-worker assignment descriptors."""
    prepared_assignments: list[PreparedWorkerAssignment] = []
    assignment_entries: list[dict[str, Any]] = []
    assignments_by_worker: dict[str, PreparedWorkerAssignment] = {}
    expected_output_paths: list[str] = []
    expected_status_paths: list[str] = []
    cleanup_inputs: list[str] = []
    for worker_id in worker_ids:
        assignment_descriptor = _build_worker_assignment_descriptor(
            batch_id=batch_id,
            worker_id=worker_id,
            config_name=config_name,
            resolved_config_path=resolved_config_path,
            source_root=source_root,
            cache_config=cache_config,
        )
        cleanup_inputs.append(
            _relative(Path(assignment_descriptor["cache_path"]).parent)
        )
        prepared_assignment = PreparedWorkerAssignment(
            payload=assignment_descriptor,
            parts=[],
            prepared_metadata=None,
        )
        prepared_assignments.append(prepared_assignment)
        assignment_entries.append(assignment_descriptor)
        assignments_by_worker[worker_id] = prepared_assignment
        expected_output_paths.append(str(assignment_descriptor["result_summary_path"]))
        expected_status_paths.append(str(assignment_descriptor["status_path"]))
    return (
        prepared_assignments,
        assignment_entries,
        assignments_by_worker,
        expected_output_paths,
        expected_status_paths,
        cleanup_inputs,
    )


def _assign_prepared_entries_to_workers(
    *,
    planning_inputs: PreparedBatchPlanningInputs,
    worker_ids: list[str],
) -> tuple[
    dict[str, dict[str, list[PreparedBalancingEntry]]],
    dict[str, dict[str, PreparedRootPlan]],
    Counter,
]:
    """Assign RDAP-aware prepared entries across workers deterministically."""
    worker_source_entries: dict[str, dict[str, list[PreparedBalancingEntry]]] = {
        worker_id: defaultdict(list) for worker_id in worker_ids
    }
    worker_root_plans: dict[str, dict[str, PreparedRootPlan]] = {
        worker_id: {} for worker_id in worker_ids
    }
    worker_entry_counts: Counter = Counter()
    worker_rdap_root_counts: Counter = Counter()
    worker_server_counts: dict[str, Counter] = {
        worker_id: Counter() for worker_id in worker_ids
    }

    rdap_root_targets = _worker_target_counts(
        worker_ids,
        len(
            [
                plan
                for plan in planning_inputs.root_plans.values()
                if plan.status != "unavailable"
            ]
        ),
    )

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
        worker_entry_counts[worker_id] += len(
            planning_inputs.eligible_root_entries[registrable_domain]
        )
        plan = planning_inputs.root_plans[registrable_domain]
        logger.debug(
            "Batch preparation assigned root=%s status=%s authoritative_server=%s "
            "worker=%s entry_count=%d",
            registrable_domain,
            plan.status,
            plan.authoritative_base_url or "(none)",
            worker_id,
            len(planning_inputs.eligible_root_entries[registrable_domain]),
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

    for authoritative_base_url, current_roots in sorted(
        roots_by_server.items(),
        key=lambda item: (-len(item[1]), item[0]),
    ):
        for registrable_domain in sorted(current_roots):
            candidates = [
                worker_id
                for worker_id in worker_ids
                if worker_rdap_root_counts[worker_id] < rdap_root_targets[worker_id]
            ]
            if not candidates:
                candidates = list(worker_ids)
            worker_id = min(
                candidates,
                key=lambda current_worker_id, authoritative_server=authoritative_base_url: (
                    worker_server_counts[current_worker_id][authoritative_server],
                    -(
                        rdap_root_targets[current_worker_id]
                        - worker_rdap_root_counts[current_worker_id]
                    ),
                    current_worker_id,
                ),
            )
            assign_root(worker_id, registrable_domain)
            worker_rdap_root_counts[worker_id] += 1
            worker_server_counts[worker_id][authoritative_base_url] += 1

    for registrable_domain in sorted(unknown_roots):
        candidates = [
            worker_id
            for worker_id in worker_ids
            if worker_rdap_root_counts[worker_id] < rdap_root_targets[worker_id]
        ]
        if not candidates:
            candidates = list(worker_ids)
        worker_id = min(
            candidates,
            key=lambda current_worker_id: (
                worker_rdap_root_counts[current_worker_id],
                worker_entry_counts[current_worker_id],
                current_worker_id,
            ),
        )
        assign_root(worker_id, registrable_domain)
        worker_rdap_root_counts[worker_id] += 1

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
        worker_server_counts=worker_server_counts,
        roots_by_server=roots_by_server,
    )
    return worker_source_entries, worker_root_plans, worker_entry_counts


def _append_legacy_parts(
    *,
    parser: DomainListParser,
    batch_id: str,
    worker_ids: list[str],
    legacy_jobs: list[tuple[int, Any, InputFileFormat]],
    assignments_by_worker: dict[str, PreparedWorkerAssignment],
    worker_entry_counts: Counter,
) -> None:
    """Append legacy contiguous source parts for non-RDAP-aware jobs."""
    source_start_index = 0
    for source_index, job, detected_format in legacy_jobs:
        source_part_count = min(len(worker_ids), len(job.lines))
        for _detected_format, chunk_index, chunk_lines in _iter_job_chunks(
            parser=parser,
            job=job,
            part_count=source_part_count,
        ):
            worker_index = (source_start_index + chunk_index) % len(worker_ids)
            worker_id = worker_ids[worker_index]
            part_descriptor = _build_part_descriptor(
                batch_id=batch_id,
                worker_id=worker_id,
                source_index=source_index,
                job=job,
                detected_format=detected_format,
                part_index=chunk_index,
                chunk_lines=chunk_lines,
            )
            prepared_part = PreparedWorkerPart(
                lines=chunk_lines, payload=part_descriptor
            )
            assignments_by_worker[worker_id].parts.append(prepared_part)
            assignments_by_worker[worker_id].payload["parts"].append(part_descriptor)
            worker_entry_counts[worker_id] += len(chunk_lines)
        source_start_index = (source_start_index + source_part_count) % len(worker_ids)


def _append_prepared_parts(
    *,
    batch_id: str,
    worker_ids: list[str],
    source_jobs_by_id: dict[str, Any],
    source_formats: dict[str, InputFileFormat],
    worker_source_entries: dict[str, dict[str, list[PreparedBalancingEntry]]],
    worker_root_plans: dict[str, dict[str, PreparedRootPlan]],
    assignments_by_worker: dict[str, PreparedWorkerAssignment],
) -> None:
    """Append RDAP-aware prepared parts and worker metadata to assignments."""
    eligible_part_indexes: dict[tuple[str, str], int] = {}
    source_worker_ids: dict[str, list[str]] = defaultdict(list)
    for worker_id, source_entries in worker_source_entries.items():
        for source_id, entries in source_entries.items():
            if entries:
                source_worker_ids[source_id].append(worker_id)
    for source_id, source_worker_group in source_worker_ids.items():
        for part_index, worker_id in enumerate(sorted(source_worker_group)):
            eligible_part_indexes[(source_id, worker_id)] = part_index

    for worker_id in worker_ids:
        assignment = assignments_by_worker[worker_id]
        assignment.prepared_metadata = _build_worker_prepared_metadata(
            batch_id=batch_id,
            worker_id=worker_id,
            source_entries=worker_source_entries[worker_id],
            root_plans=worker_root_plans[worker_id],
        )
        for source_id, entries in sorted(
            worker_source_entries[worker_id].items(),
            key=lambda item: (item[1][0].source_index, item[0]),
        ):
            if not entries:
                continue
            ordered_entries = sorted(entries, key=lambda current: current.line_index)
            source_job = source_jobs_by_id[source_id]
            chunk_lines = [entry.raw_line for entry in ordered_entries]
            part_descriptor = _build_part_descriptor(
                batch_id=batch_id,
                worker_id=worker_id,
                source_index=ordered_entries[0].source_index,
                job=source_job,
                detected_format=source_formats[source_id],
                part_index=eligible_part_indexes[(source_id, worker_id)],
                chunk_lines=chunk_lines,
            )
            prepared_part = PreparedWorkerPart(
                lines=chunk_lines,
                payload=part_descriptor,
            )
            assignment.parts.append(prepared_part)
            assignment.payload["parts"].append(part_descriptor)
        ordered_pairs = sorted(
            zip(assignment.parts, assignment.payload["parts"]),
            key=lambda pair: (
                pair[0].payload["source_index"],
                pair[0].payload["part_index"],
                pair[0].payload["source_id"],
            ),
        )
        assignment.parts = [pair[0] for pair in ordered_pairs]
        assignment.payload["parts"] = [pair[1] for pair in ordered_pairs]


def _build_worker_assignment_descriptor(
    *,
    batch_id: str,
    worker_id: str,
    config_name: str,
    resolved_config_path: Path,
    source_root: Path,
    cache_config: dict[str, Any],
) -> dict[str, Any]:
    result_root = Path(".automation") / "results" / batch_id / worker_id
    status_path = Path(".automation") / "status" / batch_id / f"{worker_id}.json"
    summary_path = result_root / RESULT_SUMMARY_BASENAME
    filtered_path = result_root / "output" / "filtered" / f"{config_name}.txt"
    dead_path = result_root / "output" / "dead" / f"{config_name}.txt"
    review_path = result_root / "output" / "review" / f"{config_name}.csv"
    audit_path = result_root / "output" / "raw" / f"{config_name}.jsonl"
    log_path = result_root / "state" / "worker.log"
    cache_path = result_root / "cache" / "check-cache.sqlite3"
    worker_state_root = result_root / "state"
    prepared_metadata_path = _worker_prepared_metadata_path(
        batch_id=batch_id,
        worker_id=worker_id,
    )
    return {
        "batch_id": batch_id,
        "config_name": config_name,
        "config_path": _relative_to_root(resolved_config_path, root=source_root),
        "worker_id": worker_id,
        "parts": [],
        "prepared_metadata_path": _relative(prepared_metadata_path),
        "result_root": _relative(result_root),
        "result_summary_path": _relative(summary_path),
        "status_path": _relative(status_path),
        "filtered_path": _relative(filtered_path),
        "dead_path": _relative(dead_path),
        "review_path": _relative(review_path),
        "audit_path": _relative(audit_path),
        "log_path": _relative(log_path),
        "cache_path": _relative(cache_path),
        "state_root": _relative(worker_state_root),
        "cache_config": json.loads(json.dumps(cache_config)),
    }


def _build_part_descriptor(
    *,
    batch_id: str,
    worker_id: str,
    source_index: int,
    job: Any,
    detected_format: InputFileFormat,
    part_index: int,
    chunk_lines: list[str],
) -> dict[str, Any]:
    part_path = (
        Path(".automation")
        / "batches"
        / batch_id
        / "workers"
        / worker_id
        / f"{job.source_id}.txt"
    )
    return {
        "source_id": job.source_id,
        "source_index": source_index,
        "part_index": part_index,
        "worker_id": worker_id,
        "source_input_label": job.input_label,
        "source_format": detected_format.value,
        "line_count": len(chunk_lines),
        "part_path": _relative(part_path),
        "source_config": json.loads(json.dumps(job.config)),
    }


def prepare_batch(
    *,
    source_root: Path,
    config_path: Path,
    target_ref: str,
    source_sha: str | None,
    worker_ids: list[str],
    batch_id: str,
    orchestrator_run_id: str,
    orchestrator_run_attempt: str,
    worker_runtime_budget_seconds: int = DEFAULT_WORKER_RUNTIME_BUDGET_SECONDS,
    created_at: str | None = None,
) -> PreparedBatch:
    """Build one committed batch manifest and deterministic worker input parts."""
    if worker_runtime_budget_seconds < 1:
        raise ValueError("worker_runtime_budget_seconds must be at least 1")
    created_timestamp = created_at or _utc_now()
    stale_recovery_after_seconds = (
        worker_runtime_budget_seconds + STALE_RECOVERY_GRACE_SECONDS
    )
    resolved_config_path = _resolve_from_root(source_root, config_path)
    config = load_config(resolved_config_path)
    jobs = build_source_jobs(config)
    if not jobs:
        raise ValueError(f"config {config_path} produced no runnable source jobs")

    config_name = str(config["config_name"])
    output_directory = Path(jobs[0].config["output"]["directory"])
    manifest_path = Path(".automation") / "batches" / batch_id / "manifest.json"
    next_turn_path = Path(".automation") / "current" / f"{config_name}.json"
    done_marker_path = Path(".automation") / "aggregate" / batch_id / "done.json"
    failed_marker_path = Path(".automation") / "aggregate" / batch_id / "failed.json"

    parser = DomainListParser()
    planning_inputs = _collect_batch_planning_inputs(parser=parser, jobs=jobs)
    total_work_units = (
        len(planning_inputs.root_plans)
        + len(planning_inputs.public_suffix_entries)
        + sum(
            len(job.lines)
            for _source_index, job, _detected_format in planning_inputs.legacy_jobs
        )
    )
    if total_work_units < 1:
        raise ValueError("config produced no input lines to process")
    participating_worker_ids = worker_ids[: min(len(worker_ids), total_work_units)]
    if not participating_worker_ids:
        raise ValueError("at least one worker_id is required to prepare a batch")

    (
        prepared_assignments,
        assignment_entries,
        assignments_by_worker,
        expected_output_paths,
        expected_status_paths,
        cleanup_inputs,
    ) = _initialize_assignment_descriptors(
        worker_ids=participating_worker_ids,
        batch_id=batch_id,
        config_name=config_name,
        resolved_config_path=resolved_config_path,
        source_root=source_root,
        cache_config=config["cache"],
    )
    worker_source_entries, worker_root_plans, worker_entry_counts = (
        _assign_prepared_entries_to_workers(
            planning_inputs=planning_inputs,
            worker_ids=participating_worker_ids,
        )
    )
    _append_legacy_parts(
        parser=parser,
        batch_id=batch_id,
        worker_ids=participating_worker_ids,
        legacy_jobs=planning_inputs.legacy_jobs,
        assignments_by_worker=assignments_by_worker,
        worker_entry_counts=worker_entry_counts,
    )
    _append_prepared_parts(
        batch_id=batch_id,
        worker_ids=participating_worker_ids,
        source_jobs_by_id=planning_inputs.source_jobs_by_id,
        source_formats=planning_inputs.source_formats,
        worker_source_entries=worker_source_entries,
        worker_root_plans=worker_root_plans,
        assignments_by_worker=assignments_by_worker,
    )

    manifest = _build_batch_manifest(
        batch_id=batch_id,
        orchestrator_run_id=orchestrator_run_id,
        orchestrator_run_attempt=orchestrator_run_attempt,
        created_timestamp=created_timestamp,
        source_sha=source_sha,
        target_ref=target_ref,
        resolved_config_path=resolved_config_path,
        source_root=source_root,
        config_name=config_name,
        worker_assignments=assignment_entries,
        expected_output_paths=expected_output_paths,
        expected_status_paths=expected_status_paths,
        output_directory=output_directory,
        cleanup_inputs=cleanup_inputs,
        next_turn_path=next_turn_path,
        done_marker_path=done_marker_path,
        failed_marker_path=failed_marker_path,
        manifest_path=manifest_path,
        worker_runtime_budget_seconds=worker_runtime_budget_seconds,
        stale_recovery_after_seconds=stale_recovery_after_seconds,
    )
    return PreparedBatch(
        manifest=manifest,
        worker_assignments=prepared_assignments,
    )


def write_prepared_batch(prepared: PreparedBatch, *, state_root: Path) -> list[str]:
    """Write one prepared batch to disk and return the committed path list."""
    manifest_path = state_root / prepared.manifest["manifest_path"]
    _write_json(manifest_path, prepared.manifest)
    committed_paths = [prepared.manifest["manifest_path"]]
    for assignment in prepared.worker_assignments:
        prepared_metadata_path = (
            state_root / assignment.payload["prepared_metadata_path"]
        )
        _write_json(
            prepared_metadata_path,
            (
                assignment.prepared_metadata
                if assignment.prepared_metadata is not None
                else {
                    "automation_format_version": AUTOMATION_FORMAT_VERSION,
                    "batch_id": prepared.manifest["batch_id"],
                    "worker_id": assignment.payload["worker_id"],
                    "sources": {},
                    "rdap_roots": {},
                }
            ),
        )
        committed_paths.append(assignment.payload["prepared_metadata_path"])
        for part in assignment.parts:
            part_path = state_root / part.payload["part_path"]
            part_path.parent.mkdir(parents=True, exist_ok=True)
            part_path.write_text("".join(part.lines), encoding="utf-8")
            committed_paths.append(part.payload["part_path"])
    return sorted(committed_paths)


def validate_manifest_payload(manifest: dict[str, Any]) -> None:
    """Validate one committed batch manifest."""
    required_keys = {
        "automation_format_version",
        "batch_id",
        "orchestrator",
        "target_ref",
        "worker_assignments",
        "expected_worker_count",
        "expected_worker_identities",
        "expected_output_paths",
        "expected_status_paths",
        "aggregation_inputs",
        "cleanup_inputs",
        "next_turn_preparation_inputs",
        "done_marker_path",
        "failed_marker_path",
        "manifest_path",
        "worker_runtime_budget_seconds",
        "stale_recovery_after_seconds",
    }
    missing_keys = required_keys.difference(manifest)
    if missing_keys:
        raise ValueError(
            "manifest is missing required keys: " + ", ".join(sorted(missing_keys))
        )
    if manifest["automation_format_version"] != AUTOMATION_FORMAT_VERSION:
        raise ValueError(
            "manifest automation_format_version must be " f"{AUTOMATION_FORMAT_VERSION}"
        )
    if (
        not isinstance(manifest["worker_assignments"], list)
        or not manifest["worker_assignments"]
    ):
        raise ValueError(
            "manifest worker_assignments must contain at least one assignment"
        )
    if len(manifest["expected_worker_identities"]) != manifest["expected_worker_count"]:
        raise ValueError(
            "manifest expected_worker_count does not match worker identities"
        )
    if int(manifest["worker_runtime_budget_seconds"]) < 1:
        raise ValueError("manifest worker_runtime_budget_seconds must be at least 1")
    if int(manifest["stale_recovery_after_seconds"]) < int(
        manifest["worker_runtime_budget_seconds"]
    ):
        raise ValueError(
            "manifest stale_recovery_after_seconds must be at least the worker runtime budget"
        )
    if not isinstance(manifest["orchestrator"], dict):
        raise ValueError("manifest orchestrator must be a JSON object")


def load_manifest(batch_id: str, *, state_root: Path) -> dict[str, Any]:
    """Load one manifest by batch identifier."""
    manifest_path = state_root / ".automation" / "batches" / batch_id / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError(f"manifest {manifest_path} must be a JSON object")
    validate_manifest_payload(manifest)
    return manifest


def _load_existing_metadata(metadata_output_path: Path) -> dict[str, Any]:
    if not metadata_output_path.exists():
        return {}
    payload = json.loads(metadata_output_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(
            f"worker metadata {metadata_output_path} must be a JSON object"
        )
    return payload


def bootstrap_worker_metadata(
    *,
    batch_id: str,
    worker_id: str,
    target_ref: str,
    source_sha: str,
    run_id: str,
    run_attempt: str,
    metadata_output_path: Path,
) -> dict[str, Any]:
    """Write minimal worker metadata before manifest or status handling begins."""
    metadata = {
        "automation_format_version": AUTOMATION_FORMAT_VERSION,
        "batch_id": batch_id,
        "worker_id": worker_id,
        "target_ref": target_ref,
        "source_sha": source_sha,
        "run_id": str(run_id),
        "run_attempt": str(run_attempt),
        "participates": False,
        "status_paths": [],
        "result_paths": [],
        "overall_conclusion": STATUS_IN_PROGRESS,
        "status_templates": [],
        "errors": [],
        "phase": "bootstrapped",
    }
    _write_json(metadata_output_path, metadata)
    return metadata


@contextmanager
def _pushd(path: Path) -> Iterator[None]:
    original = Path.cwd()
    path.mkdir(parents=True, exist_ok=True)
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(original)


def _write_yaml(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml_module.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _write_result_summary(
    *,
    repo_root: Path,
    assignment: dict[str, Any],
    conclusion: str,
    error_reason: str | None,
) -> dict[str, Any]:
    summary_payload = {
        "automation_format_version": AUTOMATION_FORMAT_VERSION,
        "batch_id": assignment["batch_id"],
        "worker_id": assignment["worker_id"],
        "conclusion": conclusion,
        "result_root": assignment["result_root"],
        "filtered_path": assignment["filtered_path"],
        "dead_path": assignment["dead_path"],
        "review_path": assignment["review_path"],
        "audit_path": assignment["audit_path"],
        "cache_path": assignment["cache_path"],
        "log_path": assignment["log_path"],
        "state_root": assignment["state_root"],
        "error_reason": error_reason,
        "written_at": _utc_now(),
    }
    _write_json(repo_root / assignment["result_summary_path"], summary_payload)
    return summary_payload


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


def _assignment_for_worker(
    manifest: dict[str, Any], *, worker_id: str
) -> dict[str, Any] | None:
    for assignment in manifest["worker_assignments"]:
        if assignment["worker_id"] == worker_id:
            return assignment
    return None


def _build_worker_config(
    *,
    source_root: Path,
    state_root: Path,
    assignment: dict[str, Any],
    temp_config_path: Path,
) -> None:
    cache_config = json.loads(json.dumps(assignment["cache_config"]))
    source_configs: list[dict[str, Any]] = []
    for part in assignment["parts"]:
        source_config = json.loads(json.dumps(part["source_config"]))
        source_config.get("geo", {}).pop("requires_region_lookup", None)
        source_config.get("geo", {}).pop("effective_provider", None)
        source_config["input"]["type"] = "file"
        source_config["input"]["location"] = str(state_root / part["part_path"])
        source_config["input"]["label"] = part["source_input_label"]
        source_config["input"]["format"] = part["source_format"]
        source_config["output"]["directory"] = str(
            state_root / Path(assignment["result_root"]) / "output"
        )
        source_configs.append(source_config)
    payload = {
        "version": 2,
        "cache": {
            "cache_file": str(state_root / assignment["cache_path"]),
            "baseline_cache_file": str(
                (source_root / ".tmp" / "runtime" / "check-cache.sqlite3").resolve()
            ),
            "classification_ttl_days": cache_config["classification_ttl_days"],
            "dns_ttl_days": cache_config["dns_ttl_days"],
        },
        "sources": source_configs,
    }
    _write_yaml(temp_config_path, payload)


def _stage_worker_manual_filter_pass_file(
    *, source_root: Path, assignment: dict[str, Any], result_root: Path
) -> Path | None:
    """Copy the repo-root manual filter-pass file into the worker runtime cwd."""
    source_path = (
        source_root
        / "input"
        / "manual_filter_pass"
        / f"{assignment['config_name']}.txt"
    )
    if not source_path.is_file():
        logger.debug(
            "Worker %s found no repo-root manual filter-pass file at %s; "
            "skipping worker-local staging",
            assignment["worker_id"],
            source_path,
        )
        return None
    target_path = (
        result_root
        / "input"
        / "manual_filter_pass"
        / f"{assignment['config_name']}.txt"
    )
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, target_path)
    logger.debug(
        "Worker %s staged manual filter-pass file from %s to %s",
        assignment["worker_id"],
        source_path,
        target_path,
    )
    return target_path


def _status_template_for_worker(
    *,
    manifest: dict[str, Any],
    assignment: dict[str, Any],
    worker_id: str,
) -> dict[str, Any]:
    return {
        "automation_format_version": AUTOMATION_FORMAT_VERSION,
        "status_version": WORKER_STATUS_VERSION,
        "batch_id": manifest["batch_id"],
        "worker_id": worker_id,
        "worker_category": "static-worker-workflow",
        "conclusion": STATUS_IN_PROGRESS,
        "output_paths": [
            assignment["result_root"],
            assignment["filtered_path"],
            assignment["dead_path"],
            assignment["review_path"],
            assignment["audit_path"],
        ],
        "status_path": assignment["status_path"],
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
        "worker_category": template["worker_category"],
        "conclusion": conclusion,
        "output_paths": template["output_paths"],
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
    metadata_output_path: Path,
) -> dict[str, Any]:
    """Write initial worker metadata and one in-progress worker status file."""
    manifest = load_manifest(batch_id, state_root=state_root)
    metadata = _load_existing_metadata(metadata_output_path)
    assignment = _assignment_for_worker(manifest, worker_id=worker_id)
    if assignment is None:
        metadata.update(
            {
                "automation_format_version": AUTOMATION_FORMAT_VERSION,
                "batch_id": batch_id,
                "worker_id": worker_id,
                "participates": False,
                "target_ref": manifest["target_ref"],
                "status_paths": [],
                "result_paths": [],
                "overall_conclusion": "skipped",
                "status_templates": [],
                "phase": "skipped",
            }
        )
        _write_json(metadata_output_path, metadata)
        return metadata

    status_templates = [
        _status_template_for_worker(
            manifest=manifest,
            assignment=assignment,
            worker_id=worker_id,
        )
    ]
    written_paths: list[str] = []
    for template in status_templates:
        status_payload = _status_payload_from_template(
            template=template,
            output_commit_sha="",
            push_retry_count=0,
            finished_at=None,
            conclusion=STATUS_IN_PROGRESS,
            failure_reason=None,
        )
        status_path = state_root / template["status_path"]
        _write_json(status_path, status_payload)
        written_paths.append(template["status_path"])

    metadata.update(
        {
            "automation_format_version": AUTOMATION_FORMAT_VERSION,
            "batch_id": batch_id,
            "worker_id": worker_id,
            "participates": True,
            "target_ref": manifest["target_ref"],
            "status_templates": status_templates,
            "status_paths": [template["status_path"] for template in status_templates],
            "result_paths": [assignment["result_root"]],
            "overall_conclusion": STATUS_IN_PROGRESS,
            "errors": list(metadata.get("errors", [])),
            "initialized_status_paths": written_paths,
            "phase": "initialized",
        }
    )
    _write_json(metadata_output_path, metadata)
    return metadata


def run_worker(
    *,
    batch_id: str,
    worker_id: str,
    source_root: Path,
    state_root: Path,
    metadata_output_path: Path,
    max_runtime_seconds: float | None = None,
) -> dict[str, Any]:
    """Process one worker assignment and write one metadata file."""
    manifest = load_manifest(batch_id, state_root=state_root)
    assignment = _assignment_for_worker(manifest, worker_id=worker_id)
    if assignment is None:
        return initialize_worker_statuses(
            batch_id=batch_id,
            worker_id=worker_id,
            state_root=state_root,
            metadata_output_path=metadata_output_path,
        )

    if metadata_output_path.exists():
        metadata = json.loads(metadata_output_path.read_text(encoding="utf-8"))
    else:
        metadata = initialize_worker_statuses(
            batch_id=batch_id,
            worker_id=worker_id,
            state_root=state_root,
            metadata_output_path=metadata_output_path,
        )
    template = metadata["status_templates"][0]
    overall_conclusion = STATUS_SUCCESS
    error_messages: list[str] = list(metadata.get("errors", []))
    result_root = state_root / assignment["result_root"]
    log_path = state_root / assignment["log_path"]
    if result_root.exists():
        shutil.rmtree(result_root)
    error_reason: str | None = None
    conclusion = STATUS_SUCCESS
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_config_path = Path(temp_dir) / f"{assignment['config_name']}.yaml"
            _build_worker_config(
                source_root=source_root,
                state_root=state_root,
                assignment=assignment,
                temp_config_path=temp_config_path,
            )
            _stage_worker_manual_filter_pass_file(
                source_root=source_root,
                assignment=assignment,
                result_root=result_root,
            )
            with _capture_root_logs_to_file(log_path), _pushd(result_root):
                exit_code = run_pipeline(
                    temp_config_path,
                    max_runtime_seconds=max_runtime_seconds,
                    prepared_metadata_path=state_root
                    / assignment["prepared_metadata_path"],
                )
            if exit_code != 0:
                raise RuntimeError(f"pipeline exited with status {exit_code}")
    except Exception as exc:  # pylint: disable=broad-exception-caught
        overall_conclusion = STATUS_FAILURE
        conclusion = STATUS_FAILURE
        error_reason = str(exc)
        error_messages.append(f"{worker_id}: {exc}")
        logging.getLogger(__name__).exception("Worker %s failed", worker_id)
    summary_payload = _write_result_summary(
        repo_root=state_root,
        assignment=assignment,
        conclusion=conclusion,
        error_reason=error_reason,
    )
    template["conclusion"] = conclusion
    template["error_reason"] = error_reason
    template["output_paths"] = [
        summary_payload["result_root"],
        summary_payload["filtered_path"],
        summary_payload["dead_path"],
        summary_payload["review_path"],
        summary_payload["audit_path"],
    ]
    metadata["status_templates"] = [template]
    metadata["status_paths"] = [
        template["status_path"] for template in metadata["status_templates"]
    ]
    metadata["result_paths"] = [assignment["result_root"]]
    metadata["overall_conclusion"] = overall_conclusion
    metadata["errors"] = error_messages
    metadata["phase"] = "processed"
    _write_json(metadata_output_path, metadata)
    return metadata


def finalize_worker_statuses(
    *,
    state_root: Path,
    metadata_path: Path,
    output_commit_sha: str,
    push_retry_count: int,
    fallback_conclusion: str | None = None,
    fallback_failure_reason: str | None = None,
    finished_at: str | None = None,
) -> list[str]:
    """Write committed worker status files after the output commit SHA is known."""
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if not metadata.get("participates"):
        return []
    finished_timestamp = finished_at or _utc_now()
    written_paths: list[str] = []
    for template in metadata["status_templates"]:
        conclusion = template["conclusion"]
        failure_reason = template["error_reason"]
        if conclusion == STATUS_IN_PROGRESS and fallback_conclusion is not None:
            conclusion = fallback_conclusion
            failure_reason = fallback_failure_reason
        status_payload = _status_payload_from_template(
            template=template,
            output_commit_sha=output_commit_sha,
            push_retry_count=push_retry_count,
            finished_at=finished_timestamp,
            conclusion=conclusion,
            failure_reason=failure_reason,
        )
        status_path = state_root / template["status_path"]
        _write_json(status_path, status_payload)
        written_paths.append(template["status_path"])
    metadata["phase"] = "finalized"
    _write_json(metadata_path, metadata)
    return written_paths


def materialize_incomplete_statuses(
    *,
    batch_id: str,
    state_root: Path,
    failure_reason: str,
    finished_at: str | None = None,
) -> dict[str, Any]:
    """Rewrite missing or in-progress worker statuses to terminal failure."""
    manifest = load_manifest(batch_id, state_root=state_root)
    written_paths: list[str] = []
    finished_timestamp = finished_at or _utc_now()
    created_at_raw = str(manifest["orchestrator"]["created_at"])
    for assignment in manifest["worker_assignments"]:
        status_path = state_root / assignment["status_path"]
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
        template = _status_template_for_worker(
            manifest=manifest,
            assignment=assignment,
            worker_id=str(assignment["worker_id"]),
        )
        if existing_payload is not None:
            started_at = existing_payload.get("timestamps", {}).get("started_at")
            if started_at is not None:
                template["started_at"] = started_at
        else:
            template["started_at"] = created_at_raw
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
        written_paths.append(assignment["status_path"])
    return {
        "batch_id": batch_id,
        "written_paths": written_paths,
        "written_count": len(written_paths),
    }


def download_worker_metadata(
    *,
    repo: str,
    run_id: str,
    token: str,
    output_path: Path,
    artifact_name: str = WORKER_METADATA_ARTIFACT_NAME,
) -> dict[str, Any]:
    """Download and extract one worker metadata artifact via the GitHub REST API."""
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    list_request = urllib.request.Request(
        (
            f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/artifacts"
            f"?name={artifact_name}"
        ),
        headers=headers,
    )
    try:
        with urllib.request.urlopen(list_request) as response:  # nosec B310
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:  # pragma: no cover
        raise RuntimeError(f"unable to list artifacts for run {run_id}: {exc}") from exc
    artifacts = payload.get("artifacts", [])
    if not artifacts:
        raise RuntimeError(
            f"no artifact named {artifact_name!r} found for run {run_id}"
        )
    artifact_id = artifacts[0]["id"]
    download_request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/actions/artifacts/{artifact_id}/zip",
        headers=headers,
    )
    with urllib.request.urlopen(download_request) as response:  # nosec B310
        archive_bytes = response.read()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temp_dir:
        archive_path = Path(temp_dir) / "artifact.zip"
        archive_path.write_bytes(archive_bytes)
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(Path(temp_dir) / "artifact")
        extracted_path = Path(temp_dir) / "artifact" / output_path.name
        if not extracted_path.exists():
            raise RuntimeError(
                f"artifact {artifact_name!r} did not contain expected file {output_path.name!r}"
            )
        shutil.copy2(extracted_path, output_path)
    return json.loads(output_path.read_text(encoding="utf-8"))


def _canonical_row_signature(row: dict[str, Any]) -> str:
    return json.dumps(row, sort_keys=True, separators=(",", ":"))


def _merge_host_txt_files(source_paths: Iterable[Path], target_path: Path) -> None:
    hosts = sorted(
        {
            line.strip()
            for source_path in source_paths
            if source_path.exists()
            for line in source_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
    )
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(
        "".join(f"{host}\n" for host in hosts),
        encoding="utf-8",
    )


def _merge_audit_files(audit_paths: Iterable[Path], target_path: Path) -> None:
    seen_rows: dict[str, dict[str, Any]] = {}
    for audit_path in audit_paths:
        if not audit_path.exists():
            continue
        for row in _sorted_dict_rows(audit_path):
            seen_rows[_canonical_row_signature(row)] = row
    ordered_rows = sorted(
        seen_rows.values(),
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
    review_rows: list[dict[str, Any]] = []
    for review_path in review_paths:
        if not review_path.exists():
            continue
        with review_path.open("r", encoding="utf-8", newline="") as handle:
            review_rows.extend(list(csv.DictReader(handle)))
    if target_path.exists():
        target_path.unlink()
    if review_rows:
        write_review_rows(target_path, review_rows)


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


def _worker_cache_paths(manifest: dict[str, Any], *, state_root: Path) -> list[Path]:
    return [
        state_root / str(assignment["cache_path"])
        for assignment in manifest["worker_assignments"]
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


def _result_summary_payloads(
    manifest: dict[str, Any], *, state_root: Path
) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for summary_path in manifest["aggregation_inputs"]["result_summary_paths"]:
        payloads.append(
            json.loads((state_root / summary_path).read_text(encoding="utf-8"))
        )
    return payloads


def _resolved_summary_output_paths(
    summaries: list[dict[str, Any]], *, state_root: Path
) -> dict[str, list[Path]]:
    """Resolve aggregate input paths from worker summary payloads."""
    return {
        "filtered": [state_root / payload["filtered_path"] for payload in summaries],
        "dead": [state_root / payload["dead_path"] for payload in summaries],
        "audit": [state_root / payload["audit_path"] for payload in summaries],
        "review": [state_root / payload["review_path"] for payload in summaries],
    }


def _resolved_final_aggregate_paths(
    manifest: dict[str, Any], *, state_root: Path
) -> dict[str, Path]:
    """Resolve final aggregate output paths from the batch manifest."""
    aggregation_inputs = manifest["aggregation_inputs"]
    return {
        "filtered": state_root / aggregation_inputs["final_filtered_path"],
        "dead": state_root / aggregation_inputs["final_dead_path"],
        "review": state_root / aggregation_inputs["final_review_path"],
        "audit": state_root / aggregation_inputs["final_audit_path"],
        "log": state_root / aggregation_inputs["final_log_path"],
        "cache": state_root / aggregation_inputs["final_cache_path"],
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
    manifest = load_manifest(batch_id, state_root=state_root)
    done_marker_path = state_root / manifest["done_marker_path"]
    if done_marker_path.exists():
        logger.info(
            "Aggregate readiness for batch %s resolved to done because %s already exists",
            batch_id,
            manifest["done_marker_path"],
        )
        return {"state": "done", "manifest": manifest}
    missing_status_paths = []
    in_progress_status_paths = []
    status_payloads = []
    for status_path in manifest["expected_status_paths"]:
        resolved_status_path = state_root / status_path
        if not resolved_status_path.exists():
            missing_status_paths.append(status_path)
            continue
        payload = json.loads(resolved_status_path.read_text(encoding="utf-8"))
        status_payloads.append(payload)
        if payload["conclusion"] == STATUS_IN_PROGRESS:
            in_progress_status_paths.append(status_path)
    if missing_status_paths or in_progress_status_paths:
        logger.debug(
            "Aggregate readiness for batch %s is not ready: missing=%s in_progress=%s",
            batch_id,
            missing_status_paths,
            in_progress_status_paths,
        )
        return {
            "state": "not_ready",
            "manifest": manifest,
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
            "manifest": manifest,
            "status_payloads": status_payloads,
        }
    logger.info(
        "Aggregate readiness for batch %s resolved to ready_success with %d statuses",
        batch_id,
        len(status_payloads),
    )
    return {
        "state": "ready_success",
        "manifest": manifest,
        "status_payloads": status_payloads,
    }


def aggregate_batch(
    *,
    batch_id: str,
    state_root: Path,
) -> dict[str, Any]:
    """Aggregate one fully completed batch into final deterministic outputs."""
    readiness = validate_aggregate_readiness(batch_id, state_root=state_root)
    manifest = readiness["manifest"]
    logger.debug(
        "Aggregate batch %s starting with readiness=%s manifest_paths=%s",
        batch_id,
        readiness["state"],
        json.dumps(
            {
                "final_filtered_path": manifest["aggregation_inputs"][
                    "final_filtered_path"
                ],
                "final_dead_path": manifest["aggregation_inputs"]["final_dead_path"],
                "final_review_path": manifest["aggregation_inputs"][
                    "final_review_path"
                ],
                "final_audit_path": manifest["aggregation_inputs"]["final_audit_path"],
                "final_log_path": manifest["aggregation_inputs"]["final_log_path"],
                "final_cache_path": manifest["aggregation_inputs"]["final_cache_path"],
                "cleanup_inputs": manifest["cleanup_inputs"],
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
            source_paths=_worker_cache_paths(manifest, state_root=state_root),
            target_path=(
                state_root / manifest["aggregation_inputs"]["final_cache_path"]
            ),
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
            "failed_status_paths": manifest["expected_status_paths"],
            "written_at": _utc_now(),
        }
        _write_json(state_root / manifest["failed_marker_path"], failure_payload)
        logger.info(
            "Aggregate marked batch %s failed and wrote %s",
            batch_id,
            manifest["failed_marker_path"],
        )
        return {
            "state": "failed",
            "manifest": manifest,
            "failed_statuses": failed_statuses,
            "cache_merge_summary": cache_merge_summary,
        }
    if readiness["state"] != "ready_success":
        return readiness
    status_payloads = readiness["status_payloads"]
    summaries = _result_summary_payloads(manifest, state_root=state_root)
    summary_output_paths = _resolved_summary_output_paths(
        summaries,
        state_root=state_root,
    )
    logger.debug(
        "Aggregate batch %s loaded %d worker summaries: %s",
        batch_id,
        len(summaries),
        json.dumps(
            [
                {
                    "worker_id": payload["worker_id"],
                    "filtered": _path_debug_summary(
                        state_root / payload["filtered_path"]
                    ),
                    "dead": _path_debug_summary(state_root / payload["dead_path"]),
                    "review": _path_debug_summary(state_root / payload["review_path"]),
                    "audit": _path_debug_summary(state_root / payload["audit_path"]),
                    "log": _path_debug_summary(state_root / payload["log_path"]),
                    "cache": _path_debug_summary(state_root / payload["cache_path"]),
                }
                for payload in summaries
            ],
            sort_keys=True,
        ),
    )

    final_output_paths = _resolved_final_aggregate_paths(
        manifest,
        state_root=state_root,
    )

    _merge_host_txt_files(
        summary_output_paths["filtered"], final_output_paths["filtered"]
    )
    _merge_host_txt_files(summary_output_paths["dead"], final_output_paths["dead"])
    _merge_audit_files(summary_output_paths["audit"], final_output_paths["audit"])
    _merge_review_files(summary_output_paths["review"], final_output_paths["review"])
    cache_merge_summary = merge_cache_files(
        source_paths=_worker_cache_paths(manifest, state_root=state_root),
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
    logger.debug(
        "Aggregate output summaries for batch %s: %s",
        batch_id,
        json.dumps(
            {
                "final_filtered": _path_debug_summary(final_output_paths["filtered"]),
                "final_dead": _path_debug_summary(final_output_paths["dead"]),
                "final_review": _path_debug_summary(final_output_paths["review"]),
                "final_audit": _path_debug_summary(final_output_paths["audit"]),
                "final_log": _path_debug_summary(final_output_paths["log"]),
                "final_cache": _path_debug_summary(final_output_paths["cache"]),
            },
            sort_keys=True,
        ),
    )

    removed_cleanup_paths: list[str] = []
    missing_cleanup_paths: list[str] = []
    for cleanup_path in manifest["cleanup_inputs"]:
        target_path = state_root / cleanup_path
        if target_path.is_dir():
            shutil.rmtree(target_path)
            removed_cleanup_paths.append(cleanup_path)
            continue
        if target_path.exists():
            target_path.unlink()
            removed_cleanup_paths.append(cleanup_path)
            continue
        missing_cleanup_paths.append(cleanup_path)
    logger.debug(
        "Aggregate cleanup for batch %s removed=%s missing=%s",
        batch_id,
        removed_cleanup_paths,
        missing_cleanup_paths,
    )

    next_turn_payload = {
        "automation_format_version": AUTOMATION_FORMAT_VERSION,
        "batch_id": batch_id,
        "target_ref": manifest["target_ref"],
        "final_filtered_path": manifest["aggregation_inputs"]["final_filtered_path"],
        "final_dead_path": manifest["aggregation_inputs"]["final_dead_path"],
        "final_review_path": manifest["aggregation_inputs"]["final_review_path"],
        "final_audit_path": manifest["aggregation_inputs"]["final_audit_path"],
        "updated_at": _utc_now(),
    }
    _write_json(
        state_root / manifest["next_turn_preparation_inputs"]["current_batch_path"],
        next_turn_payload,
    )
    logger.debug(
        "Aggregate next-turn payload for batch %s wrote %s",
        batch_id,
        manifest["next_turn_preparation_inputs"]["current_batch_path"],
    )

    summary_counts = Counter(payload["conclusion"] for payload in status_payloads)
    _merge_log_files(
        summaries=summaries,
        state_root=state_root,
        target_path=final_output_paths["log"],
    )
    logger.info(
        "Aggregate completed batch %s with summary_counts=%s",
        batch_id,
        dict(summary_counts),
    )
    manifest_text = (state_root / manifest["manifest_path"]).read_text(encoding="utf-8")
    return {
        "state": "aggregated",
        "manifest": manifest,
        "cache_merge_summary": cache_merge_summary,
        "done_marker_payload": {
            "automation_format_version": AUTOMATION_FORMAT_VERSION,
            "batch_id": batch_id,
            "manifest_sha256": _sha256_text(manifest_text),
            "summary_counts": dict(summary_counts),
            "written_at": _utc_now(),
        },
    }


def write_done_marker(
    *,
    state_root: Path,
    manifest: dict[str, Any],
    done_marker_payload: dict[str, Any],
    aggregate_commit_sha: str,
) -> str:
    """Persist the durable done marker after the aggregate commit SHA is known."""
    payload = dict(done_marker_payload)
    payload["aggregate_commit_sha"] = aggregate_commit_sha
    _write_json(state_root / manifest["done_marker_path"], payload)
    return manifest["done_marker_path"]
