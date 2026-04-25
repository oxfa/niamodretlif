"""Async staged runtime implementation."""

from __future__ import annotations

# pylint: disable=duplicate-code,too-many-lines

import asyncio
import json
import logging
import sys
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import shutil
from typing import Any

from domain_pipeline.classifications import (
    CLASSIFICATION_DNS_RESOLVED_WITHOUT_IP_ADDRESSES,
    CLASSIFICATION_DNS_RESOLVES,
    CLASSIFICATION_GEO_LOOKUP_FAILED,
    CLASSIFICATION_GEO_POLICY_REJECTED,
    CLASSIFICATION_GEO_REGION_NAME_UNAVAILABLE,
    CLASSIFICATION_INPUT_PUBLIC_SUFFIX,
    CLASSIFICATION_MANUAL_ADD_REGISTERED,
    CLASSIFICATION_MANUAL_ADD_UNAVAILABLE,
    CLASSIFICATION_MANUAL_ADD_UNREGISTERED,
    CLASSIFICATION_MANUAL_FILTER_PASSED,
    CLASSIFICATION_RDAP_LOOKUP_UNAVAILABLE_DNS_DISABLED,
    CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_REGISTERED_DNS_DISABLED,
    CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED,
    PRE_GEO_REVIEW_CLASSIFICATIONS,
    ROOT_CLASSIFICATION_RDAP_LOOKUP_UNAVAILABLE,
    ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_REGISTERED,
    ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED,
)
from ..checking import (
    CacheableRDAPUnavailableError,
    DNSResult,
    DomainChecker,
    IPGeoResult,
    RDAPResult,
    RDAPUnavailableError,
    build_geo_provider,
    evaluate_geo_policy,
)
from ..io.parser import ParsedDomainEntry
from ..io.output_manager import output_paths_for_job, review_output_path_for_job
from ..path_layout import (
    incomplete_run_debug_root,
    incomplete_run_manifest_path,
    incomplete_run_publish_snapshot_root,
)
from .async_constants import DNS_STAGE_WORKERS, GEO_STAGE_WORKERS, RDAP_STAGE_WORKERS
from .bootstrap_async import AsyncBootstrapCache
from .cache_async import start_writer_tasks, stop_writer_tasks
from .contracts import (
    CompletedHostResult,
    DNSCacheWriteRequest,
    DNSWorkItem,
    GeoCacheWriteRequest,
    GeoWorkItem,
    ParsedHostItem,
    RootCacheWriteRequest,
)
from .geo_scheduler import GeoProviderScheduler
from .logging_async import RuntimeLogTransport
from .orchestrator import build_cache_bundle, build_queue_bundle
from .pipeline_runner import (
    build_checker,
    build_source_jobs,
    dns_resolver_key,
    parse_source_entries,
    schedule_rdap_entries,
)
from .pure_helpers import (
    ROUTE_DEAD,
    ROUTE_FILTERED,
    ROUTE_REVIEW,
    build_output_row,
    classify_host_from_results,
    route_for_row,
)
from .transports import (
    AsyncDNSTransport,
    AsyncGeoTransport,
    AsyncRDAPTransport,
    resolve_geo_token,
)
from .writer import IncompleteRunWriteResult, ResultCollectorWriter, WriterResult

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class RuntimeBudget:
    """Optional soft runtime budget for one pipeline run."""

    max_runtime_seconds: float


@dataclass(frozen=True)
class BudgetStopContext:
    """Host-level context captured when the soft runtime budget stops a run."""

    source_id: str
    sequence: int
    total: int
    host: str


@dataclass(frozen=True)
class RuntimeIdentity:
    """Stable config identity used for logging and incomplete-run state."""

    config_path: Path
    config_file_name: str
    config_name: str


def _collect_output_paths(jobs: list) -> list[Path]:
    output_paths: list[Path] = []
    seen_paths: set[Path] = set()
    for job in jobs:
        for path in [
            *output_paths_for_job(job).values(),
            review_output_path_for_job(job),
        ]:
            if path in seen_paths:
                continue
            seen_paths.add(path)
            output_paths.append(path)
    return output_paths


def _clear_existing_output_paths(output_paths: list[Path]) -> None:
    """Remove previously published output artifacts before publishing a full run."""
    for path in output_paths:
        if path.is_file():
            path.unlink()


class AsyncPipelineRuntime:  # pylint: disable=too-many-instance-attributes,attribute-defined-outside-init
    """One staged async runtime instance for one workflow-owned runtime payload."""

    @classmethod
    def from_runtime_payload(
        cls,
        runtime_config: dict[str, Any],
        *,
        runtime_identity: RuntimeIdentity,
        runtime_budget: RuntimeBudget | None = None,
        prepared_metadata: dict[str, Any] | None = None,
        time_source: Callable[[], float] = time.monotonic,
    ) -> "AsyncPipelineRuntime":
        """Build one runtime from a prepared automation payload."""
        runtime = cls.__new__(cls)
        runtime._initialize(
            config=runtime_config,
            runtime_identity=runtime_identity,
            runtime_budget=runtime_budget,
            prepared_metadata_path=None,
            prepared_metadata=prepared_metadata,
            time_source=time_source,
        )
        return runtime

    def _initialize(
        self,
        *,
        config: dict[str, Any],
        runtime_identity: RuntimeIdentity,
        runtime_budget: RuntimeBudget | None,
        prepared_metadata_path: Path | None,
        prepared_metadata: dict[str, Any] | None,
        time_source: Callable[[], float],
    ) -> None:
        """Initialize one runtime from either a config path or prepared payload."""
        self.runtime_identity = runtime_identity
        self.config_path = runtime_identity.config_path
        self.config = config
        self.prepared_metadata_path = prepared_metadata_path
        self.prepared_metadata = self._load_prepared_metadata(
            prepared_metadata_path,
            prepared_metadata=prepared_metadata,
        )
        runtime_paths = self.config.get("runtime_paths", {})
        self.runtime_paths = (
            dict(runtime_paths) if isinstance(runtime_paths, dict) else {}
        )
        self.cache_path = Path(str(self.config["cache"]["cache_file"]).strip())
        baseline_cache_file = str(
            self.config["cache"].get("baseline_cache_file", "")
        ).strip()
        self.baseline_cache_path = (
            Path(baseline_cache_file) if baseline_cache_file else None
        )
        self.runtime_budget = runtime_budget
        self.time_source = time_source
        self.start_time = self.time_source()
        self.now = datetime.now(timezone.utc)
        self.queue_bundle = build_queue_bundle()
        self.cache_bundle = build_cache_bundle(
            self.cache_path,
            baseline_cache_path=self.baseline_cache_path,
        )
        self.writer = ResultCollectorWriter()
        self.geo_scheduler = GeoProviderScheduler()
        self.checkers: dict[str, DomainChecker] = {}
        self.rdap_transports: dict[str, AsyncRDAPTransport] = {}
        self.dns_transports: dict[str, AsyncDNSTransport] = {}
        self.geo_transports: dict[str, AsyncGeoTransport] = {}
        self.root_tasks: dict[str, asyncio.Task[RDAPResult]] = {}
        self.cache_stats: Counter = Counter()
        self.stopped_early = False
        self.budget_stop_context: BudgetStopContext | None = None

    def _runtime_override_path(self, key: str) -> Path | None:
        """Return one optional runtime-only path override."""
        raw_value = str(self.runtime_paths.get(key, "")).strip()
        if not raw_value:
            return None
        return Path(raw_value)

    def incomplete_manifest_path(self) -> Path:
        """Return the incomplete-run manifest path for this runtime."""
        return self._runtime_override_path(
            "incomplete_manifest_path"
        ) or incomplete_run_manifest_path(
            Path.cwd(),
            config_name=self.runtime_identity.config_name,
        )

    def incomplete_publish_snapshot_root(self) -> Path:
        """Return the incomplete-run publish-snapshot root for this runtime."""
        return self._runtime_override_path(
            "incomplete_publish_snapshot_root"
        ) or incomplete_run_publish_snapshot_root(
            Path.cwd(),
            config_name=self.runtime_identity.config_name,
        )

    def incomplete_debug_root(self) -> Path:
        """Return the incomplete-run debug root for this runtime."""
        return self._runtime_override_path(
            "incomplete_debug_root"
        ) or incomplete_run_debug_root(
            Path.cwd(),
            config_name=self.runtime_identity.config_name,
        )

    @staticmethod
    def _load_prepared_metadata(
        path: Path | None,
        *,
        prepared_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Return worker-local prepared metadata when automation supplied it."""
        if prepared_metadata is not None:
            payload = prepared_metadata
        elif path is None or not path.is_file():
            return {"sources": {}, "rdap_roots": {}, "terminal_rows": []}
        else:
            payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("prepared metadata must be a JSON object")
        sources = payload.get("sources", {})
        rdap_roots = payload.get("rdap_roots", {})
        terminal_rows = payload.get("terminal_rows", [])
        prepared_source_ids = payload.get("prepared_source_ids", None)
        if (
            not isinstance(sources, dict)
            or not isinstance(rdap_roots, dict)
            or not isinstance(terminal_rows, list)
            or (
                prepared_source_ids is not None
                and not isinstance(prepared_source_ids, list)
            )
        ):
            raise ValueError(
                "prepared metadata must contain JSON object sources, JSON object "
                "rdap_roots, JSON array terminal_rows, and optional JSON array "
                "prepared_source_ids"
            )
        log.debug(
            "Loaded prepared metadata with %d sources, %d RDAP roots, and %d terminal rows",
            len(sources),
            len(rdap_roots),
            len(terminal_rows),
        )
        return payload

    def _prepared_source_entries(self, source_id: str) -> list[dict[str, Any]] | None:
        """Return prepared entries for one source when automation supplied them."""
        source_payload = self.prepared_metadata.get("sources", {}).get(source_id)
        if source_payload is None:
            return None
        if not isinstance(source_payload, dict):
            raise ValueError(
                f"prepared metadata for source {source_id} must be a JSON object"
            )
        entries = source_payload.get("entries", [])
        if not isinstance(entries, list):
            raise ValueError(
                f"prepared metadata entries for source {source_id} must be a JSON array"
            )
        return entries

    def _prepared_root_payload(self, registrable_domain: str) -> dict[str, Any] | None:
        """Return prepared RDAP metadata for one registrable domain."""
        if not registrable_domain:
            return None
        payload = self.prepared_metadata.get("rdap_roots", {}).get(registrable_domain)
        if payload is None:
            return None
        if not isinstance(payload, dict):
            raise ValueError(
                f"prepared RDAP metadata for root {registrable_domain} must be a JSON object"
            )
        return payload

    def _prepared_terminal_rows(self) -> list[dict[str, Any]]:
        """Return preparation-owned terminal rows when shared preparation supplied them."""
        payload = self.prepared_metadata.get("terminal_rows", [])
        if not isinstance(payload, list):
            raise ValueError("prepared metadata terminal_rows must be a JSON array")
        return payload

    def _prepared_source_ids(self) -> set[str]:
        """Return all source ids whose raw inputs should be skipped by runtime parse."""
        payload = self.prepared_metadata.get("prepared_source_ids")
        if payload is None:
            return set(self.prepared_metadata.get("sources", {}))
        if not isinstance(payload, list):
            raise ValueError(
                "prepared metadata prepared_source_ids must be a JSON array"
            )
        return {str(item) for item in payload}

    def _parsed_host_from_prepared_entry(
        self,
        *,
        job,
        payload: dict[str, Any],
        sequence: int,
        total: int,
    ) -> ParsedHostItem:
        """Build one runtime parsed item from batch-prepared metadata."""
        entry = ParsedDomainEntry(
            host=str(payload["host"]),
            registrable_domain=str(payload["registrable_domain"]),
            input_name=str(payload.get("input_name", "")),
            public_suffix=str(payload.get("public_suffix", "")),
            is_public_suffix_input=bool(payload.get("is_public_suffix_input", False)),
            input_kind=str(payload.get("input_kind", "exact_host")),
            apex_scope=str(payload.get("apex_scope", "exact_only")),
            source_format=str(payload.get("source_format", "")),
        )
        root_payload = self._prepared_root_payload(entry.registrable_domain)
        return ParsedHostItem(
            job=job,
            entry=entry,
            sequence=sequence,
            total=total,
            manual_filter_pass=bool(payload.get("manual_filter_pass", False)),
            manual_add=bool(payload.get("manual_add", False)),
            source_id_override=(
                None
                if payload.get("source_id_override") is None
                else str(payload.get("source_id_override"))
            ),
            source_input_label_override=(
                None
                if payload.get("source_input_label_override") is None
                else str(payload.get("source_input_label_override"))
            ),
            source_ids=tuple(
                str(item) for item in payload.get("source_ids", [job.source_id])
            ),
            source_input_labels=tuple(
                str(item)
                for item in payload.get(
                    "source_input_labels",
                    [job.input_label],
                )
            ),
            prepared_rdap_status=(
                None if root_payload is None else str(root_payload.get("status", ""))
            )
            or None,
            prepared_authoritative_base_url=(
                None
                if root_payload is None
                else (
                    str(root_payload.get("authoritative_base_url"))
                    if root_payload.get("authoritative_base_url") is not None
                    else None
                )
            ),
        )

    async def _emit_public_suffix_guard(self, parsed: ParsedHostItem) -> None:
        """Emit one public-suffix input directly from parse stage."""
        log.debug(
            "[%s %d/%d] %s bypassed RDAP/DNS and emitted via public suffix guard",
            parsed.job.source_id,
            parsed.sequence,
            parsed.total,
            parsed.entry.host,
        )
        dns_result = DNSResult(
            host=parsed.entry.host,
            a_exists=False,
            a_nodata=False,
            a_nxdomain=False,
            a_timeout=False,
            a_servfail=False,
            canonical_name=None,
        )
        row = build_output_row(
            parsed.job,
            parsed.entry,
            CLASSIFICATION_INPUT_PUBLIC_SUFFIX,
            None,
            dns_result,
            [],
            "skipped",
            "public_suffix_guard",
            "skipped",
            "public_suffix_guard",
            None,
            dns_status_override="skipped",
            source_ids_override=list(parsed.source_ids) or None,
            source_input_labels_override=list(parsed.source_input_labels) or None,
        )
        await self.queue_bundle.result_queue.put(
            CompletedHostResult(
                job=parsed.job,
                entry=parsed.entry,
                classification=CLASSIFICATION_INPUT_PUBLIC_SUFFIX,
                route=ROUTE_REVIEW,
                row=row,
                rdap_result=None,
                dns_result=dns_result,
            )
        )

    async def _emit_manual_add_result(
        self,
        parsed: ParsedHostItem,
        rdap_result: RDAPResult | None,
    ) -> None:
        """Emit one manual-add host after RDAP, always skipping DNS and geo."""
        provenance_label = parsed.source_input_label_override or parsed.job.input_label
        if rdap_result is not None and rdap_result.exists:
            classification = CLASSIFICATION_MANUAL_ADD_REGISTERED
            route = ROUTE_FILTERED
            geo_reason = "manual_add_registered"
            geo_policy_reason = "manual_add_registered"
            log.info(
                "[%s %d/%d] %s bypassed DNS/geo via manual-add file %s "
                "(rdap=registered)",
                parsed.job.source_id,
                parsed.sequence,
                parsed.total,
                parsed.entry.host,
                provenance_label,
            )
        elif rdap_result is not None:
            classification = CLASSIFICATION_MANUAL_ADD_UNREGISTERED
            route = ROUTE_REVIEW
            geo_reason = "manual_add_unregistered"
            geo_policy_reason = "manual_add_unregistered"
            log.info(
                "[%s %d/%d] %s routed to review via manual-add file %s "
                "(rdap=unregistered)",
                parsed.job.source_id,
                parsed.sequence,
                parsed.total,
                parsed.entry.host,
                provenance_label,
            )
        else:
            classification = CLASSIFICATION_MANUAL_ADD_UNAVAILABLE
            route = ROUTE_REVIEW
            geo_reason = "manual_add_unavailable"
            geo_policy_reason = "manual_add_unavailable"
            log.info(
                "[%s %d/%d] %s routed to review via manual-add file %s "
                "(rdap=unavailable)",
                parsed.job.source_id,
                parsed.sequence,
                parsed.total,
                parsed.entry.host,
                provenance_label,
            )
        dns_result = DNSResult(
            host=parsed.entry.host,
            a_exists=False,
            a_nodata=False,
            a_nxdomain=False,
            a_timeout=False,
            a_servfail=False,
            canonical_name=None,
        )
        row = build_output_row(
            parsed.job,
            parsed.entry,
            classification,
            rdap_result,
            dns_result,
            [],
            "skipped",
            geo_reason,
            "skipped",
            geo_policy_reason,
            None,
            dns_status_override="skipped",
            source_id_override=parsed.source_id_override,
            source_input_label_override=parsed.source_input_label_override,
            source_ids_override=list(parsed.source_ids) or None,
            source_input_labels_override=list(parsed.source_input_labels) or None,
        )
        await self.queue_bundle.result_queue.put(
            CompletedHostResult(
                job=parsed.job,
                entry=parsed.entry,
                classification=classification,
                route=route,
                row=row,
                rdap_result=rdap_result,
                dns_result=dns_result,
            )
        )

    async def _emit_manual_filter_pass(
        self, parsed: ParsedHostItem, rdap_result: RDAPResult | None
    ) -> None:
        """Emit one manually approved host after RDAP, skipping DNS and geo."""
        log.info(
            "[%s %d/%d] %s bypassed DNS/geo via manual filter-pass file %s "
            "(rdap=%s)",
            parsed.job.source_id,
            parsed.sequence,
            parsed.total,
            parsed.entry.host,
            parsed.job.input_label,
            (
                "registered"
                if rdap_result is not None and rdap_result.exists
                else "unavailable"
            ),
        )
        dns_result = DNSResult(
            host=parsed.entry.host,
            a_exists=False,
            a_nodata=False,
            a_nxdomain=False,
            a_timeout=False,
            a_servfail=False,
            canonical_name=None,
        )
        row = build_output_row(
            parsed.job,
            parsed.entry,
            CLASSIFICATION_MANUAL_FILTER_PASSED,
            rdap_result,
            dns_result,
            [],
            "skipped",
            "manual_filter_pass",
            "skipped",
            "manual_filter_pass",
            None,
            dns_status_override="skipped",
            source_ids_override=list(parsed.source_ids) or None,
            source_input_labels_override=list(parsed.source_input_labels) or None,
        )
        await self.queue_bundle.result_queue.put(
            CompletedHostResult(
                job=parsed.job,
                entry=parsed.entry,
                classification=CLASSIFICATION_MANUAL_FILTER_PASSED,
                route=ROUTE_FILTERED,
                row=row,
                rdap_result=rdap_result,
                dns_result=dns_result,
            )
        )

    def _record_cache_hit(self, cache_name: str, source: str | None) -> None:
        """Increment total and source-specific cache hit counters."""
        if source is None:
            return
        self.cache_stats[f"{cache_name}_cache_hits"] += 1
        self.cache_stats[f"{cache_name}_{source}_cache_hits"] += 1

    def _record_cache_miss(self, cache_name: str) -> None:
        """Increment the cache miss counter after both layers miss."""
        self.cache_stats[f"{cache_name}_cache_misses"] += 1

    def _elapsed_runtime_seconds(self) -> float:
        """Return elapsed runtime using the injected monotonic clock."""
        return self.time_source() - self.start_time

    def _should_stop_queueing_new_work(self) -> bool:
        """Return whether the soft runtime budget has been reached."""
        if self.runtime_budget is None:
            return False
        return (
            self._elapsed_runtime_seconds() >= self.runtime_budget.max_runtime_seconds
        )

    def _record_budget_stop(
        self,
        job,
        *,
        sequence: int,
        total: int,
        host: str,
    ) -> None:
        """Log the first soft-stop request for one budgeted run."""
        if self.stopped_early:
            return
        self.stopped_early = True
        self.budget_stop_context = BudgetStopContext(
            source_id=job.source_id,
            sequence=sequence,
            total=total,
            host=host,
        )
        log.warning(
            "Soft runtime budget reached after %.1fs at source=%s entry=%d/%d "
            "host=%s; stopping new work so the workflow can commit cache progress "
            "before the GitHub Actions limit",
            self._elapsed_runtime_seconds(),
            job.source_id,
            sequence,
            total,
            host,
        )

    def checker_for(self, source_id: str, source_config: dict) -> DomainChecker:
        """Return the cached checker instance for one source id."""
        checker = self.checkers.get(source_id)
        if checker is None:
            checker = build_checker(source_config)
            self.checkers[source_id] = checker
        return checker

    def rdap_transport_for(
        self, source_id: str, source_config: dict
    ) -> AsyncRDAPTransport:
        """Return the cached RDAP transport for one source id."""
        transport = self.rdap_transports.get(source_id)
        if transport is None:
            checker = self.checker_for(source_id, source_config)
            transport = AsyncRDAPTransport(
                checker=checker, bootstrap_cache=AsyncBootstrapCache(checker)
            )
            self.rdap_transports[source_id] = transport
        return transport

    def dns_transport_for(
        self, source_id: str, source_config: dict
    ) -> AsyncDNSTransport:
        """Return the cached DNS transport for one source id."""
        transport = self.dns_transports.get(source_id)
        if transport is None:
            transport = AsyncDNSTransport(
                checker=self.checker_for(source_id, source_config)
            )
            self.dns_transports[source_id] = transport
        return transport

    def geo_transport_for(
        self, source_id: str, source_config: dict
    ) -> AsyncGeoTransport | None:
        """Return the cached geo transport for one source id when geo is enabled."""
        if not source_config["geo"]["enabled"]:
            return None
        transport = self.geo_transports.get(source_id)
        if transport is None:
            effective_provider = str(source_config["geo"]["effective_provider"])
            token = resolve_geo_token(source_config["geo"], effective_provider)
            provider = build_geo_provider(
                effective_provider,
                timeout=source_config["geo"]["timeout"],
                token=token,
            )
            transport = AsyncGeoTransport(
                provider,
                timeout=float(source_config["geo"]["timeout"]),
                token=token,
            )
            self.geo_transports[source_id] = transport
        return transport

    async def run(self) -> tuple[WriterResult, list[Path], bool]:
        """Run the staged pipeline for the loaded config."""
        jobs = build_source_jobs(
            self.config,
            prepared_source_ids=self._prepared_source_ids(),
        )
        target_output_paths = _collect_output_paths(jobs)
        writer_tasks = await start_writer_tasks(self.cache_bundle.writers)
        log_transport = RuntimeLogTransport()
        log_transport.install()
        try:
            async with asyncio.TaskGroup() as task_group:
                task_group.create_task(self._parse_stage(jobs), name="parse_stage")
                for index in range(RDAP_STAGE_WORKERS):
                    task_group.create_task(
                        self._rdap_stage(), name=f"rdap_stage_{index}"
                    )
                for index in range(DNS_STAGE_WORKERS):
                    task_group.create_task(self._dns_stage(), name=f"dns_stage_{index}")
                for index in range(GEO_STAGE_WORKERS):
                    task_group.create_task(self._geo_stage(), name=f"geo_stage_{index}")
                task_group.create_task(
                    self._result_collector(), name="result_collector"
                )
            self._ingest_prepared_terminal_rows(jobs)
            if self.stopped_early:
                return (
                    WriterResult(
                        counts=Counter(self.writer.counts),
                        output_paths=[],
                    ),
                    target_output_paths,
                    False,
                )
            _clear_existing_output_paths(target_output_paths)
            return self.writer.write(), target_output_paths, True
        finally:
            log_transport.uninstall()
            await stop_writer_tasks(self.cache_bundle.writers, writer_tasks)

    def _ingest_prepared_terminal_rows(self, jobs: list) -> None:
        """Queue shared-preparation terminal rows after stage processing completes."""
        terminal_rows = self._prepared_terminal_rows()
        if not terminal_rows:
            return
        if not jobs:
            raise ValueError(
                "prepared terminal rows require at least one configured runtime job"
            )
        anchor_job = jobs[0]
        for row in terminal_rows:
            if not isinstance(row, dict):
                raise ValueError(
                    "prepared metadata terminal_rows entries must be objects"
                )
            self.writer.add_terminal_row(job=anchor_job, row=row, route="review")

    async def _parse_stage(self, jobs: list) -> None:
        try:
            for job in jobs:
                prepared_entries = self._prepared_source_entries(job.source_id)
                if prepared_entries is None:
                    entries, _stats = parse_source_entries(job)
                    if not entries:
                        log.debug(
                            "Parse stage queued 0 entries for source=%s", job.source_id
                        )
                        continue
                    entries = schedule_rdap_entries(
                        self.checker_for(job.source_id, job.config),
                        job,
                        entries,
                    )
                    total = len(entries)
                    log.debug(
                        "Parse stage queued %d entries for source=%s after RDAP scheduling",
                        total,
                        job.source_id,
                    )
                    iterable: list[ParsedHostItem] = [
                        ParsedHostItem(
                            job=job, entry=entry, sequence=sequence, total=total
                        )
                        for sequence, entry in enumerate(entries, start=1)
                    ]
                else:
                    total = len(prepared_entries)
                    log.debug(
                        "Parse stage queued %d prepared entries for source=%s "
                        "from automation metadata",
                        total,
                        job.source_id,
                    )
                    iterable = [
                        self._parsed_host_from_prepared_entry(
                            job=job,
                            payload=entry_payload,
                            sequence=sequence,
                            total=total,
                        )
                        for sequence, entry_payload in enumerate(
                            prepared_entries,
                            start=1,
                        )
                    ]
                for parsed in iterable:
                    if self._should_stop_queueing_new_work():
                        self._record_budget_stop(
                            job,
                            sequence=parsed.sequence,
                            total=total,
                            host=parsed.entry.host,
                        )
                        break
                    if parsed.entry.is_public_suffix_input:
                        await self._emit_public_suffix_guard(parsed)
                        continue
                    await self.queue_bundle.parse_to_rdap.put(parsed)
                if self.stopped_early:
                    break
        finally:
            for _ in range(RDAP_STAGE_WORKERS):
                await self.queue_bundle.parse_to_rdap.put(None)

    async def _resolve_rdap_result(self, parsed: ParsedHostItem) -> RDAPResult | None:
        root = parsed.entry.registrable_domain
        next_stage_message = (
            "continuing to DNS"
            if parsed.job.config["dns"]["enabled"]
            else "DNS is disabled so routing directly from RDAP stage"
        )
        cached, cache_source = (
            await self.cache_bundle.reader.get_fresh_root_with_source(root, self.now)
        )
        if cached is not None:
            assert cache_source is not None
            self._record_cache_hit("rdap", cache_source)
            if (
                cached.classification
                == ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED
            ):
                log.debug(
                    "[%s %d/%d] %s RDAP root %s cache hit for root=%s "
                    "classification=%s; filtering hosts under root",
                    parsed.job.source_id,
                    parsed.sequence,
                    parsed.total,
                    parsed.entry.host,
                    cache_source,
                    root,
                    cached.classification,
                )
                return RDAPResult(False, [], from_cache=True)
            if cached.is_cached_rdap_unavailable():
                log.debug(
                    "[%s %d/%d] %s RDAP root %s cache hit for root=%s "
                    "classification=%s with cached unavailable RDAP state; "
                    "skipping live RDAP and %s",
                    parsed.job.source_id,
                    parsed.sequence,
                    parsed.total,
                    parsed.entry.host,
                    cache_source,
                    root,
                    cached.classification,
                    next_stage_message,
                )
                return None
            if cached.statuses_complete:
                log.debug(
                    "[%s %d/%d] %s RDAP root %s cache hit for root=%s "
                    "classification=%s; skipping live RDAP and %s",
                    parsed.job.source_id,
                    parsed.sequence,
                    parsed.total,
                    parsed.entry.host,
                    cache_source,
                    root,
                    cached.classification,
                    next_stage_message,
                )
                return RDAPResult(True, list(cached.statuses), from_cache=True)
            log.debug(
                "[%s %d/%d] %s RDAP root %s cache hit for root=%s "
                "classification=%s but cached statuses are incomplete; "
                "refreshing live RDAP",
                parsed.job.source_id,
                parsed.sequence,
                parsed.total,
                parsed.entry.host,
                cache_source,
                root,
                cached.classification,
            )
        else:
            self._record_cache_miss("rdap")
            log.debug(
                "[%s %d/%d] %s RDAP root cache miss for root=%s after checking "
                "overlay and baseline; performing live RDAP registrable-domain lookup",
                parsed.job.source_id,
                parsed.sequence,
                parsed.total,
                parsed.entry.host,
                root,
            )

        task = self.root_tasks.get(root)
        if task is None:
            log.debug(
                "[%s %d/%d] %s starting live RDAP task for root=%s",
                parsed.job.source_id,
                parsed.sequence,
                parsed.total,
                parsed.entry.host,
                root,
            )
            task = asyncio.create_task(
                self._live_rdap_lookup(parsed), name=f"rdap_{root}"
            )
            self.root_tasks[root] = task
        else:
            log.debug(
                "[%s %d/%d] %s joining in-flight RDAP task for root=%s",
                parsed.job.source_id,
                parsed.sequence,
                parsed.total,
                parsed.entry.host,
                root,
            )
        return await task

    async def _live_rdap_lookup(self, parsed: ParsedHostItem) -> RDAPResult:
        transport = self.rdap_transport_for(parsed.job.source_id, parsed.job.config)
        if parsed.prepared_authoritative_base_url is not None:
            log.debug(
                "[%s %d/%d] %s using precomputed authoritative RDAP base URL %s for root=%s",
                parsed.job.source_id,
                parsed.sequence,
                parsed.total,
                parsed.entry.host,
                parsed.prepared_authoritative_base_url,
                parsed.entry.registrable_domain,
            )
        try:
            rdap_result = await transport.lookup(
                parsed.entry.registrable_domain,
                authoritative_base_url=parsed.prepared_authoritative_base_url,
            )
        except CacheableRDAPUnavailableError:
            ttl_days = int(
                self.config["cache"]["classification_ttl_days"][
                    "rdap_lookup_unavailable"
                ]
            )
            await self.cache_bundle.writers[0].queue.put(
                RootCacheWriteRequest(
                    domain=parsed.entry.registrable_domain,
                    classification=ROOT_CLASSIFICATION_RDAP_LOOKUP_UNAVAILABLE,
                    statuses=[],
                    statuses_complete=False,
                    checked_at=self.now,
                    ttl_days=ttl_days,
                )
            )
            self.cache_stats["cached_written"] += 1
            log.debug(
                "[%s %d/%d] %s queued RDAP unavailable cache write for root=%s ttl_days=%d",
                parsed.job.source_id,
                parsed.sequence,
                parsed.total,
                parsed.entry.host,
                parsed.entry.registrable_domain,
                ttl_days,
            )
            raise
        log.debug(
            "[%s %d/%d] %s live RDAP result for root=%s -> exists=%s statuses=%s",
            parsed.job.source_id,
            parsed.sequence,
            parsed.total,
            parsed.entry.host,
            parsed.entry.registrable_domain,
            rdap_result.exists,
            list(rdap_result.statuses) or "(none)",
        )
        await self.cache_bundle.writers[0].queue.put(
            RootCacheWriteRequest(
                domain=parsed.entry.registrable_domain,
                classification=(
                    ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_REGISTERED
                    if rdap_result.exists
                    else ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED
                ),
                statuses=list(rdap_result.statuses),
                statuses_complete=True,
                checked_at=self.now,
                ttl_days=(
                    int(
                        self.config["cache"]["classification_ttl_days"][
                            "rdap_registrable_domain_registered"
                        ]
                    )
                    if rdap_result.exists
                    else int(
                        self.config["cache"]["classification_ttl_days"][
                            "rdap_registrable_domain_unregistered"
                        ]
                    )
                ),
            )
        )
        self.cache_stats["cached_written"] += 1
        log.debug(
            "[%s %d/%d] %s queued RDAP root cache write for root=%s ttl_days=%d",
            parsed.job.source_id,
            parsed.sequence,
            parsed.total,
            parsed.entry.host,
            parsed.entry.registrable_domain,
            (
                int(
                    self.config["cache"]["classification_ttl_days"][
                        "rdap_registrable_domain_registered"
                    ]
                )
                if rdap_result.exists
                else int(
                    self.config["cache"]["classification_ttl_days"][
                        "rdap_registrable_domain_unregistered"
                    ]
                )
            ),
        )
        return rdap_result

    async def _rdap_stage(self) -> None:
        while True:
            parsed = await self.queue_bundle.parse_to_rdap.get()
            try:
                if parsed is None:
                    await self.queue_bundle.rdap_to_dns.put(None)
                    return
                if parsed.prepared_rdap_status == "unavailable":
                    if parsed.job.config["dns"]["enabled"]:
                        log.debug(
                            "[%s %d/%d] %s bypassing RDAP for root=%s because "
                            "batch preparation marked the authoritative server "
                            "unavailable; continuing to DNS",
                            parsed.job.source_id,
                            parsed.sequence,
                            parsed.total,
                            parsed.entry.host,
                            parsed.entry.registrable_domain,
                        )
                    else:
                        log.debug(
                            "[%s %d/%d] %s bypassing RDAP for root=%s because "
                            "batch preparation marked the authoritative server "
                            "unavailable; DNS is disabled so routing directly "
                            "from RDAP stage",
                            parsed.job.source_id,
                            parsed.sequence,
                            parsed.total,
                            parsed.entry.host,
                            parsed.entry.registrable_domain,
                        )
                    rdap_result = None
                else:
                    try:
                        rdap_result = await self._resolve_rdap_result(parsed)
                    except RDAPUnavailableError:
                        if parsed.job.config["dns"]["enabled"]:
                            log.debug(
                                "[%s %d/%d] %s RDAP unavailable for root=%s; continuing to DNS",
                                parsed.job.source_id,
                                parsed.sequence,
                                parsed.total,
                                parsed.entry.host,
                                parsed.entry.registrable_domain,
                            )
                        else:
                            log.debug(
                                "[%s %d/%d] %s RDAP unavailable for root=%s; DNS is "
                                "disabled so routing directly from RDAP stage",
                                parsed.job.source_id,
                                parsed.sequence,
                                parsed.total,
                                parsed.entry.host,
                                parsed.entry.registrable_domain,
                            )
                        rdap_result = None
                if parsed.manual_add:
                    await self._emit_manual_add_result(parsed, rdap_result)
                    continue
                if rdap_result is not None and not rdap_result.exists:
                    log.debug(
                        "[%s %d/%d] %s filtered before DNS because registrable_domain=%s "
                        "is RDAP-unregistered (rdap_source=%s)",
                        parsed.job.source_id,
                        parsed.sequence,
                        parsed.total,
                        parsed.entry.host,
                        parsed.entry.registrable_domain,
                        "cache" if rdap_result.from_cache else "live",
                    )
                    dns_result = DNSResult(
                        host=parsed.entry.host,
                        a_exists=False,
                        a_nodata=False,
                        a_nxdomain=True,
                        a_timeout=False,
                        a_servfail=False,
                        canonical_name=None,
                    )
                    row = build_output_row(
                        parsed.job,
                        parsed.entry,
                        CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED,
                        rdap_result,
                        dns_result,
                        [],
                        "skipped",
                        "dead_root",
                        "skipped",
                        "dead_root",
                        None,
                        dns_status_override="skipped",
                        source_ids_override=list(parsed.source_ids) or None,
                        source_input_labels_override=list(parsed.source_input_labels)
                        or None,
                    )
                    await self.queue_bundle.result_queue.put(
                        CompletedHostResult(
                            job=parsed.job,
                            entry=parsed.entry,
                            classification=CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED,
                            route=ROUTE_DEAD,
                            row=row,
                            rdap_result=rdap_result,
                            dns_result=dns_result,
                        )
                    )
                    continue
                if parsed.manual_filter_pass:
                    await self._emit_manual_filter_pass(parsed, rdap_result)
                    continue
                if not parsed.job.config["dns"]["enabled"]:
                    log.debug(
                        "[%s %d/%d] %s bypassed DNS and geo because dns.enabled=false; "
                        "routing directly from RDAP stage",
                        parsed.job.source_id,
                        parsed.sequence,
                        parsed.total,
                        parsed.entry.host,
                    )
                    dns_result = DNSResult(
                        host=parsed.entry.host,
                        a_exists=False,
                        a_nodata=False,
                        a_nxdomain=False,
                        a_timeout=False,
                        a_servfail=False,
                        canonical_name=None,
                    )
                    row = build_output_row(
                        parsed.job,
                        parsed.entry,
                        (
                            CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_REGISTERED_DNS_DISABLED
                            if rdap_result is not None
                            else CLASSIFICATION_RDAP_LOOKUP_UNAVAILABLE_DNS_DISABLED
                        ),
                        rdap_result,
                        dns_result,
                        [],
                        "skipped",
                        "dns_disabled",
                        "skipped",
                        "dns_disabled",
                        None,
                        dns_status_override="skipped",
                        source_ids_override=list(parsed.source_ids) or None,
                        source_input_labels_override=list(parsed.source_input_labels)
                        or None,
                    )
                    await self.queue_bundle.result_queue.put(
                        CompletedHostResult(
                            job=parsed.job,
                            entry=parsed.entry,
                            classification=(
                                CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_REGISTERED_DNS_DISABLED
                                if rdap_result is not None
                                else CLASSIFICATION_RDAP_LOOKUP_UNAVAILABLE_DNS_DISABLED
                            ),
                            route=(
                                ROUTE_FILTERED
                                if rdap_result is not None
                                else ROUTE_REVIEW
                            ),
                            row=row,
                            rdap_result=rdap_result,
                            dns_result=dns_result,
                        )
                    )
                    continue
                await self.queue_bundle.rdap_to_dns.put(
                    DNSWorkItem(parsed=parsed, rdap_result=rdap_result)
                )
            finally:
                self.queue_bundle.parse_to_rdap.task_done()

    async def _dns_stage(self) -> None:
        while True:
            work_item = await self.queue_bundle.rdap_to_dns.get()
            try:
                if work_item is None:
                    await self.queue_bundle.dns_to_geo.put(None)
                    return
                parsed = work_item.parsed
                resolver_key = dns_resolver_key(parsed.job.config["dns"])
                cached, cache_source = (
                    await self.cache_bundle.reader.get_fresh_dns_with_source(
                        parsed.entry.host, resolver_key, self.now
                    )
                )
                if cached is not None:
                    assert cache_source is not None
                    self._record_cache_hit("dns", cache_source)
                    dns_result = DNSResult(
                        host=cached.host,
                        a_exists=cached.a_exists,
                        a_nodata=cached.a_nodata,
                        a_nxdomain=cached.a_nxdomain,
                        a_timeout=cached.a_timeout,
                        a_servfail=cached.a_servfail,
                        canonical_name=cached.canonical_name or None,
                        ipv4_addresses=list(cached.ipv4_addresses),
                        ipv6_addresses=list(cached.ipv6_addresses),
                    )
                    log.debug(
                        "[%s %d/%d] %s DNS %s cache hit for resolver=%s "
                        "-> status=%s cname=%s ips=%s",
                        parsed.job.source_id,
                        parsed.sequence,
                        parsed.total,
                        parsed.entry.host,
                        cache_source,
                        resolver_key,
                        dns_result.status,
                        dns_result.canonical_name or "(none)",
                        dns_result.resolved_ips or "(none)",
                    )
                else:
                    self._record_cache_miss("dns")
                    log.debug(
                        "[%s %d/%d] %s DNS cache miss for resolver=%s after checking "
                        "overlay and baseline",
                        parsed.job.source_id,
                        parsed.sequence,
                        parsed.total,
                        parsed.entry.host,
                        resolver_key,
                    )
                    dns_result = await self.dns_transport_for(
                        parsed.job.source_id, parsed.job.config
                    ).lookup(parsed.entry.host)
                    await self.cache_bundle.writers[1].queue.put(
                        DNSCacheWriteRequest(
                            host=parsed.entry.host,
                            resolver_key=resolver_key,
                            a_exists=dns_result.a_exists,
                            a_nodata=dns_result.a_nodata,
                            a_nxdomain=dns_result.a_nxdomain,
                            a_timeout=dns_result.a_timeout,
                            a_servfail=dns_result.a_servfail,
                            canonical_name=dns_result.canonical_name or "",
                            ipv4_addresses=list(dns_result.ipv4_addresses),
                            ipv6_addresses=list(dns_result.ipv6_addresses),
                            checked_at=self.now,
                            ttl_days=int(self.config["cache"]["dns_ttl_days"]),
                        )
                    )
                    self.cache_stats["cached_written"] += 1
                    log.debug(
                        "[%s %d/%d] %s queued DNS cache write for resolver=%s "
                        "ttl_days=%d status=%s",
                        parsed.job.source_id,
                        parsed.sequence,
                        parsed.total,
                        parsed.entry.host,
                        resolver_key,
                        int(self.config["cache"]["dns_ttl_days"]),
                        dns_result.status,
                    )
                checker = self.checker_for(parsed.job.source_id, parsed.job.config)
                classification = classify_host_from_results(
                    parsed.entry.host,
                    parsed.entry.registrable_domain,
                    work_item.rdap_result,
                    dns_result,
                    hold_statuses=set(getattr(checker, "HOLD_STATUSES", set())),
                    deletion_statuses=set(getattr(checker, "DELETION_STATUSES", set())),
                )
                log.debug(
                    "[%s %d/%d] %s -> %s (root=%s, dns=%s, rdap_statuses=%s)",
                    parsed.job.source_id,
                    parsed.sequence,
                    parsed.total,
                    parsed.entry.host,
                    classification,
                    parsed.entry.registrable_domain,
                    dns_result.status,
                    (
                        "|".join(work_item.rdap_result.statuses)
                        if work_item.rdap_result is not None
                        else "(none)"
                    ),
                )
                if not dns_result.resolved_ips:
                    if classification == CLASSIFICATION_DNS_RESOLVES:
                        classification = (
                            CLASSIFICATION_DNS_RESOLVED_WITHOUT_IP_ADDRESSES
                        )
                    log.debug(
                        "[%s %d/%d] %s produced no resolved IPs; routing directly from DNS stage",
                        parsed.job.source_id,
                        parsed.sequence,
                        parsed.total,
                        parsed.entry.host,
                    )
                    row = build_output_row(
                        parsed.job,
                        parsed.entry,
                        classification,
                        work_item.rdap_result,
                        dns_result,
                        [],
                        "skipped",
                        "no_resolved_ips",
                        "skipped",
                        "no_resolved_ips",
                        None,
                        source_ids_override=list(parsed.source_ids) or None,
                        source_input_labels_override=list(parsed.source_input_labels)
                        or None,
                    )
                    await self.queue_bundle.result_queue.put(
                        CompletedHostResult(
                            job=parsed.job,
                            entry=parsed.entry,
                            classification=classification,
                            route=route_for_row(
                                classification, "skipped", "no_resolved_ips"
                            ),
                            row=row,
                            rdap_result=work_item.rdap_result,
                            dns_result=dns_result,
                        )
                    )
                    continue
                await self.queue_bundle.dns_to_geo.put(
                    GeoWorkItem(
                        parsed=parsed,
                        rdap_result=work_item.rdap_result,
                        dns_result=dns_result,
                        classification=classification,
                    )
                )
            finally:
                self.queue_bundle.rdap_to_dns.task_done()

    async def _lookup_geo(self, work_item: GeoWorkItem):
        parsed = work_item.parsed
        if work_item.classification in PRE_GEO_REVIEW_CLASSIFICATIONS:
            return (
                None,
                [],
                [],
                "skipped",
                "classification_precludes_geo_lookup",
                "skipped",
                "classification_precludes_geo_lookup",
                None,
            )
        if not parsed.job.config["geo"]["enabled"]:
            return (
                None,
                [],
                [],
                "skipped",
                "geo_disabled",
                "skipped",
                "geo_disabled",
                None,
            )
        if not work_item.dns_result.resolved_ips:
            return (
                None,
                [],
                [],
                "skipped",
                "no_resolved_ips",
                "skipped",
                "no_resolved_ips",
                None,
            )
        geo_transport = self.geo_transport_for(parsed.job.source_id, parsed.job.config)
        if geo_transport is None:
            return (
                None,
                [],
                [],
                "skipped",
                "geo_disabled",
                "skipped",
                "geo_disabled",
                None,
            )

        provider_name = str(parsed.job.config["geo"]["effective_provider"])
        # Runtime transport owns provider construction; this call retrieves the
        # already-selected provider instance for logging and result annotation.
        # pylint: disable-next=protected-access
        provider_used = geo_transport._provider(provider_name)
        log.debug(
            "[%s %d/%d] %s geo evaluation using provider=%s resolved_ips=%s",
            parsed.job.source_id,
            parsed.sequence,
            parsed.total,
            parsed.entry.host,
            provider_name,
            work_item.dns_result.resolved_ips or "(none)",
        )
        resolved_ips = list(work_item.dns_result.resolved_ips)
        geo_results: list[IPGeoResult | None] = [None] * len(resolved_ips)
        missing_indices: list[int] = []
        missing_ips: list[str] = []
        for index, ip in enumerate(resolved_ips):
            cached, cache_source = (
                await self.cache_bundle.reader.get_fresh_geo_with_source(
                    provider_name, ip, self.now
                )
            )
            if cached is not None:
                assert cache_source is not None
                self._record_cache_hit("geo", cache_source)
                geo_results[index] = IPGeoResult(
                    ip=ip,
                    provider=provider_name,
                    country_code=cached.country_code,
                    region_code=cached.region_code,
                    region_name=cached.region_name,
                    status="cache_hit",
                )
                log.debug(
                    "[%s %d/%d] %s geo %s cache hit for provider=%s ip=%s "
                    "-> country=%s region_code=%s region_name=%s",
                    parsed.job.source_id,
                    parsed.sequence,
                    parsed.total,
                    parsed.entry.host,
                    cache_source,
                    provider_name,
                    ip,
                    cached.country_code or "(none)",
                    cached.region_code or "(none)",
                    cached.region_name or "(none)",
                )
                continue
            self._record_cache_miss("geo")
            log.debug(
                "[%s %d/%d] %s geo cache miss for provider=%s ip=%s after checking "
                "overlay and baseline",
                parsed.job.source_id,
                parsed.sequence,
                parsed.total,
                parsed.entry.host,
                provider_name,
                ip,
            )
            missing_indices.append(index)
            missing_ips.append(ip)

        if provider_name in {"geojs", "ipinfo_lite"}:
            looked_up_results = await geo_transport.lookup_ips(
                provider_name, missing_ips
            )
        else:
            looked_up_results = [
                await geo_transport.lookup_ip(provider_name, ip) for ip in missing_ips
            ]
        if len(looked_up_results) != len(missing_ips):
            raise ValueError(
                f"{provider_name} returned {len(looked_up_results)} geo results "
                f"for {len(missing_ips)} requested IPs"
            )
        for index, result in zip(missing_indices, looked_up_results):
            ip = resolved_ips[index]
            geo_results[index] = result
            log.debug(
                "[%s %d/%d] %s geo lookup result for provider=%s ip=%s "
                "-> status=%s country=%s region_code=%s region_name=%s",
                parsed.job.source_id,
                parsed.sequence,
                parsed.total,
                parsed.entry.host,
                provider_name,
                ip,
                result.status,
                result.country_code or "(none)",
                result.region_code or "(none)",
                result.region_name or "(none)",
            )
            if result.usable:
                await self.cache_bundle.writers[2].queue.put(
                    GeoCacheWriteRequest(
                        provider=provider_name,
                        ip=ip,
                        country_code=result.country_code,
                        region_code=result.region_code,
                        region_name=result.region_name,
                        checked_at=self.now,
                        ttl_days=int(parsed.job.config["geo"]["cache_ttl_days"]),
                    )
                )
                self.cache_stats["cached_written"] += 1
                log.debug(
                    "[%s %d/%d] %s queued geo cache write for provider=%s ip=%s ttl_days=%d",
                    parsed.job.source_id,
                    parsed.sequence,
                    parsed.total,
                    parsed.entry.host,
                    provider_name,
                    ip,
                    int(parsed.job.config["geo"]["cache_ttl_days"]),
                )
        resolved_geo_results = [result for result in geo_results if result is not None]

        attempts = [
            {
                "provider": provider_name,
                "statuses": {
                    result.ip: result.status for result in resolved_geo_results
                },
            }
        ]
        if not any(result.usable for result in resolved_geo_results):
            return (
                provider_used,
                resolved_geo_results,
                attempts,
                "review",
                "geo_lookup_failed",
                "skipped",
                "geo_lookup_failed",
                None,
            )

        policy = parsed.job.config["geo"]["policy"]
        if parsed.job.config["geo"]["requires_region_lookup"] and not any(
            result.region_name.strip()
            for result in resolved_geo_results
            if result.usable
        ):
            return (
                provider_used,
                resolved_geo_results,
                attempts,
                "review",
                "region_name_unavailable",
                "skipped",
                "region_name_unavailable",
                None,
            )
        has_rules = (
            any(policy["include"]["countries"])
            or any(policy["include"]["regions"])
            or any(policy["exclude"]["countries"])
            or any(policy["exclude"]["regions"])
        )
        if not policy["enabled"]:
            return (
                provider_used,
                resolved_geo_results,
                attempts,
                "ok",
                "lookup_succeeded",
                "skipped",
                "policy_disabled",
                None,
            )
        if not has_rules:
            return (
                provider_used,
                resolved_geo_results,
                attempts,
                "ok",
                "lookup_succeeded",
                "skipped",
                "policy_has_no_rules",
                None,
            )
        decision = evaluate_geo_policy(resolved_geo_results, policy)
        return (
            provider_used,
            resolved_geo_results,
            attempts,
            "ok",
            "lookup_succeeded",
            decision.status,
            decision.reason,
            decision,
        )

    async def _geo_stage(self) -> None:
        while True:
            work_item = await self.queue_bundle.dns_to_geo.get()
            try:
                if work_item is None:
                    await self.queue_bundle.result_queue.put(None)
                    return
                (
                    provider_used,
                    geo_results,
                    geo_attempts,
                    geo_status,
                    geo_reason,
                    geo_policy_status,
                    geo_policy_reason,
                    decision,
                ) = await self._lookup_geo(work_item)
                classification = work_item.classification
                if geo_status == "review":
                    if geo_reason == "geo_lookup_failed":
                        classification = CLASSIFICATION_GEO_LOOKUP_FAILED
                    elif geo_reason == "region_name_unavailable":
                        classification = CLASSIFICATION_GEO_REGION_NAME_UNAVAILABLE
                if geo_policy_status == "rejected":
                    classification = CLASSIFICATION_GEO_POLICY_REJECTED
                matched_ips = decision.matched_ips if decision is not None else []
                rejected_ips = decision.rejected_ips if decision is not None else []
                log.debug(
                    "[%s %d/%d] %s geo -> %s/%s "
                    "(lookup_reason=%s, policy_reason=%s, provider=%s, ips=%s, "
                    "matched=%s, rejected=%s, cache_hits=%d, cache_misses=%d)",
                    work_item.parsed.job.source_id,
                    work_item.parsed.sequence,
                    work_item.parsed.total,
                    work_item.parsed.entry.host,
                    geo_status,
                    geo_reason,
                    geo_policy_status,
                    geo_policy_reason,
                    provider_used.provider_name if provider_used is not None else "",
                    [result.ip for result in geo_results] or "(none)",
                    matched_ips,
                    rejected_ips,
                    sum(1 for result in geo_results if result.status == "cache_hit"),
                    sum(1 for result in geo_results if result.status != "cache_hit"),
                )
                row = build_output_row(
                    work_item.parsed.job,
                    work_item.parsed.entry,
                    classification,
                    work_item.rdap_result,
                    work_item.dns_result,
                    geo_results,
                    geo_status,
                    geo_reason,
                    geo_policy_status,
                    geo_policy_reason,
                    provider_used,
                    source_ids_override=list(work_item.parsed.source_ids) or None,
                    source_input_labels_override=list(
                        work_item.parsed.source_input_labels
                    )
                    or None,
                )
                if (
                    classification
                    in {
                        CLASSIFICATION_GEO_LOOKUP_FAILED,
                        CLASSIFICATION_GEO_REGION_NAME_UNAVAILABLE,
                    }
                    and geo_attempts
                ):
                    row["geo_attempts"] = geo_attempts
                await self.queue_bundle.result_queue.put(
                    CompletedHostResult(
                        job=work_item.parsed.job,
                        entry=work_item.parsed.entry,
                        classification=classification,
                        route=route_for_row(
                            classification, geo_policy_status, geo_reason
                        ),
                        row=row,
                        rdap_result=work_item.rdap_result,
                        dns_result=work_item.dns_result,
                        geo_results=geo_results,
                        geo_attempts=geo_attempts,
                        geo_policy=decision,
                    )
                )
            finally:
                self.queue_bundle.dns_to_geo.task_done()

    async def _result_collector(self) -> None:
        sentinels_seen = 0
        while True:
            result = await self.queue_bundle.result_queue.get()
            try:
                if result is None:
                    sentinels_seen += 1
                    if sentinels_seen >= GEO_STAGE_WORKERS:
                        return
                    continue
                self.writer.add(result)
            finally:
                self.queue_bundle.result_queue.task_done()


def _log_run_summary(
    elapsed: float,
    writer_result: WriterResult,
    cache_stats: Counter,
    cache_file: Path,
    output_paths: list[Path],
) -> None:
    log.info("========================================")
    log.info("Pipeline complete in %.1fs", elapsed)
    if cache_file.is_file():
        log.info("  Cache file: %s (%d bytes)", cache_file, cache_file.stat().st_size)
    for output_path in output_paths:
        if not output_path.is_file():
            continue
        with output_path.open("r", encoding="utf-8") as handle:
            line_count = sum(1 for _ in handle)
        log.info(
            "  Output file: %s (%d lines, %d bytes)",
            output_path,
            line_count,
            output_path.stat().st_size,
        )
    emitted_hosts = writer_result.counts.get("route_filtered", 0)
    review_hosts = writer_result.counts.get("route_review", 0)
    dead_hosts = writer_result.counts.get("route_dead", 0)
    log.info("  Total input hosts: %d", emitted_hosts + review_hosts + dead_hosts)
    log.info("  Hosts emitted to filtered output: %d", emitted_hosts)
    log.info("  Hosts routed to review: %d", review_hosts)
    log.info(
        "  Hosts written to output/dead after RDAP-unregistered verdict: %d",
        dead_hosts,
    )
    log.info("  Cache writes: %d", cache_stats.get("cached_written", 0))
    log.info("  Cache refreshes: %d", cache_stats.get("cached_refreshed", 0))
    log.info("  Cache clears: %d", cache_stats.get("cache_cleared", 0))
    log.info("  RDAP cache hits: %d", cache_stats.get("rdap_cache_hits", 0))
    log.info("  RDAP cache misses: %d", cache_stats.get("rdap_cache_misses", 0))
    log.info(
        "  RDAP overlay cache hits: %d",
        cache_stats.get("rdap_overlay_cache_hits", 0),
    )
    log.info(
        "  RDAP baseline cache hits: %d",
        cache_stats.get("rdap_baseline_cache_hits", 0),
    )
    log.info("  DNS cache hits: %d", cache_stats.get("dns_cache_hits", 0))
    log.info("  DNS cache misses: %d", cache_stats.get("dns_cache_misses", 0))
    log.info(
        "  DNS overlay cache hits: %d",
        cache_stats.get("dns_overlay_cache_hits", 0),
    )
    log.info(
        "  DNS baseline cache hits: %d",
        cache_stats.get("dns_baseline_cache_hits", 0),
    )
    log.info("  Geo cache hits: %d", cache_stats.get("geo_cache_hits", 0))
    log.info("  Geo cache misses: %d", cache_stats.get("geo_cache_misses", 0))
    log.info(
        "  Geo overlay cache hits: %d",
        cache_stats.get("geo_overlay_cache_hits", 0),
    )
    log.info(
        "  Geo baseline cache hits: %d",
        cache_stats.get("geo_baseline_cache_hits", 0),
    )


def _path_display(path: Path) -> str:
    """Render one path relative to cwd when possible."""
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def _clear_incomplete_run_state(runtime: AsyncPipelineRuntime) -> None:
    """Remove stale incomplete-run state after a successful full publish."""
    state_root = runtime.incomplete_manifest_path().parent
    debug_root = runtime.incomplete_debug_root()
    if state_root.is_dir():
        shutil.rmtree(state_root)
    if debug_root.is_dir():
        shutil.rmtree(debug_root)


def _write_incomplete_run_state(
    runtime: AsyncPipelineRuntime,
    elapsed: float,
    writer_result: WriterResult,
    output_paths: list[Path],
) -> Path:
    """Persist incomplete-run artifacts and one manifest for workflow commits."""
    manifest_path = runtime.incomplete_manifest_path()
    state_root = manifest_path.parent
    publish_snapshot_root = runtime.incomplete_publish_snapshot_root()
    debug_root = runtime.incomplete_debug_root()
    incomplete_writer_result: IncompleteRunWriteResult = (
        runtime.writer.write_incomplete_run(
            publish_root=publish_snapshot_root,
            debug_root=debug_root,
        )
    )
    stop_context = runtime.budget_stop_context
    published_branch_paths = [
        _path_display(path) for path in output_paths if path.parts[:1] == ("output",)
    ]
    state_artifact_paths = [
        _path_display(manifest_path),
        *[_path_display(path) for path in incomplete_writer_result.state_paths],
    ]
    debug_artifact_paths = [
        _path_display(path) for path in incomplete_writer_result.debug_paths
    ]
    payload: dict[str, Any] = {
        "status": "incomplete",
        "reason": "max_runtime_seconds_reached",
        "config_path": str(runtime.runtime_identity.config_path),
        "config_file_name": runtime.runtime_identity.config_file_name,
        "config_name": runtime.runtime_identity.config_name,
        "cache_file": str(runtime.cache_path),
        "stopped_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": elapsed,
        "max_runtime_seconds": (
            runtime.runtime_budget.max_runtime_seconds
            if runtime.runtime_budget is not None
            else None
        ),
        "published_outputs_kept": True,
        "published_branch_paths": published_branch_paths,
        "state_artifact_paths": state_artifact_paths,
        "debug_artifact_paths": debug_artifact_paths,
        "counts": dict(writer_result.counts),
        "cache_stats": dict(runtime.cache_stats),
    }
    if stop_context is not None:
        payload["stop_context"] = {
            "source_id": stop_context.source_id,
            "sequence": stop_context.sequence,
            "total": stop_context.total,
            "host": stop_context.host,
        }
    state_root.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest_path


async def run_prepared_pipeline_async(
    runtime_config: dict[str, Any],
    *,
    runtime_identity: dict[str, str],
    max_runtime_seconds: float | None = None,
    prepared_metadata: dict[str, Any] | None = None,
) -> int:
    """Run the async pipeline from one prepared automation payload without YAML reload."""
    start_time = time.monotonic()
    runtime_budget = (
        RuntimeBudget(max_runtime_seconds=max_runtime_seconds)
        if max_runtime_seconds is not None
        else None
    )
    config_identity = RuntimeIdentity(
        config_path=Path(runtime_identity["config_path"]),
        config_file_name=runtime_identity["config_file_name"],
        config_name=runtime_identity["config_name"],
    )
    runtime = AsyncPipelineRuntime.from_runtime_payload(
        runtime_config,
        runtime_identity=config_identity,
        runtime_budget=runtime_budget,
        prepared_metadata=prepared_metadata,
    )
    log.info("========================================")
    log.info("Pipeline start")
    log.info("  Config path: %s", runtime.runtime_identity.config_path)
    log.info("  Config file: %s", runtime.runtime_identity.config_file_name)
    log.info("  Config name: %s", runtime.runtime_identity.config_name)
    log.info("  Python: %s", sys.version.split()[0])
    log.info("  Working dir: %s", Path.cwd())
    log.info("  Cache file: %s", runtime.cache_path)
    log.info("  Sources configured: %d", len(runtime.config["sources"]))
    if runtime_budget is not None:
        log.info("  Soft runtime budget: %.1fs", runtime_budget.max_runtime_seconds)
    log.info("========================================")
    writer_result, output_paths, outputs_published = await runtime.run()
    elapsed = time.monotonic() - start_time
    if not outputs_published:
        manifest_path = _write_incomplete_run_state(
            runtime,
            elapsed,
            writer_result,
            output_paths,
        )
        log.warning(
            "Soft runtime budget stop after %.1fs; leaving previously published "
            "outputs unchanged for this run and writing incomplete-run state to %s",
            elapsed,
            manifest_path,
        )
    else:
        _clear_incomplete_run_state(runtime)
    _log_run_summary(
        elapsed,
        writer_result,
        runtime.cache_stats,
        runtime.cache_path,
        output_paths if outputs_published else [],
    )
    return 0
