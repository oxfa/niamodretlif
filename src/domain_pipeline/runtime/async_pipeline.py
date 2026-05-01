"""Worker-local async DNS actionability runtime."""

from __future__ import annotations

import asyncio
import logging
import os
from collections import Counter
from pathlib import Path
from typing import Any

from domain_pipeline.checking import (
    DelegationResult,
    GEO_STATUS_CACHE_HIT,
    HostResolutionResult,
    IPGeoResult,
    build_geo_provider,
    evaluate_geo_policy,
)
from domain_pipeline.classifications import (
    CLASSIFICATION_GEO_LOOKUP_FAILED,
    CLASSIFICATION_INPUT_PUBLIC_SUFFIX,
    CLASSIFICATION_MANUAL_ADD_ACTIONABLE,
    CLASSIFICATION_MANUAL_FILTER_PASSED,
)
from domain_pipeline.io.parser import DomainListParser, ParsedDomainEntry
from domain_pipeline.runtime.cache_async import CacheHitSource
from domain_pipeline.runtime.contracts import (
    CompletedHostResult,
    DelegationCacheWriteRequest,
    GeoCacheWriteRequest,
    GeoWorkItem,
    HostResolutionCacheWriteRequest,
    HostResolutionWorkItem,
    ParsedHostItem,
)
from domain_pipeline.runtime.history import PipelineCache, utc_now
from domain_pipeline.runtime.orchestrator import (
    CacheBundle,
    QueueBundle,
    build_cache_bundle,
    build_queue_bundle,
)
from domain_pipeline.runtime.pipeline_runner import build_checker, build_source_jobs
from domain_pipeline.runtime.pure_helpers import (
    build_base_row,
    classify_delegation,
    classify_host_resolution,
    geo_policy_classification,
    host_resolution_skipped_classification,
    route_for_classification,
)
from domain_pipeline.runtime.transports import (
    AsyncDelegationTransport,
    AsyncGeoTransport,
    AsyncHostResolutionTransport,
)
from domain_pipeline.runtime.writer import ResultCollectorWriter
from domain_pipeline.shared import SourceJob
from .async_constants import (
    DELEGATION_STAGE_WORKERS,
    GEO_STAGE_WORKERS,
    HOST_RESOLUTION_STAGE_WORKERS,
)

logger = logging.getLogger(__name__)


def _entry_from_payload(payload: dict[str, Any]) -> ParsedDomainEntry:
    return ParsedDomainEntry(
        host=str(payload["host"]),
        registrable_domain=str(payload.get("registrable_domain", "")),
        input_name=str(payload.get("input_name", payload["host"])),
        public_suffix=str(payload.get("public_suffix", "")),
        is_public_suffix_input=bool(payload.get("is_public_suffix_input", False)),
        input_kind=str(payload.get("input_kind", "exact_host")),
        apex_scope=str(payload.get("apex_scope", "exact_only")),
        source_format=str(payload.get("source_format", "plain")),
    )


def _geo_provider_token(geo_config: dict[str, Any]) -> str:
    """Return runtime-only geo token without persisting environment secrets."""
    config_token = str(geo_config.get("token", "")).strip()
    if config_token:
        logger.debug("Geo provider token source=config")
        return config_token
    env_token = os.environ.get("GEO_IPINFO_TOKEN", "").strip()
    logger.debug(
        "Geo provider token source=%s",
        "GEO_IPINFO_TOKEN" if env_token else "empty",
    )
    return env_token


def _prepared_entries(
    job: SourceJob, prepared_metadata: dict[str, Any] | None
) -> list[tuple[ParsedDomainEntry, dict[str, Any]]]:
    if not prepared_metadata:
        return []
    source_payload = prepared_metadata.get("sources", {}).get(job.source_id)
    if not isinstance(source_payload, dict):
        return []
    entries = source_payload.get("entries", [])
    if not isinstance(entries, list):
        return []
    result: list[tuple[ParsedDomainEntry, dict[str, Any]]] = []
    for item in entries:
        if isinstance(item, dict):
            result.append((_entry_from_payload(item), item))
    return result


class AsyncPipelineRuntime:
    """Worker-local async DAG for prepared and config-sourced runtime payloads."""

    def __init__(
        self,
        config: dict[str, Any],
        *,
        runtime_identity: dict[str, str] | None = None,
        prepared_metadata: dict[str, Any] | None = None,
    ) -> None:
        self.config = config
        self.runtime_identity = runtime_identity or {}
        self.prepared_metadata = prepared_metadata or {}
        self.writer = ResultCollectorWriter()
        cache_payload = config.get("cache", {})
        cache_file = str(cache_payload.get("cache_file", "")).strip()
        cache_path = Path(cache_file) if cache_file else Path(".cache.sqlite3")
        baseline_cache_file = str(cache_payload.get("baseline_cache_file", "")).strip()
        baseline_cache_path = Path(baseline_cache_file) if baseline_cache_file else None
        cache = PipelineCache.load(cache_path)
        cache.close()
        self.cache_bundle = build_cache_bundle(
            cache_path,
            baseline_cache_path=baseline_cache_path,
        )
        self.cache_reader = self.cache_bundle.reader
        self.cache_stats: Counter[str] = Counter()

    @classmethod
    def from_runtime_payload(
        cls,
        runtime_config: dict[str, Any],
        *,
        runtime_identity: dict[str, str] | None = None,
        prepared_metadata: dict[str, Any] | None = None,
    ) -> "AsyncPipelineRuntime":
        """Build a runtime from a manifest-owned payload."""
        return cls(
            runtime_config,
            runtime_identity=runtime_identity,
            prepared_metadata=prepared_metadata,
        )

    def close(self) -> None:
        """Close runtime resources."""
        return

    def _delegation_from_cache_record(self, record: Any) -> DelegationResult:
        return DelegationResult(
            domain=record.domain,
            ns_exists=record.ns_exists,
            ns_nodata=record.ns_nodata,
            ns_nxdomain=record.ns_nxdomain,
            ns_timeout=record.ns_timeout,
            ns_servfail=record.ns_servfail,
            no_nameservers=record.no_nameservers,
            nameservers=record.nameservers,
            from_cache=True,
        )

    def _host_resolution_from_cache_record(self, record: Any) -> HostResolutionResult:
        """Build a host-resolution result from the physical dns_history table."""
        return HostResolutionResult(
            host=record.host,
            a_exists=record.a_exists,
            a_nodata=record.a_nodata,
            a_nxdomain=record.a_nxdomain,
            a_timeout=record.a_timeout,
            a_servfail=record.a_servfail,
            canonical_name=record.canonical_name or None,
            ipv4_addresses=record.ipv4_addresses,
            ipv6_addresses=record.ipv6_addresses,
            from_cache=True,
        )

    def _geo_from_cache_record(self, record: Any) -> IPGeoResult:
        return IPGeoResult(
            ip=record.ip,
            provider=record.provider,
            country_code=record.country_code,
            region_code=record.region_code,
            region_name=record.region_name,
            status=GEO_STATUS_CACHE_HIT,
        )

    def _host_resolution_ttl_days(self, result: HostResolutionResult) -> int:
        """Return cache retention for one stable host-resolution outcome."""
        ttl_config = self.config["cache"].get("dns_host_resolution_ttl_days", {})
        return int(
            ttl_config.get(result.status, self.config["cache"].get("dns_ttl_days", 1))
        )

    def _record_cache_hit(self, prefix: str, source: CacheHitSource | None) -> None:
        """Record cache hit counters, including overlay/baseline source."""
        self.cache_stats[f"{prefix}_cache_hits"] += 1
        if source is not None:
            self.cache_stats[f"{prefix}_{source}_cache_hits"] += 1
        if prefix == "host_resolution":
            self.cache_stats["dns_cache_hits"] += 1
            if source is not None:
                self.cache_stats[f"dns_{source}_cache_hits"] += 1

    def _record_cache_miss(self, prefix: str) -> None:
        """Record cache misses with legacy dns_* aliases for host resolution."""
        self.cache_stats[f"{prefix}_cache_misses"] += 1
        if prefix == "host_resolution":
            self.cache_stats["dns_cache_misses"] += 1

    async def _lookup_delegation(
        self, job: SourceJob, entry: ParsedDomainEntry
    ) -> DelegationResult:
        checker = build_checker(job.config)
        resolver_key = checker.delegation_resolver_key()
        now = utc_now()
        cached, source = await self.cache_reader.get_fresh_delegation_with_source(
            entry.registrable_domain, resolver_key, now
        )
        if cached is not None:
            self._record_cache_hit("delegation", source)
            return self._delegation_from_cache_record(cached)
        self._record_cache_miss("delegation")
        result = await AsyncDelegationTransport(checker).lookup(
            entry.registrable_domain
        )
        if result.status in {"timeout", "servfail"}:
            return result
        ttl_config = self.config["cache"]["classification_ttl_days"]
        ttl_days = (
            int(ttl_config["dns_delegation_actionable"])
            if result.actionable
            else int(ttl_config["dns_delegation_unactionable"])
        )
        await self.cache_bundle.writers[0].queue.put(
            DelegationCacheWriteRequest(
                domain=result.domain,
                resolver_key=resolver_key,
                ns_exists=result.ns_exists,
                ns_nodata=result.ns_nodata,
                ns_nxdomain=result.ns_nxdomain,
                ns_timeout=result.ns_timeout,
                ns_servfail=result.ns_servfail,
                no_nameservers=result.no_nameservers,
                nameservers=result.nameservers,
                checked_at=now,
                ttl_days=ttl_days,
            )
        )
        return result

    async def _lookup_host_resolution(
        self, job: SourceJob, entry: ParsedDomainEntry
    ) -> HostResolutionResult:
        """Run or cache-read the optional dns.host_resolution stage."""
        checker = build_checker(job.config)
        resolver_key = checker.host_resolution_resolver_key()
        now = utc_now()
        cached, source = await self.cache_reader.get_fresh_dns_with_source(
            entry.host, resolver_key, now
        )
        if cached is not None:
            cached_result = self._host_resolution_from_cache_record(cached)
            if cached_result.status != "unknown":
                self._record_cache_hit("host_resolution", source)
                return cached_result
            logger.debug(
                "Ignoring stale host-resolution cache row for %s with unknown status",
                entry.host,
            )
        self._record_cache_miss("host_resolution")
        result = await AsyncHostResolutionTransport(checker).lookup(entry.host)
        if result.status in {"timeout", "servfail", "unknown"}:
            return result
        ttl_days = self._host_resolution_ttl_days(result)
        if ttl_days <= 0:
            return result
        await self.cache_bundle.writers[1].queue.put(
            HostResolutionCacheWriteRequest(
                host=result.host,
                resolver_key=resolver_key,
                a_exists=result.a_exists,
                a_nodata=result.a_nodata,
                a_nxdomain=result.a_nxdomain,
                a_timeout=result.a_timeout,
                a_servfail=result.a_servfail,
                canonical_name=result.canonical_name or "",
                ipv4_addresses=result.ipv4_addresses,
                ipv6_addresses=result.ipv6_addresses,
                checked_at=now,
                ttl_days=ttl_days,
            )
        )
        return result

    async def _lookup_geo(
        self, job: SourceJob, host_resolution_result: HostResolutionResult
    ) -> tuple[str, list[IPGeoResult], Any | None]:
        geo_config = job.config["geo"]
        provider_name = str(
            geo_config.get("effective_provider") or geo_config.get("provider")
        )
        now = utc_now()
        cached_results: dict[str, IPGeoResult] = {}
        missing_ips: list[str] = []
        seen_missing_ips: set[str] = set()
        for ip in host_resolution_result.resolved_ips:
            cached, source = await self.cache_reader.get_fresh_geo_with_source(
                provider_name, ip, now
            )
            if cached is not None:
                self._record_cache_hit("geo", source)
                cached_results[ip] = self._geo_from_cache_record(cached)
                continue
            if ip not in seen_missing_ips:
                self.cache_stats["geo_cache_misses"] += 1
                missing_ips.append(ip)
                seen_missing_ips.add(ip)
        try:
            fetched_results: list[IPGeoResult] = []
            if missing_ips:
                provider = build_geo_provider(
                    provider_name,
                    timeout=float(geo_config.get("timeout", 5.0)),
                    token=_geo_provider_token(geo_config),
                )
                fetched_results = await AsyncGeoTransport(provider).lookup_ips(
                    missing_ips
                )
            fetched_by_ip = {result.ip: result for result in fetched_results}
            for result in fetched_results:
                if not result.usable or result.status == GEO_STATUS_CACHE_HIT:
                    continue
                await self.cache_bundle.writers[2].queue.put(
                    GeoCacheWriteRequest(
                        provider=provider_name,
                        ip=result.ip,
                        country_code=result.country_code,
                        region_code=result.region_code,
                        region_name=result.region_name,
                        checked_at=now,
                        ttl_days=int(geo_config.get("cache_ttl_days", 7)),
                    )
                )
            results = [
                cached_results[ip] if ip in cached_results else fetched_by_ip[ip]
                for ip in host_resolution_result.resolved_ips
                if ip in cached_results or ip in fetched_by_ip
            ]
            policy = evaluate_geo_policy(results, geo_config["policy"])
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.warning(
                "Geo lookup failed for %s: %s", host_resolution_result.host, exc
            )
            return CLASSIFICATION_GEO_LOOKUP_FAILED, [], None
        return (
            geo_policy_classification(policy, results, geo_config["policy"]),
            results,
            policy,
        )

    def _completed_result(
        self,
        *,
        job: SourceJob,
        entry: ParsedDomainEntry,
        classification: str,
        delegation_result: DelegationResult | None = None,
        host_resolution_result: HostResolutionResult | None = None,
        geo_results: list[IPGeoResult] | None = None,
        geo_policy: Any | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> CompletedHostResult:
        provenance = provenance or {}
        row = build_base_row(
            job=job,
            entry=entry,
            classification=classification,
            delegation_result=delegation_result,
            host_resolution_result=host_resolution_result,
            geo_results=geo_results or [],
            geo_policy=geo_policy,
            source_id_override=provenance.get("source_id_override"),
            source_input_label_override=provenance.get("source_input_label_override"),
            source_ids=tuple(provenance.get("source_ids", ())),
            source_input_labels=tuple(provenance.get("source_input_labels", ())),
        )
        return CompletedHostResult(
            job=job,
            entry=entry,
            classification=classification,
            route=route_for_classification(classification),
            row=row,
            delegation_result=delegation_result,
            host_resolution_result=host_resolution_result,
            geo_results=geo_results or [],
            geo_policy=geo_policy,
        )

    async def _put_completed(
        self,
        queue_bundle: QueueBundle,
        parsed: ParsedHostItem,
        *,
        classification: str,
        delegation_result: DelegationResult | None = None,
        host_resolution_result: HostResolutionResult | None = None,
        geo_results: list[IPGeoResult] | None = None,
        geo_policy: Any | None = None,
    ) -> None:
        await queue_bundle.result_queue.put(
            self._completed_result(
                job=parsed.job,
                entry=parsed.entry,
                classification=classification,
                delegation_result=delegation_result,
                host_resolution_result=host_resolution_result,
                geo_results=geo_results,
                geo_policy=geo_policy,
                provenance={
                    "source_id_override": parsed.source_id_override,
                    "source_input_label_override": parsed.source_input_label_override,
                    "source_ids": parsed.source_ids,
                    "source_input_labels": parsed.source_input_labels,
                },
            )
        )

    async def _delegation_worker(self, queue_bundle: QueueBundle) -> None:
        """Consume worker-local delegation input and route each result."""
        while True:
            parsed = await queue_bundle.delegation_input.get()
            try:
                if parsed is None:
                    return
                if (
                    parsed.entry.is_public_suffix_input
                    or not parsed.entry.registrable_domain
                ):
                    await self._put_completed(
                        queue_bundle,
                        parsed,
                        classification=CLASSIFICATION_INPUT_PUBLIC_SUFFIX,
                    )
                    continue
                delegation_result = await self._lookup_delegation(
                    parsed.job, parsed.entry
                )
                await self._route_delegation_result(
                    queue_bundle, parsed, delegation_result
                )
            finally:
                queue_bundle.delegation_input.task_done()

    async def _route_delegation_result(
        self,
        queue_bundle: QueueBundle,
        parsed: ParsedHostItem,
        delegation_result: DelegationResult,
    ) -> None:
        delegation_classification = classify_delegation(delegation_result)
        if not delegation_result.actionable:
            await self._put_completed(
                queue_bundle,
                parsed,
                classification=delegation_classification,
                delegation_result=delegation_result,
            )
            return
        if parsed.manual_filter_pass:
            await self._put_completed(
                queue_bundle,
                parsed,
                classification=CLASSIFICATION_MANUAL_FILTER_PASSED,
                delegation_result=delegation_result,
            )
            return
        if parsed.manual_add:
            await self._put_completed(
                queue_bundle,
                parsed,
                classification=CLASSIFICATION_MANUAL_ADD_ACTIONABLE,
                delegation_result=delegation_result,
            )
            return
        dns_config = parsed.job.config["dns"]
        if not bool(dns_config.get("host_resolution", {}).get("enabled", False)):
            await self._put_completed(
                queue_bundle,
                parsed,
                classification=host_resolution_skipped_classification(),
                delegation_result=delegation_result,
            )
            return
        await queue_bundle.delegation_to_host_resolution.put(
            HostResolutionWorkItem(parsed=parsed, delegation_result=delegation_result)
        )

    async def _host_resolution_worker(self, queue_bundle: QueueBundle) -> None:
        """Consume host-resolution work and route review, filtered, or geo cases."""
        while True:
            work_item = await queue_bundle.delegation_to_host_resolution.get()
            try:
                if work_item is None:
                    return
                host_resolution_result = await self._lookup_host_resolution(
                    work_item.parsed.job, work_item.parsed.entry
                )
                await self._route_host_resolution_result(
                    queue_bundle, work_item, host_resolution_result
                )
            finally:
                queue_bundle.delegation_to_host_resolution.task_done()

    async def _route_host_resolution_result(
        self,
        queue_bundle: QueueBundle,
        work_item: HostResolutionWorkItem,
        host_resolution_result: HostResolutionResult,
    ) -> None:
        host_classification = classify_host_resolution(host_resolution_result)
        if route_for_classification(host_classification) == "review":
            await self._put_completed(
                queue_bundle,
                work_item.parsed,
                classification=host_classification,
                delegation_result=work_item.delegation_result,
                host_resolution_result=host_resolution_result,
            )
            return
        if not bool(work_item.parsed.job.config["geo"].get("enabled", False)):
            await self._put_completed(
                queue_bundle,
                work_item.parsed,
                classification=host_classification,
                delegation_result=work_item.delegation_result,
                host_resolution_result=host_resolution_result,
            )
            return
        await queue_bundle.host_resolution_to_geo.put(
            GeoWorkItem(
                parsed=work_item.parsed,
                delegation_result=work_item.delegation_result,
                host_resolution_result=host_resolution_result,
                classification=host_classification,
            )
        )

    async def _geo_worker(self, queue_bundle: QueueBundle) -> None:
        """Consume geo work and emit terminal policy results."""
        while True:
            work_item = await queue_bundle.host_resolution_to_geo.get()
            try:
                if work_item is None:
                    return
                geo_classification, geo_results, geo_policy = await self._lookup_geo(
                    work_item.parsed.job, work_item.host_resolution_result
                )
                await self._put_completed(
                    queue_bundle,
                    work_item.parsed,
                    classification=geo_classification,
                    delegation_result=work_item.delegation_result,
                    host_resolution_result=work_item.host_resolution_result,
                    geo_results=geo_results,
                    geo_policy=geo_policy,
                )
            finally:
                queue_bundle.host_resolution_to_geo.task_done()

    async def _result_writer(self, queue_bundle: QueueBundle) -> None:
        """Drain terminal results into the deterministic writer buffer."""
        while True:
            result = await queue_bundle.result_queue.get()
            try:
                if result is None:
                    return
                self.writer.add(result)
            finally:
                queue_bundle.result_queue.task_done()

    def _source_jobs(self) -> list[SourceJob]:
        """Return source jobs for prepared workflow or direct runtime modes."""
        if self.prepared_metadata:
            return [
                SourceJob(
                    source_id=str(source["id"]),
                    input_label=str(
                        source.get("input", {}).get("label")
                        or source["input"]["location"]
                    ),
                    output_stem=str(self.config["config_name"]),
                    lines=[],
                    config=source,
                )
                for source in self.config["sources"]
                if source.get("enabled", True)
            ]
        return build_source_jobs(self.config)

    def _runtime_items(self) -> list[ParsedHostItem]:
        """Build worker-local items that seed the delegation input queue."""
        parser = DomainListParser()
        item_payloads: list[tuple[SourceJob, ParsedDomainEntry, dict[str, Any]]] = []
        for job in self._source_jobs():
            prepared_entries = _prepared_entries(job, self.prepared_metadata)
            if prepared_entries:
                for entry, provenance in prepared_entries:
                    item_payloads.append((job, entry, provenance))
                continue
            forced_format = job.config.get("input", {}).get("format", "auto")
            for entry in parser.process_entries(
                job.lines,
                source_name=job.input_label,
                forced_format=None if forced_format == "auto" else forced_format,
            ):
                item_payloads.append((job, entry, {}))
        total = len(item_payloads)
        return [
            ParsedHostItem(
                job=job,
                entry=entry,
                sequence=index,
                total=total,
                manual_filter_pass=bool(provenance.get("manual_filter_pass", False)),
                manual_add=bool(provenance.get("manual_add", False)),
                source_id_override=provenance.get("source_id_override"),
                source_input_label_override=provenance.get(
                    "source_input_label_override"
                ),
                source_ids=tuple(provenance.get("source_ids", ())),
                source_input_labels=tuple(provenance.get("source_input_labels", ())),
            )
            for index, (job, entry, provenance) in enumerate(item_payloads)
        ]

    async def _load_delegation_input(self, queue_bundle: QueueBundle) -> None:
        """Seed the first worker-local queue from runtime payload entries."""
        items = self._runtime_items()
        logger.debug(
            "Async pipeline loader enqueueing delegation_input items=%d", len(items)
        )
        for item in items:
            await queue_bundle.delegation_input.put(item)
        for _ in range(DELEGATION_STAGE_WORKERS):
            await queue_bundle.delegation_input.put(None)
        logger.debug(
            "Async pipeline loader sent delegation sentinels count=%d",
            DELEGATION_STAGE_WORKERS,
        )

    async def _join_or_raise(
        self,
        queue: asyncio.Queue[Any],
        watched_tasks: list[asyncio.Task[Any]],
    ) -> None:
        """Wait for a queue to drain while surfacing worker task failures."""
        join_task = asyncio.create_task(queue.join())
        try:
            while not join_task.done():
                active_tasks = [task for task in watched_tasks if not task.done()]
                done, _pending = await asyncio.wait(
                    [join_task, *active_tasks],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in done:
                    if task is join_task:
                        continue
                    exception = task.exception()
                    if exception is not None:
                        raise exception
            await join_task
        finally:
            if not join_task.done():
                join_task.cancel()

    async def _stop_cache_writers(
        self,
        cache_bundle: CacheBundle,
        cache_tasks: list[asyncio.Task[Any]],
    ) -> None:
        """Drain and stop cache writers after all stage workers have stopped."""
        logger.debug("Async pipeline waiting for cache writer queues to drain")
        for writer in cache_bundle.writers:
            await writer.queue.join()
        logger.debug(
            "Async pipeline stopping cache writers count=%d", len(cache_bundle.writers)
        )
        for writer in cache_bundle.writers:
            await writer.queue.put(None)
        await asyncio.gather(*cache_tasks)
        logger.debug("Async pipeline cache writers stopped")

    async def run_async(self) -> int:
        """Run the prepared or config-sourced pipeline through async stage queues."""
        queue_bundle = build_queue_bundle()
        logger.debug(
            "Async pipeline starting worker-local queues delegation_workers=%d "
            "host_resolution_workers=%d geo_workers=%d prepared_metadata=%s",
            DELEGATION_STAGE_WORKERS,
            HOST_RESOLUTION_STAGE_WORKERS,
            GEO_STAGE_WORKERS,
            bool(self.prepared_metadata),
        )
        loader_task = asyncio.create_task(self._load_delegation_input(queue_bundle))
        delegation_tasks = [
            asyncio.create_task(self._delegation_worker(queue_bundle))
            for _ in range(DELEGATION_STAGE_WORKERS)
        ]
        host_resolution_tasks = [
            asyncio.create_task(self._host_resolution_worker(queue_bundle))
            for _ in range(HOST_RESOLUTION_STAGE_WORKERS)
        ]
        geo_tasks = [
            asyncio.create_task(self._geo_worker(queue_bundle))
            for _ in range(GEO_STAGE_WORKERS)
        ]
        result_task = asyncio.create_task(self._result_writer(queue_bundle))
        cache_tasks = [
            asyncio.create_task(writer.run()) for writer in self.cache_bundle.writers
        ]
        all_tasks = [
            loader_task,
            *delegation_tasks,
            *host_resolution_tasks,
            *geo_tasks,
            result_task,
            *cache_tasks,
        ]
        try:
            await loader_task
            logger.debug("Async pipeline waiting for delegation_input drain")
            await self._join_or_raise(queue_bundle.delegation_input, delegation_tasks)
            await asyncio.gather(*delegation_tasks)
            logger.debug("Async pipeline delegation_input drained")
            for _ in range(HOST_RESOLUTION_STAGE_WORKERS):
                await queue_bundle.delegation_to_host_resolution.put(None)
            logger.debug(
                "Async pipeline sent host-resolution sentinels count=%d",
                HOST_RESOLUTION_STAGE_WORKERS,
            )
            logger.debug(
                "Async pipeline waiting for delegation_to_host_resolution drain"
            )
            await self._join_or_raise(
                queue_bundle.delegation_to_host_resolution,
                host_resolution_tasks,
            )
            await asyncio.gather(*host_resolution_tasks)
            logger.debug("Async pipeline delegation_to_host_resolution drained")
            for _ in range(GEO_STAGE_WORKERS):
                await queue_bundle.host_resolution_to_geo.put(None)
            logger.debug(
                "Async pipeline sent geo sentinels count=%d",
                GEO_STAGE_WORKERS,
            )
            logger.debug("Async pipeline waiting for host_resolution_to_geo drain")
            await self._join_or_raise(queue_bundle.host_resolution_to_geo, geo_tasks)
            await asyncio.gather(*geo_tasks)
            logger.debug("Async pipeline host_resolution_to_geo drained")
            logger.debug("Async pipeline waiting for result_queue drain")
            await self._join_or_raise(queue_bundle.result_queue, [result_task])
            await queue_bundle.result_queue.put(None)
            await result_task
            logger.debug("Async pipeline result_queue drained and writer stopped")
            await self._stop_cache_writers(self.cache_bundle, cache_tasks)
            writer_result = self.writer.write()
            logger.info(
                "Pipeline emitted counts=%s outputs=%s",
                dict(writer_result.counts),
                writer_result.output_paths,
            )
            return 0
        except Exception:
            for task in all_tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*all_tasks, return_exceptions=True)
            raise

    def run(self) -> int:
        """Run the async DAG from synchronous compatibility callers."""
        return asyncio.run(self.run_async())


async def run_prepared_pipeline_async(
    runtime_config: dict[str, Any],
    *,
    runtime_identity: dict[str, str] | None = None,
    max_runtime_seconds: float | None = None,
    prepared_metadata: dict[str, Any] | None = None,
) -> int:
    """Run one workflow-owned runtime payload."""
    runtime = AsyncPipelineRuntime.from_runtime_payload(
        runtime_config,
        runtime_identity=runtime_identity,
        prepared_metadata=prepared_metadata,
    )
    try:
        if max_runtime_seconds is None:
            return await runtime.run_async()
        return await asyncio.wait_for(runtime.run_async(), timeout=max_runtime_seconds)
    finally:
        runtime.close()
