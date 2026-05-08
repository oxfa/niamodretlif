"""Worker-local async DNS actionability runtime."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import os
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from domain_pipeline.prepare.classifications import (
    PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX,
)
from domain_pipeline.worker.ip_location.result_codes import (
    PIPELINE_RESULT_CODE_IP_LOCATION_LOOKUP_FAILED,
)
from domain_pipeline.worker.cache.requests import (
    DelegationCacheWriteRequest,
    IpLocationCacheWriteRequest,
    HostResolutionCacheWriteRequest,
)
from domain_pipeline.worker.runtime.contracts import (
    CompletedHostResult,
    HostResolutionWorkItem,
    ParsedHostItem,
    WorkerSourceContext,
)
from domain_pipeline.worker.cache.repository import CacheRepository, utc_now
from domain_pipeline.worker.cache.service import (
    CacheBundle,
    CacheHitSource,
    build_cache_bundle,
)
from domain_pipeline.worker.ip_location import ip_location_policy_result_code
from domain_pipeline.worker.runtime.transports import (
    AsyncDelegationTransport,
    AsyncIpLocationTransport,
    AsyncHostResolutionTransport,
)
from domain_pipeline.prepare.sources.parser import ParsedDomainEntry
from domain_pipeline.worker.delegation import DelegationResult
from domain_pipeline.worker.host_resolution import HostResolutionResult
from domain_pipeline.worker.ip_location import (
    IP_LOCATION_STATUS_CACHE_HIT,
    IPLocationResult,
    build_ip_location_provider,
    evaluate_ip_location_policy,
)
from domain_pipeline.worker.output import ResultOutputWriter
from domain_pipeline.worker.runtime.dns_factory import RuntimeDNSCheckerFactory
from domain_pipeline.worker.dns_query.query_coordinator import (
    DNSQueryCoordinatorRegistry,
)
from domain_pipeline.worker.runtime.adaptive import (
    AdaptiveDNSPressureState,
    AdaptiveStageDecisionEngine,
    AdaptiveStageSupervisor,
)
from domain_pipeline.worker.runtime.busy_state import BusyReason, BusyStateRecorder
from domain_pipeline.worker.runtime.capacity import (
    DNSStageCapacityGroup,
    RuntimeDNSCapacityGroups,
    capacity_state_for_groups,
    discover_dns_capacity_groups,
)
from domain_pipeline.worker.runtime.config_validation import (
    runtime_cache_payload,
    runtime_stage_concurrency_payload,
)
from domain_pipeline.worker.runtime.loading import RuntimeItemLoader
from domain_pipeline.worker.runtime.queues import RuntimeQueueSet
from domain_pipeline.worker.runtime.results import (
    CompletedResultFactory,
    delegation_result_from_cache_record,
    ip_location_result_from_cache_record,
    host_resolution_result_from_cache_record,
)
from domain_pipeline.worker.runtime.stages import (
    DelegationStage,
    IpLocationStage,
    HostResolutionStage,
)
from domain_pipeline.worker.runtime.constants import (
    DELEGATION_STAGE_CONCURRENCY,
    DNS_HOST_RESOLUTION_STAGE_CONCURRENCY,
    IP_LOCATION_STAGE_CONCURRENCY,
)

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class RuntimeStageConcurrencyCounts:
    """Worker-local async stage concurrency counts."""

    delegation: int
    host_resolution: int
    ip_location: int


@dataclasses.dataclass(frozen=True)
class RuntimeStageConcurrencyLimits:
    """Adaptive sizing for one worker-local runtime stage."""

    minimum: int
    cap: int
    enabled: bool = True


@dataclasses.dataclass(frozen=True)
class RuntimeStageConcurrencySettings:
    """Parsed worker-local runtime stage sizing settings."""

    delegation: RuntimeStageConcurrencyLimits
    host_resolution: RuntimeStageConcurrencyLimits
    ip_location: RuntimeStageConcurrencyLimits
    adaptive_enabled: bool
    supervisor_interval_seconds: float
    busy_scale_up_after_seconds: float
    idle_scale_down_after_seconds: float
    pressure_window_seconds: float
    queue_pressure_ratio: float
    scale_up_step: int
    scale_down_step: int


def _runtime_stage_concurrency_payload(config: dict[str, Any]) -> dict[str, Any]:
    """Return canonical stage concurrency payload."""
    return runtime_stage_concurrency_payload(config)


def _runtime_stage_concurrency_counts(
    config: dict[str, Any],
) -> RuntimeStageConcurrencyCounts:
    """Return runtime stage concurrency counts with defaults."""
    stage_concurrency = _runtime_stage_concurrency_payload(config)
    minimums = dict(stage_concurrency.get("minimums", {}))
    return RuntimeStageConcurrencyCounts(
        delegation=int(minimums.get("delegation", DELEGATION_STAGE_CONCURRENCY)),
        host_resolution=int(
            minimums.get("host_resolution", DNS_HOST_RESOLUTION_STAGE_CONCURRENCY)
        ),
        ip_location=int(minimums.get("ip_location", IP_LOCATION_STAGE_CONCURRENCY)),
    )


def _runtime_stage_concurrency_settings(
    config: dict[str, Any],
) -> RuntimeStageConcurrencySettings:
    """Return parsed runtime concurrency settings for adaptive and static modes."""
    counts = _runtime_stage_concurrency_counts(config)
    stage_concurrency = _runtime_stage_concurrency_payload(config)
    adaptive = dict(stage_concurrency.get("adaptive", {}))
    adaptive_enabled = bool(adaptive.get("enabled", True))
    multiplier = max(int(adaptive.get("max_concurrency_multiplier", 4)), 1)

    def concurrency_settings(
        minimum: int, *, adaptive_stage: bool = True
    ) -> RuntimeStageConcurrencyLimits:
        if not adaptive_enabled or not adaptive_stage:
            return RuntimeStageConcurrencyLimits(
                minimum=minimum, cap=minimum, enabled=False
            )
        return RuntimeStageConcurrencyLimits(
            minimum=minimum,
            cap=minimum * multiplier,
            enabled=True,
        )

    return RuntimeStageConcurrencySettings(
        delegation=concurrency_settings(
            counts.delegation,
            adaptive_stage=bool(adaptive.get("delegation_enabled", True)),
        ),
        host_resolution=concurrency_settings(
            counts.host_resolution,
            adaptive_stage=bool(adaptive.get("host_resolution_enabled", True)),
        ),
        ip_location=concurrency_settings(counts.ip_location, adaptive_stage=False),
        adaptive_enabled=adaptive_enabled,
        supervisor_interval_seconds=float(
            adaptive.get("supervisor_interval_seconds", 1.0)
        ),
        busy_scale_up_after_seconds=float(
            adaptive.get("busy_scale_up_after_seconds", 5.0)
        ),
        idle_scale_down_after_seconds=float(
            adaptive.get("idle_scale_down_after_seconds", 5.0)
        ),
        pressure_window_seconds=float(adaptive.get("pressure_window_seconds", 5.0)),
        queue_pressure_ratio=float(adaptive.get("queue_pressure_ratio", 0.8)),
        scale_up_step=int(adaptive.get("scale_up_step", 1)),
        scale_down_step=int(adaptive.get("scale_down_step", 1)),
    )


def _runtime_dns_capacity_groups(
    config: dict[str, Any],
    *,
    prepared_metadata: dict[str, Any] | None,
) -> RuntimeDNSCapacityGroups:
    """Return stage-specific DNS capacity groups for this runtime payload."""
    return discover_dns_capacity_groups(
        RuntimeItemLoader(config=config, prepared_metadata=prepared_metadata)
    )


def _ip_location_provider_token(ip_location_config: dict[str, Any]) -> str:
    """Return runtime-only ip location token without persisting environment secrets."""
    config_token = str(ip_location_config.get("token", "")).strip()
    if config_token:
        logger.debug("IpLocation provider token source=config")
        return config_token
    env_token = os.environ.get("IP_LOCATION_IPINFO_TOKEN", "").strip()
    logger.debug(
        "IpLocation provider token source=%s",
        "IP_LOCATION_IPINFO_TOKEN" if env_token else "empty",
    )
    return env_token


class PipelineExecutor:
    """Worker-local async DAG for prepared and config-sourced runtime payloads."""

    def __init__(
        self,
        config: dict[str, Any],
        *,
        runtime_identity: dict[str, str] | None = None,
        prepared_metadata: dict[str, Any] | None = None,
    ) -> None:
        _ = runtime_identity
        self.config = config
        self.prepared_metadata = prepared_metadata
        self.writer = ResultOutputWriter()
        cache_payload = runtime_cache_payload(config)
        cache_file = str(cache_payload.get("cache_file", "")).strip()
        cache_path = Path(cache_file)
        baseline_cache_file = str(cache_payload.get("baseline_cache_file", "")).strip()
        baseline_cache_path = Path(baseline_cache_file) if baseline_cache_file else None
        cache = CacheRepository.load(cache_path)
        cache.close()
        self.cache_bundle = build_cache_bundle(
            cache_path,
            baseline_cache_path=baseline_cache_path,
        )
        self.cache_reader = self.cache_bundle.reader
        self.cache_stats: Counter[str] = Counter()
        self.stage_concurrency = _runtime_stage_concurrency_counts(config)
        self.concurrency_settings = _runtime_stage_concurrency_settings(config)
        self.dns_capacity_groups = _runtime_dns_capacity_groups(
            config,
            prepared_metadata=prepared_metadata,
        )
        self.delegation_executor = ThreadPoolExecutor(
            max_workers=self.concurrency_settings.delegation.cap,
            thread_name_prefix="dns-delegation",
        )
        self.host_resolution_executor = ThreadPoolExecutor(
            max_workers=self.concurrency_settings.host_resolution.cap,
            thread_name_prefix="dns-host-resolution",
        )
        self._delegation_tasks: dict[
            tuple[str, str], asyncio.Task[DelegationResult]
        ] = {}
        self.busy_state = BusyStateRecorder()

    @classmethod
    def from_runtime_payload(
        cls,
        runtime_config: dict[str, Any],
        *,
        runtime_identity: dict[str, str] | None = None,
        prepared_metadata: dict[str, Any] | None = None,
    ) -> "PipelineExecutor":
        """Build a runtime from a manifest-owned payload."""
        return cls(
            runtime_config,
            runtime_identity=runtime_identity,
            prepared_metadata=prepared_metadata,
        )

    def close(self) -> None:
        """Close runtime resources."""
        logger.debug(
            "Runtime DNS executors shutdown requested wait=False "
            "cancel_futures=True; running DNS calls may continue"
        )
        self.delegation_executor.shutdown(wait=False, cancel_futures=True)
        self.host_resolution_executor.shutdown(wait=False, cancel_futures=True)

    def _host_resolution_ttl_days(self, result: HostResolutionResult) -> int:
        """Return cache retention for one stable host-resolution outcome."""
        ttl_config = self.config["cache"].get("host_resolution_ttl_days", {})
        return int(ttl_config.get(result.status, 1))

    def _record_cache_hit(self, prefix: str, source: CacheHitSource | None) -> None:
        """Record cache hit counters, including overlay/baseline source."""
        self.cache_stats[f"{prefix}_cache_hits"] += 1
        if source is not None:
            self.cache_stats[f"{prefix}_{source}_cache_hits"] += 1

    def _record_cache_miss(self, prefix: str) -> None:
        """Record cache misses for one cache family."""
        self.cache_stats[f"{prefix}_cache_misses"] += 1

    async def lookup_delegation(
        self, source_context: WorkerSourceContext, entry: ParsedDomainEntry
    ) -> DelegationResult:
        """Run or cache-read the required delegation stage."""
        return await self.lookup_delegation_root(
            source_context, entry.registrable_domain
        )

    async def lookup_delegation_root(
        self, source_context: WorkerSourceContext, registrable_domain: str
    ) -> DelegationResult:
        """Run or join one root-level delegation lookup."""
        checker = RuntimeDNSCheckerFactory().build(source_context.config)
        resolver_key = checker.delegation_resolver_key()
        task_key = (registrable_domain, resolver_key)
        task = self._delegation_tasks.get(task_key)
        if task is None:
            task = asyncio.create_task(
                self._lookup_delegation_root_once(
                    checker=checker,
                    registrable_domain=registrable_domain,
                    resolver_key=resolver_key,
                ),
                name=f"delegation_{registrable_domain}",
            )
            self._delegation_tasks[task_key] = task
        try:
            async with self.busy_state.track(BusyReason.INFLIGHT_JOIN):
                return await task
        finally:
            if task.done() and self._delegation_tasks.get(task_key) is task:
                self._delegation_tasks.pop(task_key, None)

    async def _lookup_delegation_root_once(
        self,
        *,
        checker: Any,
        registrable_domain: str,
        resolver_key: str,
    ) -> DelegationResult:
        """Run or cache-read one root-level delegation lookup."""
        now = utc_now()
        async with self.busy_state.track(BusyReason.CACHE_READ):
            cached, source = await self.cache_reader.get_fresh_delegation_with_source(
                registrable_domain, resolver_key, now
            )
        if cached is not None:
            cached_result = delegation_result_from_cache_record(cached)
            self._record_cache_hit("delegation", source)
            return cached_result
        self._record_cache_miss("delegation")
        async with self.busy_state.track(BusyReason.LIVE_DNS):
            result = await AsyncDelegationTransport(
                checker, executor=self.delegation_executor
            ).lookup(registrable_domain)
        if result.status in {
            "timeout",
            "servfail",
            "ns_nodata_soa_timeout",
            "ns_nodata_soa_servfail",
        }:
            return result
        ttl_config = self.config["cache"]["classification_ttl_days"]
        ttl_days = (
            int(ttl_config["delegation_actionable"])
            if result.actionable
            else int(ttl_config["delegation_unactionable"])
        )
        async with self.busy_state.track(BusyReason.CACHE_WRITE_QUEUE_PUT):
            await self.cache_bundle.writers[0].queue.put(
                DelegationCacheWriteRequest(
                    domain=result.domain,
                    resolver_key=resolver_key,
                    ns_exists=result.ns_exists,
                    ns_nodata=result.ns_nodata,
                    ns_nxdomain=result.ns_nxdomain,
                    ns_timeout=result.ns_timeout,
                    ns_servfail=result.ns_servfail,
                    soa_exists=result.soa_exists,
                    soa_nodata=result.soa_nodata,
                    soa_nxdomain=result.soa_nxdomain,
                    soa_timeout=result.soa_timeout,
                    soa_servfail=result.soa_servfail,
                    no_nameservers=result.no_nameservers,
                    nameservers=result.nameservers,
                    checked_at=now,
                    ttl_days=ttl_days,
                )
            )
        return result

    async def lookup_host_resolution(
        self, source_context: WorkerSourceContext, entry: ParsedDomainEntry
    ) -> HostResolutionResult:
        """Run or cache-read the optional host_resolution stage."""
        checker = RuntimeDNSCheckerFactory().build(source_context.config)
        resolver_key = checker.host_resolution_resolver_key()
        now = utc_now()
        async with self.busy_state.track(BusyReason.CACHE_READ):
            cached, source = (
                await self.cache_reader.get_fresh_host_resolution_with_source(
                    entry.host, resolver_key, now
                )
            )
        if cached is not None:
            cached_result = host_resolution_result_from_cache_record(cached)
            if cached_result.status != "unknown":
                self._record_cache_hit("host_resolution", source)
                return cached_result
            logger.debug(
                "Ignoring host-resolution cache row for %s with unknown status",
                entry.host,
            )
        self._record_cache_miss("host_resolution")
        async with self.busy_state.track(BusyReason.LIVE_DNS):
            result = await AsyncHostResolutionTransport(
                checker, executor=self.host_resolution_executor
            ).lookup(entry.host)
        if result.status in {"timeout", "servfail", "unknown"}:
            return result
        ttl_days = self._host_resolution_ttl_days(result)
        if ttl_days <= 0:
            return result
        async with self.busy_state.track(BusyReason.CACHE_WRITE_QUEUE_PUT):
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

    async def lookup_ip_location(
        self,
        source_context: WorkerSourceContext,
        host_resolution_result: HostResolutionResult,
    ) -> tuple[str, list[IPLocationResult], Any | None]:
        """Run or cache-read the optional ip location stage and evaluate its policy."""
        ip_location_config = source_context.config["ip_location"]
        provider_name = str(ip_location_config.get("effective_provider", ""))
        now = utc_now()
        cached_results: dict[str, IPLocationResult] = {}
        missing_ips: list[str] = []
        seen_missing_ips: set[str] = set()
        for ip in host_resolution_result.resolved_ips:
            cached, source = await self.cache_reader.get_fresh_ip_location_with_source(
                provider_name, ip, now
            )
            if cached is not None:
                self._record_cache_hit("ip_location", source)
                cached_results[ip] = ip_location_result_from_cache_record(cached)
                continue
            if ip not in seen_missing_ips:
                self.cache_stats["ip_location_cache_misses"] += 1
                missing_ips.append(ip)
                seen_missing_ips.add(ip)
        try:
            fetched_results: list[IPLocationResult] = []
            if missing_ips:
                provider = build_ip_location_provider(
                    provider_name,
                    timeout=float(ip_location_config.get("timeout", 5.0)),
                    token=_ip_location_provider_token(ip_location_config),
                )
                fetched_results = await AsyncIpLocationTransport(provider).lookup_ips(
                    missing_ips
                )
            fetched_by_ip = {result.ip: result for result in fetched_results}
            for result in fetched_results:
                if not result.usable or result.status == IP_LOCATION_STATUS_CACHE_HIT:
                    continue
                await self.cache_bundle.writers[2].queue.put(
                    IpLocationCacheWriteRequest(
                        provider=provider_name,
                        ip=result.ip,
                        country_code=result.country_code,
                        region_code=result.region_code,
                        region_name=result.region_name,
                        checked_at=now,
                        ttl_days=int(ip_location_config.get("cache_ttl_days", 7)),
                    )
                )
            results = [
                cached_results[ip] if ip in cached_results else fetched_by_ip[ip]
                for ip in host_resolution_result.resolved_ips
                if ip in cached_results or ip in fetched_by_ip
            ]
            policy = evaluate_ip_location_policy(results, ip_location_config["policy"])
        except Exception as exc:
            logger.warning(
                "IpLocation lookup failed for %s: %s", host_resolution_result.host, exc
            )
            return PIPELINE_RESULT_CODE_IP_LOCATION_LOOKUP_FAILED, [], None
        return (
            ip_location_policy_result_code(
                policy, results, ip_location_config["policy"]
            ),
            results,
            policy,
        )

    def _completed_result(
        self,
        *,
        source_context: WorkerSourceContext,
        entry: ParsedDomainEntry,
        pipeline_result_code: str,
        delegation_result: DelegationResult | None = None,
        host_resolution_result: HostResolutionResult | None = None,
        ip_location_results: list[IPLocationResult] | None = None,
        ip_location_policy: Any | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> CompletedHostResult:
        return CompletedResultFactory().build(
            source_context=source_context,
            entry=entry,
            pipeline_result_code=pipeline_result_code,
            delegation_result=delegation_result,
            host_resolution_result=host_resolution_result,
            ip_location_results=ip_location_results,
            ip_location_policy=ip_location_policy,
            provenance=provenance,
        )

    async def put_completed(
        self,
        queue_bundle: RuntimeQueueSet,
        parsed: ParsedHostItem,
        *,
        pipeline_result_code: str,
        delegation_result: DelegationResult | None = None,
        host_resolution_result: HostResolutionResult | None = None,
        ip_location_results: list[IPLocationResult] | None = None,
        ip_location_policy: Any | None = None,
    ) -> None:
        """Emit one terminal runtime result to the shared result queue."""
        async with self.busy_state.track(BusyReason.RESULT_PUT):
            await queue_bundle.result_queue.put(
                self._completed_result(
                    source_context=parsed.source_context,
                    entry=parsed.entry,
                    pipeline_result_code=pipeline_result_code,
                    delegation_result=delegation_result,
                    host_resolution_result=host_resolution_result,
                    ip_location_results=ip_location_results,
                    ip_location_policy=ip_location_policy,
                    provenance={
                        "source_id_override": parsed.source_id_override,
                        "source_input_label_override": (
                            parsed.source_input_label_override
                        ),
                        "source_ids": parsed.source_ids,
                        "source_input_labels": parsed.source_input_labels,
                    },
                )
            )

    async def _delegation_stage_consumer(self, queue_bundle: RuntimeQueueSet) -> None:
        """Consume worker-local delegation input and route each result."""
        await DelegationStage(self).consume(queue_bundle)

    async def _route_delegation_result(
        self,
        queue_bundle: RuntimeQueueSet,
        parsed: ParsedHostItem,
        delegation_result: DelegationResult,
    ) -> None:
        await DelegationStage(self).route(queue_bundle, parsed, delegation_result)

    async def _host_resolution_stage_consumer(
        self, queue_bundle: RuntimeQueueSet
    ) -> None:
        """Consume host-resolution work and route review, filtered, or ip location cases."""
        await HostResolutionStage(self).consume(queue_bundle)

    async def _route_host_resolution_result(
        self,
        queue_bundle: RuntimeQueueSet,
        work_item: HostResolutionWorkItem,
        host_resolution_result: HostResolutionResult,
    ) -> None:
        await HostResolutionStage(self).route(
            queue_bundle, work_item, host_resolution_result
        )

    async def _ip_location_stage_consumer(self, queue_bundle: RuntimeQueueSet) -> None:
        """Consume ip location work and emit terminal policy results."""
        await IpLocationStage(self).consume(queue_bundle)

    def log_delegation_fanout(self, registrable_domain: str, item_count: int) -> None:
        """Log the host fanout size for one root-owned delegation result."""
        logger.debug(
            "Async pipeline delegation root fanout root=%s host_items=%d",
            registrable_domain,
            item_count,
        )

    async def _result_writer(self, queue_bundle: RuntimeQueueSet) -> None:
        """Drain terminal results into the deterministic writer buffer."""
        while True:
            result = await queue_bundle.result_queue.get()
            try:
                if result is None:
                    return
                self.writer.add(result)
            finally:
                queue_bundle.result_queue.task_done()

    def _source_contexts(self) -> list[WorkerSourceContext]:
        """Return worker source contexts for prepared or direct runtime modes."""
        return RuntimeItemLoader(
            config=self.config, prepared_metadata=self.prepared_metadata
        ).source_contexts()

    def _runtime_items(self) -> list[ParsedHostItem]:
        """Build worker-local items that seed the delegation input queue."""
        return RuntimeItemLoader(
            config=self.config, prepared_metadata=self.prepared_metadata
        ).runtime_items()

    async def _load_delegation_input(
        self, queue_bundle: RuntimeQueueSet, *, send_sentinels: bool = True
    ) -> None:
        """Seed root-level delegation input from runtime payload entries."""
        loader = RuntimeItemLoader(
            config=self.config, prepared_metadata=self.prepared_metadata
        )
        root_work_items, terminal_items = loader.delegation_work_items()
        host_item_count = sum(len(work_item.items) for work_item in root_work_items)
        logger.debug(
            "Async pipeline loader enqueueing delegation roots=%d host_items=%d "
            "terminal_items=%d",
            len(root_work_items),
            host_item_count,
            len(terminal_items),
        )
        for item in terminal_items:
            await self.put_completed(
                queue_bundle,
                item,
                pipeline_result_code=PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX,
            )
        for work_item in root_work_items:
            await queue_bundle.delegation_input.put(work_item)
        if send_sentinels:
            for _ in range(self.stage_concurrency.delegation):
                await queue_bundle.delegation_input.put(None)
            logger.debug(
                "Async pipeline loader sent delegation sentinels count=%d",
                self.stage_concurrency.delegation,
            )

    def _dns_pressure_state(
        self, groups: tuple[DNSStageCapacityGroup, ...]
    ) -> AdaptiveDNSPressureState:
        """Return stage-scoped DNS capacity and recent pressure state."""
        snapshots = DNSQueryCoordinatorRegistry.provider_capacity_snapshot(
            rate_limit_enabled=True,
            pressure_window_seconds=self.concurrency_settings.pressure_window_seconds,
        )
        return capacity_state_for_groups(groups, snapshots)

    def _adaptive_supervisor(
        self,
        *,
        stage_name: str,
        queue: asyncio.Queue[Any],
        task_factory: Any,
        minimum: int,
        cap: int,
        capacity_groups: tuple[DNSStageCapacityGroup, ...],
    ) -> AdaptiveStageSupervisor:
        """Build one adaptive supervisor for a DNS stage."""
        return AdaptiveStageSupervisor(
            stage_name=stage_name,
            queue=queue,
            task_factory=task_factory,
            busy_state=self.busy_state,
            decision_engine=AdaptiveStageDecisionEngine(
                minimum=minimum,
                cap=cap,
                scale_up_step=self.concurrency_settings.scale_up_step,
                scale_down_step=self.concurrency_settings.scale_down_step,
                busy_scale_up_after_seconds=(
                    self.concurrency_settings.busy_scale_up_after_seconds
                ),
                idle_scale_down_after_seconds=(
                    self.concurrency_settings.idle_scale_down_after_seconds
                ),
                queue_pressure_ratio=self.concurrency_settings.queue_pressure_ratio,
            ),
            interval_seconds=self.concurrency_settings.supervisor_interval_seconds,
            dns_pressure_state=lambda: self._dns_pressure_state(capacity_groups),
        )

    async def _join_or_raise(
        self,
        queue: asyncio.Queue[Any],
        watched_tasks: list[asyncio.Task[Any]] | Callable[[], list[asyncio.Task[Any]]],
    ) -> None:
        """Wait for a queue to drain while surfacing consumer task failures."""

        def current_tasks() -> list[asyncio.Task[Any]]:
            return watched_tasks() if callable(watched_tasks) else watched_tasks

        join_task = asyncio.create_task(queue.join())
        try:
            while not join_task.done():
                for task in current_tasks():
                    if not task.done() or task.cancelled():
                        continue
                    exception = task.exception()
                    if exception is not None:
                        raise exception
                active_tasks = [task for task in current_tasks() if not task.done()]
                done, _pending = await asyncio.wait(
                    [join_task, *active_tasks],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in done:
                    if task is join_task:
                        continue
                    if task.cancelled():
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
        """Drain and stop cache writers after all stage consumers have stopped."""
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
        queue_bundle = RuntimeQueueSet.create()
        logger.debug(
            "Async pipeline starting worker-local queues delegation_concurrency=%d "
            "host_resolution_concurrency=%d ip_location_concurrency=%d adaptive=%s "
            "delegation_cap=%d host_resolution_cap=%d "
            "supervisor_interval_seconds=%.3f pressure_window_seconds=%.3f "
            "queue_pressure_ratio=%.3f prepared_metadata=%s",
            self.stage_concurrency.delegation,
            self.stage_concurrency.host_resolution,
            self.stage_concurrency.ip_location,
            self.concurrency_settings.adaptive_enabled,
            self.concurrency_settings.delegation.cap,
            self.concurrency_settings.host_resolution.cap,
            self.concurrency_settings.supervisor_interval_seconds,
            self.concurrency_settings.pressure_window_seconds,
            self.concurrency_settings.queue_pressure_ratio,
            self.prepared_metadata is not None,
        )
        adaptive_enabled = self.concurrency_settings.adaptive_enabled
        ip_location_tasks = [
            asyncio.create_task(
                self._ip_location_stage_consumer(queue_bundle),
                name=f"ip-location-static-consumer-{index}",
            )
            for index in range(self.stage_concurrency.ip_location)
        ]
        result_task = asyncio.create_task(
            self._result_writer(queue_bundle), name="result-writer"
        )
        cache_tasks = [
            asyncio.create_task(writer.run(), name=f"cache-writer-{index}")
            for index, writer in enumerate(self.cache_bundle.writers)
        ]
        delegation_supervisor: AdaptiveStageSupervisor | None = None
        host_resolution_supervisor: AdaptiveStageSupervisor | None = None
        if adaptive_enabled:
            host_resolution_supervisor = self._adaptive_supervisor(
                stage_name="host-resolution",
                queue=queue_bundle.delegation_to_host_resolution,
                task_factory=lambda: self._host_resolution_stage_consumer(queue_bundle),
                minimum=self.concurrency_settings.host_resolution.minimum,
                cap=self.concurrency_settings.host_resolution.cap,
                capacity_groups=self.dns_capacity_groups.host_resolution,
            )
            delegation_supervisor = self._adaptive_supervisor(
                stage_name="delegation",
                queue=queue_bundle.delegation_input,
                task_factory=lambda: self._delegation_stage_consumer(queue_bundle),
                minimum=self.concurrency_settings.delegation.minimum,
                cap=self.concurrency_settings.delegation.cap,
                capacity_groups=self.dns_capacity_groups.delegation,
            )
            await host_resolution_supervisor.start()
            await delegation_supervisor.start()
            delegation_tasks = delegation_supervisor.tasks
            host_resolution_tasks = host_resolution_supervisor.tasks
        else:
            delegation_tasks = [
                asyncio.create_task(
                    self._delegation_stage_consumer(queue_bundle),
                    name=f"delegation-static-consumer-{index}",
                )
                for index in range(self.stage_concurrency.delegation)
            ]
            host_resolution_tasks = [
                asyncio.create_task(
                    self._host_resolution_stage_consumer(queue_bundle),
                    name=f"host-resolution-static-consumer-{index}",
                )
                for index in range(self.stage_concurrency.host_resolution)
            ]
        loader_task = asyncio.create_task(
            self._load_delegation_input(
                queue_bundle, send_sentinels=not adaptive_enabled
            ),
            name="delegation-loader",
        )
        all_tasks = [
            loader_task,
            *delegation_tasks,
            *host_resolution_tasks,
            *ip_location_tasks,
            result_task,
            *cache_tasks,
        ]
        try:
            await loader_task
            logger.debug("Async pipeline waiting for delegation_input drain")
            await self._join_or_raise(
                queue_bundle.delegation_input,
                (
                    lambda: (
                        delegation_supervisor.tasks
                        if delegation_supervisor is not None
                        else delegation_tasks
                    )
                ),
            )
            if delegation_supervisor is not None:
                await delegation_supervisor.stop_after_drain()
                delegation_tasks = delegation_supervisor.tasks
            else:
                await asyncio.gather(*delegation_tasks)
            logger.debug("Async pipeline delegation_input drained")
            if host_resolution_supervisor is None:
                for _ in range(self.stage_concurrency.host_resolution):
                    await queue_bundle.delegation_to_host_resolution.put(None)
                logger.debug(
                    "Async pipeline sent host-resolution sentinels count=%d",
                    self.stage_concurrency.host_resolution,
                )
            logger.debug(
                "Async pipeline waiting for delegation_to_host_resolution drain"
            )
            await self._join_or_raise(
                queue_bundle.delegation_to_host_resolution,
                (
                    lambda: (
                        host_resolution_supervisor.tasks
                        if host_resolution_supervisor is not None
                        else host_resolution_tasks
                    )
                ),
            )
            if host_resolution_supervisor is not None:
                await host_resolution_supervisor.stop_after_drain()
                host_resolution_tasks = host_resolution_supervisor.tasks
            else:
                await asyncio.gather(*host_resolution_tasks)
            logger.debug("Async pipeline delegation_to_host_resolution drained")
            for _ in range(self.stage_concurrency.ip_location):
                await queue_bundle.host_resolution_to_ip_location.put(None)
            logger.debug(
                "Async pipeline sent ip location sentinels count=%d",
                self.stage_concurrency.ip_location,
            )
            logger.debug(
                "Async pipeline waiting for host_resolution_to_ip_location drain"
            )
            await self._join_or_raise(
                queue_bundle.host_resolution_to_ip_location, ip_location_tasks
            )
            await asyncio.gather(*ip_location_tasks)
            logger.debug("Async pipeline host_resolution_to_ip_location drained")
            logger.debug("Async pipeline waiting for result_queue drain")
            await self._join_or_raise(queue_bundle.result_queue, [result_task])
            await queue_bundle.result_queue.put(None)
            await result_task
            logger.debug("Async pipeline result_queue drained and writer stopped")
            await self._stop_cache_writers(self.cache_bundle, cache_tasks)
            writer_result = self.writer.write()
            logger.info(
                "Pipeline emitted counts=%s cache_counts=%s outputs=%s",
                dict(writer_result.counts),
                dict(sorted(self.cache_stats.items())),
                writer_result.output_paths,
            )
            return 0
        except Exception:
            if delegation_supervisor is not None:
                await delegation_supervisor.cancel()
            if host_resolution_supervisor is not None:
                await host_resolution_supervisor.cancel()
            for task in all_tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*all_tasks, return_exceptions=True)
            raise

    def run(self) -> int:
        """Run the async DAG from synchronous callers."""
        return asyncio.run(self.run_async())


async def run_prepared_pipeline_async(
    runtime_config: dict[str, Any],
    *,
    runtime_identity: dict[str, str] | None = None,
    max_runtime_seconds: float | None = None,
    prepared_metadata: dict[str, Any] | None = None,
) -> int:
    """Run one workflow-owned runtime payload."""
    runtime = PipelineExecutor.from_runtime_payload(
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
