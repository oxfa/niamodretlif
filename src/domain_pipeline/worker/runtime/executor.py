"""Worker-local async DNS actionability runtime."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from domain_pipeline.routing import (
    InputValidationRoutingPolicy,
    TerminalRouteTransition,
)
from domain_pipeline.worker.runtime.contracts import WorkerSourceContext
from domain_pipeline.worker.cache.repository import CacheRepository
from domain_pipeline.worker.cache.service import (
    CacheBundle,
    build_cache_bundle,
)
from domain_pipeline.prepare.sources.parser import DomainEntry
from domain_pipeline.worker.delegation.lookup import DelegationResult
from domain_pipeline.worker.host_resolution.lookup import HostResolutionResult
from domain_pipeline.worker.ip_location.providers import (
    IPLocationResult,
    build_ip_location_provider,
)
from domain_pipeline.worker.output.writer import ResultOutputWriter
from domain_pipeline.worker.runtime.dns_factory import RuntimeDNSCheckerFactory
from domain_pipeline.worker.dns_query.query_coordinator import (
    DNSQueryCoordinatorState,
)
from domain_pipeline.worker.runtime.adaptive import (
    AdaptiveDNSPressureState,
    AdaptiveStageSupervisorRequest,
    AdaptiveStageDecisionEngine,
    AdaptiveStageSupervisor,
    raise_task_exception,
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
from domain_pipeline.worker.runtime.lookup_services import (
    RuntimeDNSCacheLookupService,
    RuntimeIpLocationService,
)
from domain_pipeline.worker.runtime.queues import RuntimeQueueSet
from domain_pipeline.worker.runtime.results import (
    CompletedResultRequest,
    build_completed_result,
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
class RuntimeAdaptiveTimingSettings:
    """Adaptive monitor timing settings."""

    supervisor_interval_seconds: float
    busy_scale_up_after_seconds: float
    idle_scale_down_after_seconds: float
    pressure_window_seconds: float


@dataclasses.dataclass(frozen=True)
class RuntimeAdaptiveScaleSettings:
    """Adaptive scale threshold and step settings."""

    queue_pressure_ratio: float
    scale_up_step: int
    scale_down_step: int


@dataclasses.dataclass(frozen=True)
class RuntimeStageConcurrencySettings:
    """Parsed worker-local runtime stage sizing settings."""

    delegation: RuntimeStageConcurrencyLimits
    host_resolution: RuntimeStageConcurrencyLimits
    ip_location: RuntimeStageConcurrencyLimits
    adaptive_enabled: bool
    timing: RuntimeAdaptiveTimingSettings
    scale: RuntimeAdaptiveScaleSettings


@dataclasses.dataclass(frozen=True)
class RuntimeInputContext:
    """Runtime config and optional prepared metadata for one worker."""

    config: dict[str, Any]
    prepared_metadata: dict[str, Any] | None


@dataclasses.dataclass(frozen=True)
class RuntimeCacheResources:
    """Runtime cache handles and counters."""

    bundle: CacheBundle
    stats: Counter[str] = dataclasses.field(default_factory=Counter)

    @property
    def reader(self) -> Any:
        """Return the cache reader facade."""
        return self.bundle.reader


@dataclasses.dataclass(frozen=True)
class RuntimeWorkerResources:
    """Runtime-owned cache and output writer resources."""

    cache: RuntimeCacheResources
    writer: ResultOutputWriter
    dns_coordinator_state: DNSQueryCoordinatorState


@dataclasses.dataclass(frozen=True)
class RuntimeStageSettings:
    """Runtime stage sizing and DNS capacity settings."""

    concurrency: RuntimeStageConcurrencyCounts
    adaptive: RuntimeStageConcurrencySettings
    dns_capacity_groups: RuntimeDNSCapacityGroups
    host_resolution_stage_enabled: bool


@dataclasses.dataclass(frozen=True)
class RuntimeDNSExecutors:
    """Thread executors used by blocking DNS transports."""

    delegation: ThreadPoolExecutor
    host_resolution: ThreadPoolExecutor

    def close(self) -> None:
        """Request nonblocking shutdown for DNS executor pools."""
        self.delegation.shutdown(wait=False, cancel_futures=True)
        self.host_resolution.shutdown(wait=False, cancel_futures=True)


@dataclasses.dataclass(frozen=True)
class RuntimeLookupServices:
    """Runtime lookup service bundle."""

    dns_cache: RuntimeDNSCacheLookupService
    ip_location: RuntimeIpLocationService


@dataclasses.dataclass(frozen=True)
class RuntimeAdaptiveSupervisorBuildRequest:
    """Inputs needed to build one adaptive DNS-stage supervisor."""

    stage_name: str
    queue: asyncio.Queue[Any]
    task_factory: Any
    limits: RuntimeStageConcurrencyLimits
    capacity_groups: tuple[DNSStageCapacityGroup, ...]


@dataclasses.dataclass
class RuntimeStageSupervisors:
    """Adaptive supervisors for DNS-backed stages."""

    delegation: AdaptiveStageSupervisor | None = None
    host_resolution: AdaptiveStageSupervisor | None = None


@dataclasses.dataclass
class RuntimeRunTasks:
    """Async tasks and supervisors owned by one runtime run."""

    loader_task: asyncio.Task[None]
    delegation_tasks: list[asyncio.Task[Any]]
    host_resolution_tasks: list[asyncio.Task[Any]]
    ip_location_tasks: list[asyncio.Task[Any]]
    result_task: asyncio.Task[Any]
    cache_tasks: list[asyncio.Task[Any]]
    supervisors: RuntimeStageSupervisors = dataclasses.field(
        default_factory=RuntimeStageSupervisors
    )

    def all_tasks(self) -> list[asyncio.Task[Any]]:
        """Return every task that may need cancellation on runtime failure."""
        return [
            self.loader_task,
            *self.delegation_tasks,
            *self.host_resolution_tasks,
            *self.ip_location_tasks,
            self.result_task,
            *self.cache_tasks,
        ]


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
        timing=RuntimeAdaptiveTimingSettings(
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
        ),
        scale=RuntimeAdaptiveScaleSettings(
            queue_pressure_ratio=float(adaptive.get("queue_pressure_ratio", 0.8)),
            scale_up_step=int(adaptive.get("scale_up_step", 1)),
            scale_down_step=int(adaptive.get("scale_down_step", 1)),
        ),
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


def _runtime_host_resolution_stage_enabled(
    config: dict[str, Any],
    *,
    prepared_metadata: dict[str, Any] | None,
) -> bool:
    """Return whether any active source enables host-resolution work."""
    loader = RuntimeItemLoader(config=config, prepared_metadata=prepared_metadata)
    return any(
        bool(source_context.config["host_resolution"].get("enabled", False))
        for source_context in loader.source_contexts()
    )


class PipelineExecutor:
    """Worker-local async DAG for prepared and config-sourced runtime payloads."""

    def __init__(
        self,
        config: dict[str, Any],
        *,
        prepared_metadata: dict[str, Any] | None = None,
    ) -> None:
        self._input_context = RuntimeInputContext(
            config=config,
            prepared_metadata=prepared_metadata,
        )
        cache_payload = runtime_cache_payload(config)
        cache_file = str(cache_payload.get("cache_file", "")).strip()
        cache_path = Path(cache_file)
        baseline_cache_file = str(cache_payload.get("baseline_cache_file", "")).strip()
        baseline_cache_path = Path(baseline_cache_file) if baseline_cache_file else None
        cache = CacheRepository.load(cache_path)
        cache.close()
        cache_bundle = build_cache_bundle(
            cache_path,
            baseline_cache_path=baseline_cache_path,
        )
        self._resources = RuntimeWorkerResources(
            cache=RuntimeCacheResources(bundle=cache_bundle),
            writer=ResultOutputWriter(),
            dns_coordinator_state=DNSQueryCoordinatorState(),
        )
        stage_concurrency = _runtime_stage_concurrency_counts(config)
        concurrency_settings = _runtime_stage_concurrency_settings(config)
        self._stage_settings = RuntimeStageSettings(
            concurrency=stage_concurrency,
            adaptive=concurrency_settings,
            dns_capacity_groups=_runtime_dns_capacity_groups(
                config,
                prepared_metadata=prepared_metadata,
            ),
            host_resolution_stage_enabled=_runtime_host_resolution_stage_enabled(
                config,
                prepared_metadata=prepared_metadata,
            ),
        )
        self._dns_executors = RuntimeDNSExecutors(
            delegation=ThreadPoolExecutor(
                max_workers=self.concurrency_settings.delegation.cap,
                thread_name_prefix="dns-delegation",
            ),
            host_resolution=ThreadPoolExecutor(
                max_workers=self.concurrency_settings.host_resolution.cap,
                thread_name_prefix="dns-host-resolution",
            ),
        )
        self.busy_state = BusyStateRecorder()
        self._lookup_services = RuntimeLookupServices(
            dns_cache=RuntimeDNSCacheLookupService(
                config=config,
                cache_resources=self._resources.cache,
                dns_executors=self._dns_executors,
                busy_state=self.busy_state,
            ),
            ip_location=RuntimeIpLocationService(
                cache_resources=self._resources.cache,
                provider_builder=build_ip_location_provider,
            ),
        )
        self._delegation_tasks: dict[
            tuple[str, str], asyncio.Task[DelegationResult]
        ] = {}

    @property
    def config(self) -> dict[str, Any]:
        """Return this worker's runtime config payload."""
        return self._input_context.config

    @property
    def prepared_metadata(self) -> dict[str, Any] | None:
        """Return optional prepared worker metadata."""
        return self._input_context.prepared_metadata

    @property
    def cache_bundle(self) -> CacheBundle:
        """Return runtime cache writer and reader resources."""
        return self._resources.cache.bundle

    @property
    def cache_stats(self) -> Counter[str]:
        """Return mutable runtime cache counters."""
        return self._resources.cache.stats

    @property
    def stage_concurrency(self) -> RuntimeStageConcurrencyCounts:
        """Return static stage concurrency counts."""
        return self._stage_settings.concurrency

    @property
    def concurrency_settings(self) -> RuntimeStageConcurrencySettings:
        """Return adaptive stage concurrency settings."""
        return self._stage_settings.adaptive

    @property
    def dns_capacity_groups(self) -> RuntimeDNSCapacityGroups:
        """Return DNS capacity groups used by adaptive supervisors."""
        return self._stage_settings.dns_capacity_groups

    @classmethod
    def from_runtime_payload(
        cls,
        runtime_config: dict[str, Any],
        *,
        prepared_metadata: dict[str, Any] | None = None,
    ) -> "PipelineExecutor":
        """Build a runtime from a manifest-owned payload."""
        return cls(
            runtime_config,
            prepared_metadata=prepared_metadata,
        )

    def close(self) -> None:
        """Close runtime resources."""
        logger.debug(
            "Runtime DNS executors shutdown requested wait=False "
            "cancel_futures=True; running DNS calls may continue"
        )
        self._dns_executors.close()

    async def lookup_delegation_root(
        self, source_context: WorkerSourceContext, registrable_domain: str
    ) -> DelegationResult:
        """Run or join one root-level delegation lookup."""
        checker = RuntimeDNSCheckerFactory(
            coordinator_state=self._resources.dns_coordinator_state
        ).build(source_context.config)
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
        return await self._lookup_services.dns_cache.lookup_delegation_root_once(
            checker=checker,
            registrable_domain=registrable_domain,
            resolver_key=resolver_key,
        )

    async def lookup_host_resolution(
        self, source_context: WorkerSourceContext, entry: DomainEntry
    ) -> HostResolutionResult:
        """Run or cache-read the optional host_resolution stage."""
        checker = RuntimeDNSCheckerFactory(
            coordinator_state=self._resources.dns_coordinator_state
        ).build(source_context.config)
        return await self._lookup_services.dns_cache.lookup_host_resolution(
            checker=checker,
            host=entry.host,
            resolver_key=checker.host_resolution_resolver_key(),
        )

    async def lookup_ip_location(
        self,
        source_context: WorkerSourceContext,
        host_resolution_result: HostResolutionResult,
    ) -> tuple[TerminalRouteTransition, list[IPLocationResult], Any | None]:
        """Run or cache-read the optional IP-location stage and evaluate its policy."""
        return await self._lookup_services.ip_location.lookup_ip_location(
            ip_location_config=source_context.config["ip_location"],
            host_resolution_result=host_resolution_result,
        )

    async def put_completed(
        self,
        queue_bundle: RuntimeQueueSet,
        request: CompletedResultRequest,
    ) -> None:
        """Emit one terminal runtime result to the shared result queue."""
        async with self.busy_state.track(BusyReason.RESULT_PUT):
            await queue_bundle.result_queue.put(build_completed_result(request))

    async def _delegation_stage_consumer(self, queue_bundle: RuntimeQueueSet) -> None:
        """Consume worker-local delegation input and route each result."""
        await DelegationStage(self).consume(queue_bundle)

    async def _host_resolution_stage_consumer(
        self, queue_bundle: RuntimeQueueSet
    ) -> None:
        """Consume host-resolution work and route review, filtered, or IP-location cases."""
        await HostResolutionStage(self).consume(queue_bundle)

    async def _ip_location_stage_consumer(self, queue_bundle: RuntimeQueueSet) -> None:
        """Consume IP-location work and emit terminal policy results."""
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
                self._resources.writer.add(result)
            finally:
                queue_bundle.result_queue.task_done()

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
                CompletedResultRequest(
                    source_context=item.source_context,
                    entry=item.entry,
                    route_transition=InputValidationRoutingPolicy().public_suffix(),
                    source_id=item.output_source.source_id,
                    source_input_label=item.output_source.input_label,
                ),
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
        snapshots = self._resources.dns_coordinator_state.provider_capacity_snapshot(
            rate_limit_enabled=True,
            pressure_window_seconds=self.concurrency_settings.timing.pressure_window_seconds,
        )
        return capacity_state_for_groups(groups, snapshots)

    def _adaptive_supervisor(
        self,
        request: RuntimeAdaptiveSupervisorBuildRequest,
    ) -> AdaptiveStageSupervisor:
        """Build one adaptive supervisor for a DNS stage."""
        return AdaptiveStageSupervisor(
            AdaptiveStageSupervisorRequest(
                stage_name=request.stage_name,
                queue=request.queue,
                task_factory=request.task_factory,
                busy_state=self.busy_state,
                decision_engine=AdaptiveStageDecisionEngine(
                    minimum=request.limits.minimum,
                    cap=request.limits.cap,
                    scale_up_step=self.concurrency_settings.scale.scale_up_step,
                    scale_down_step=self.concurrency_settings.scale.scale_down_step,
                    busy_scale_up_after_seconds=(
                        self.concurrency_settings.timing.busy_scale_up_after_seconds
                    ),
                    idle_scale_down_after_seconds=(
                        self.concurrency_settings.timing.idle_scale_down_after_seconds
                    ),
                    queue_pressure_ratio=(
                        self.concurrency_settings.scale.queue_pressure_ratio
                    ),
                ),
                interval_seconds=(
                    self.concurrency_settings.timing.supervisor_interval_seconds
                ),
                dns_pressure_state=lambda: self._dns_pressure_state(
                    request.capacity_groups
                ),
            )
        )

    async def join_or_raise(
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
                    raise_task_exception(task)
                active_tasks = [task for task in current_tasks() if not task.done()]
                done, _pending = await asyncio.wait(
                    [join_task, *active_tasks],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in done:
                    if task is join_task:
                        continue
                    raise_task_exception(task)
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
            await writer.join()
        logger.debug(
            "Async pipeline stopping cache writers count=%d", len(cache_bundle.writers)
        )
        for writer in cache_bundle.writers:
            await writer.enqueue(None)
        await asyncio.gather(*cache_tasks)
        logger.debug("Async pipeline cache writers stopped")

    def _log_run_start(self) -> None:
        """Log queue and adaptive settings for one runtime run."""
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
            self.concurrency_settings.timing.supervisor_interval_seconds,
            self.concurrency_settings.timing.pressure_window_seconds,
            self.concurrency_settings.scale.queue_pressure_ratio,
            self.prepared_metadata is not None,
        )

    async def _start_runtime_tasks(
        self, queue_bundle: RuntimeQueueSet
    ) -> RuntimeRunTasks:
        """Start stage consumers, result writer, cache writers, and loader."""
        adaptive_enabled = self.concurrency_settings.adaptive_enabled
        host_stage_enabled = self._stage_settings.host_resolution_stage_enabled
        delegation_uses_adaptive = (
            adaptive_enabled and self.concurrency_settings.delegation.enabled
        )
        host_uses_adaptive = (
            adaptive_enabled
            and self.concurrency_settings.host_resolution.enabled
            and host_stage_enabled
        )
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
        if delegation_uses_adaptive:
            delegation_supervisor: AdaptiveStageSupervisor | None = (
                self._adaptive_supervisor(
                    RuntimeAdaptiveSupervisorBuildRequest(
                        stage_name="delegation",
                        queue=queue_bundle.delegation_input,
                        task_factory=lambda: self._delegation_stage_consumer(
                            queue_bundle
                        ),
                        limits=self.concurrency_settings.delegation,
                        capacity_groups=self.dns_capacity_groups.delegation,
                    )
                )
            )
            await delegation_supervisor.start()
            delegation_tasks = delegation_supervisor.tasks
        else:
            delegation_supervisor = None
            delegation_tasks = [
                asyncio.create_task(
                    self._delegation_stage_consumer(queue_bundle),
                    name=f"delegation-static-consumer-{index}",
                )
                for index in range(self.stage_concurrency.delegation)
            ]

        if not host_stage_enabled:
            logger.debug(
                "Adaptive stage disabled stage=host-resolution "
                "reason=stage_config_disabled"
            )
            host_resolution_supervisor = None
            host_resolution_tasks: list[asyncio.Task[Any]] = []
        elif host_uses_adaptive:
            host_resolution_supervisor = self._adaptive_supervisor(
                RuntimeAdaptiveSupervisorBuildRequest(
                    stage_name="host-resolution",
                    queue=queue_bundle.delegation_to_host_resolution,
                    task_factory=lambda: self._host_resolution_stage_consumer(
                        queue_bundle
                    ),
                    limits=self.concurrency_settings.host_resolution,
                    capacity_groups=self.dns_capacity_groups.host_resolution,
                )
            )
            await host_resolution_supervisor.start()
            host_resolution_tasks = host_resolution_supervisor.tasks
        else:
            host_resolution_supervisor = None
            host_resolution_tasks = [
                asyncio.create_task(
                    self._host_resolution_stage_consumer(queue_bundle),
                    name=f"host-resolution-static-consumer-{index}",
                )
                for index in range(self.stage_concurrency.host_resolution)
            ]
        loader_task = asyncio.create_task(
            self._load_delegation_input(
                queue_bundle, send_sentinels=not delegation_uses_adaptive
            ),
            name="delegation-loader",
        )
        return RuntimeRunTasks(
            loader_task=loader_task,
            delegation_tasks=delegation_tasks,
            host_resolution_tasks=host_resolution_tasks,
            ip_location_tasks=ip_location_tasks,
            result_task=result_task,
            cache_tasks=cache_tasks,
            supervisors=RuntimeStageSupervisors(
                delegation=delegation_supervisor,
                host_resolution=host_resolution_supervisor,
            ),
        )

    async def _drain_delegation_stage(
        self, queue_bundle: RuntimeQueueSet, tasks: RuntimeRunTasks
    ) -> None:
        logger.debug("Async pipeline waiting for delegation_input drain")
        await self.join_or_raise(
            queue_bundle.delegation_input,
            (
                lambda: (
                    tasks.supervisors.delegation.tasks
                    if tasks.supervisors.delegation is not None
                    else tasks.delegation_tasks
                )
            ),
        )
        if tasks.supervisors.delegation is not None:
            await tasks.supervisors.delegation.stop_after_drain()
            tasks.delegation_tasks = tasks.supervisors.delegation.tasks
        else:
            await asyncio.gather(*tasks.delegation_tasks)
        logger.debug("Async pipeline delegation_input drained")

    async def _drain_host_resolution_stage(
        self, queue_bundle: RuntimeQueueSet, tasks: RuntimeRunTasks
    ) -> None:
        if not self._stage_settings.host_resolution_stage_enabled:
            if queue_bundle.delegation_to_host_resolution.qsize():
                raise RuntimeError(
                    "host resolution disabled but host queue received work"
                )
            logger.debug(
                "Async pipeline host-resolution stage disabled; "
                "no queue consumers to drain"
            )
            return
        if tasks.supervisors.host_resolution is None:
            for _ in tasks.host_resolution_tasks:
                await queue_bundle.delegation_to_host_resolution.put(None)
            logger.debug(
                "Async pipeline sent host-resolution sentinels count=%d",
                len(tasks.host_resolution_tasks),
            )
        logger.debug("Async pipeline waiting for delegation_to_host_resolution drain")
        await self.join_or_raise(
            queue_bundle.delegation_to_host_resolution,
            (
                lambda: (
                    tasks.supervisors.host_resolution.tasks
                    if tasks.supervisors.host_resolution is not None
                    else tasks.host_resolution_tasks
                )
            ),
        )
        if tasks.supervisors.host_resolution is not None:
            await tasks.supervisors.host_resolution.stop_after_drain()
            tasks.host_resolution_tasks = tasks.supervisors.host_resolution.tasks
        else:
            await asyncio.gather(*tasks.host_resolution_tasks)
        logger.debug("Async pipeline delegation_to_host_resolution drained")

    async def _drain_ip_location_stage(
        self, queue_bundle: RuntimeQueueSet, tasks: RuntimeRunTasks
    ) -> None:
        for _ in range(self.stage_concurrency.ip_location):
            await queue_bundle.host_resolution_to_ip_location.put(None)
        logger.debug(
            "Async pipeline sent ip location sentinels count=%d",
            self.stage_concurrency.ip_location,
        )
        logger.debug("Async pipeline waiting for host_resolution_to_ip_location drain")
        await self.join_or_raise(
            queue_bundle.host_resolution_to_ip_location, tasks.ip_location_tasks
        )
        await asyncio.gather(*tasks.ip_location_tasks)
        logger.debug("Async pipeline host_resolution_to_ip_location drained")

    async def _drain_result_queue(
        self, queue_bundle: RuntimeQueueSet, result_task: asyncio.Task[Any]
    ) -> None:
        logger.debug("Async pipeline waiting for result_queue drain")
        await self.join_or_raise(queue_bundle.result_queue, [result_task])
        await queue_bundle.result_queue.put(None)
        await result_task
        logger.debug("Async pipeline result_queue drained and writer stopped")

    async def _cancel_runtime_tasks(self, tasks: RuntimeRunTasks) -> None:
        if tasks.supervisors.delegation is not None:
            await tasks.supervisors.delegation.cancel()
        if tasks.supervisors.host_resolution is not None:
            await tasks.supervisors.host_resolution.cancel()
        for task in tasks.all_tasks():
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks.all_tasks(), return_exceptions=True)

    async def _drain_runtime(
        self, queue_bundle: RuntimeQueueSet, tasks: RuntimeRunTasks
    ) -> None:
        await tasks.loader_task
        await self._drain_delegation_stage(queue_bundle, tasks)
        await self._drain_host_resolution_stage(queue_bundle, tasks)
        await self._drain_ip_location_stage(queue_bundle, tasks)
        await self._drain_result_queue(queue_bundle, tasks.result_task)
        await self._stop_cache_writers(self.cache_bundle, tasks.cache_tasks)

    async def run_async(self) -> int:
        """Run the prepared or config-sourced pipeline through async stage queues."""
        queue_bundle = RuntimeQueueSet.create()
        self._log_run_start()
        tasks = await self._start_runtime_tasks(queue_bundle)
        try:
            await self._drain_runtime(queue_bundle, tasks)
            writer_result = self._resources.writer.write()
            logger.info(
                "Pipeline emitted counts=%s cache_counts=%s outputs=%s",
                dict(writer_result.counts),
                dict(sorted(self.cache_stats.items())),
                writer_result.output_paths,
            )
            return 0
        except Exception:
            await self._cancel_runtime_tasks(tasks)
            raise

    def run(self) -> int:
        """Run the async DAG from synchronous callers."""
        return asyncio.run(self.run_async())


async def run_prepared_pipeline_async(
    runtime_config: dict[str, Any],
    *,
    max_runtime_seconds: float | None = None,
    prepared_metadata: dict[str, Any] | None = None,
) -> int:
    """Run one workflow-owned runtime payload."""
    runtime = PipelineExecutor.from_runtime_payload(
        runtime_config,
        prepared_metadata=prepared_metadata,
    )
    try:
        if max_runtime_seconds is None:
            return await runtime.run_async()
        return await asyncio.wait_for(runtime.run_async(), timeout=max_runtime_seconds)
    finally:
        runtime.close()
