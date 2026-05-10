"""Adaptive stage concurrency decision helpers."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import time
from collections import Counter
from collections.abc import Callable, Coroutine
from typing import Any

from domain_pipeline.worker.runtime.busy_state import (
    BusyReason,
    BusyStateRecorder,
    BusyStateSnapshot,
    busy_reason_allows_scale_up,
)

logger = logging.getLogger(__name__)

BLOCKER_LOG_INTERVAL_SECONDS = 30.0


def raise_task_exception(task: asyncio.Task[Any]) -> None:
    """Raise an exception from one completed task when it failed."""
    if not task.done() or task.cancelled():
        return
    exception = task.exception()
    if exception is not None:
        raise exception


@dataclasses.dataclass(frozen=True)
class AdaptiveStageDecision:
    """One adaptive supervisor scale decision."""

    scale_up: int
    scale_down: int
    reason: str


@dataclasses.dataclass(frozen=True)
# Adaptive decisions need these scalar fields in debug logs and tests.
# pylint: disable=too-many-instance-attributes
class AdaptiveDNSPressureState:
    """Stage-scoped DNS provider capacity state used by adaptive decisions."""

    any_provider_pressure: bool = False
    stage_pressure: bool = False
    capacity_available: bool = True
    provider_count: int = 0
    usable_provider_count: int = 0
    pressured_provider_count: int = 0
    constrained_provider_count: int = 0
    usable_parallelism: int | None = None
    summary: str = "unlimited"


@dataclasses.dataclass(frozen=True)
# Snapshot fields intentionally mirror the decision inputs instead of hiding
# blockers inside an opaque mapping.
# pylint: disable=too-many-instance-attributes
class AdaptiveDecisionSnapshot:
    """Current stage state inspected by the adaptive decision engine."""

    now: float
    active_count: int
    backlog: int
    consumer_states: tuple[BusyStateSnapshot, ...]
    dns_capacity_available: bool = True
    dns_stage_pressure: bool = False
    dns_any_provider_pressure: bool = False
    dns_usable_parallelism: int | None = None


@dataclasses.dataclass(frozen=True)
class AdaptiveStageDecisionEngine:
    """Pure scale decision logic for one adaptive runtime stage."""

    minimum: int
    cap: int
    scale_up_step: int
    scale_down_step: int
    busy_scale_up_after_seconds: float
    idle_scale_down_after_seconds: float
    queue_pressure_ratio: float = 0.8

    def decide(self, snapshot: AdaptiveDecisionSnapshot) -> AdaptiveStageDecision:
        """Return the next scale decision for the current stage snapshot."""
        if snapshot.active_count > self.minimum:
            scale_down = self._scale_down_count(snapshot)
            if scale_down:
                reason = "dns_stage_pressure" if snapshot.dns_stage_pressure else "idle"
                return AdaptiveStageDecision(0, scale_down, reason)
        blocker = self._scale_up_blocker(snapshot)
        if blocker is not None:
            return AdaptiveStageDecision(0, 0, blocker)
        scale_up = min(
            self.scale_up_step,
            self._target_active_count(snapshot) - snapshot.active_count,
        )
        if scale_up:
            return AdaptiveStageDecision(scale_up, 0, "busy")
        return AdaptiveStageDecision(0, 0, "stable")

    def _target_active_count(self, snapshot: AdaptiveDecisionSnapshot) -> int:
        """Return the DNS-capacity-bounded active consumer target."""
        if snapshot.dns_usable_parallelism is None:
            return self.cap
        return min(self.cap, max(self.minimum, snapshot.dns_usable_parallelism))

    def _scale_up_blocker(self, snapshot: AdaptiveDecisionSnapshot) -> str | None:
        """Return the stable reason scale-up is blocked, if any."""
        reason = None
        if snapshot.backlog <= 0:
            reason = "queue_empty"
        elif snapshot.dns_stage_pressure:
            reason = "dns_stage_pressure"
        elif not snapshot.dns_capacity_available:
            reason = "dns_capacity_unavailable"
        elif snapshot.active_count >= self._target_active_count(snapshot):
            reason = "at_dns_parallelism_target"
        elif (
            snapshot.active_count <= 0
            or snapshot.backlog / snapshot.active_count < self.queue_pressure_ratio
        ):
            reason = "below_queue_pressure_ratio"
        elif len(snapshot.consumer_states) < snapshot.active_count:
            reason = "busy_state_ineligible"
        else:
            for state in snapshot.consumer_states:
                if not busy_reason_allows_scale_up(state.reason):
                    reason = "busy_state_ineligible"
                    break
                if (
                    snapshot.now - state.reason_started_at
                    < self.busy_scale_up_after_seconds
                ):
                    reason = "busy_duration_insufficient"
                    break
        return reason

    def _scale_down_count(self, snapshot: AdaptiveDecisionSnapshot) -> int:
        """Return idle consumer retirement count for this tick."""
        if snapshot.backlog > 0 and not snapshot.dns_stage_pressure:
            return 0
        idle_count = 0
        for state in snapshot.consumer_states:
            if state.reason != BusyReason.QUEUE_WAIT:
                continue
            if (
                snapshot.now - state.reason_started_at
                >= self.idle_scale_down_after_seconds
            ):
                idle_count += 1
        surplus = max(snapshot.active_count - self.minimum, 0)
        return min(self.scale_down_step, surplus, idle_count)


@dataclasses.dataclass(frozen=True)
class AdaptiveStageSupervisorRequest:
    """Construction inputs for one adaptive stage supervisor."""

    stage_name: str
    queue: asyncio.Queue[object]
    task_factory: Callable[[], Coroutine[Any, Any, None]]
    busy_state: BusyStateRecorder
    decision_engine: AdaptiveStageDecisionEngine
    interval_seconds: float
    dns_pressure_state: Callable[[], AdaptiveDNSPressureState]


@dataclasses.dataclass
# Handles and counters are kept together so the supervisor can log one summary.
# pylint: disable=too-many-instance-attributes
class AdaptiveStageSupervisorState:
    """Mutable task counters and task handles owned by a supervisor."""

    tasks: list[asyncio.Task[None]] = dataclasses.field(default_factory=list)
    monitor_task: asyncio.Task[None] | None = None
    created: int = 0
    retired: int = 0
    max_active: int = 0
    ticks: int = 0
    scale_up_decisions: int = 0
    scale_down_decisions: int = 0
    blocked_decisions: Counter[str] = dataclasses.field(default_factory=Counter)
    last_logged_blocker: str | None = None
    last_blocker_log_at: float = 0.0


class AdaptiveStageSupervisor:
    """Own adaptive asyncio consumer creation and idle retirement for one stage."""

    def __init__(self, request: AdaptiveStageSupervisorRequest) -> None:
        self.request = request
        self.state = AdaptiveStageSupervisorState()

    @property
    def stage_name(self) -> str:
        """Return the stage name used in task names and logs."""
        return self.request.stage_name

    @property
    def queue(self) -> asyncio.Queue[object]:
        """Return the stage input queue."""
        return self.request.queue

    @property
    def task_factory(self) -> Callable[[], Coroutine[Any, Any, None]]:
        """Return the consumer task factory."""
        return self.request.task_factory

    @property
    def busy_state(self) -> BusyStateRecorder:
        """Return the shared busy-state recorder."""
        return self.request.busy_state

    @property
    def decision_engine(self) -> AdaptiveStageDecisionEngine:
        """Return the stage decision engine."""
        return self.request.decision_engine

    @property
    def interval_seconds(self) -> float:
        """Return the monitor interval."""
        return self.request.interval_seconds

    @property
    def dns_pressure_state(self) -> Callable[[], AdaptiveDNSPressureState]:
        """Return the DNS pressure-state callback."""
        return self.request.dns_pressure_state

    @property
    def tasks(self) -> list[asyncio.Task[None]]:
        """Return active and completed consumer tasks owned by the supervisor."""
        return list(self.state.tasks)

    async def start(self) -> None:
        """Start minimum consumers and the monitor loop."""
        logger.debug(
            "Adaptive stage starting stage=%s minimum=%d cap=%d "
            "interval_seconds=%.3f",
            self.stage_name,
            self.decision_engine.minimum,
            self.decision_engine.cap,
            self.interval_seconds,
        )
        for _ in range(self.decision_engine.minimum):
            self.create_consumer(reason="startup")
        self.state.monitor_task = asyncio.create_task(
            self._monitor(), name=f"{self.stage_name}-adaptive-monitor"
        )

    async def stop_after_drain(self) -> None:
        """Stop monitor, send one sentinel per active consumer, and wait for exit."""
        if self.state.monitor_task is not None:
            self.state.monitor_task.cancel()
            await asyncio.gather(self.state.monitor_task, return_exceptions=True)
        self.raise_consumer_failures()
        active_tasks = [task for task in self.state.tasks if not task.done()]
        for _ in active_tasks:
            await self.queue.put(None)
        if active_tasks:
            await asyncio.gather(*active_tasks)
        self.raise_consumer_failures()
        self._forget_completed()
        logger.debug(
            "Adaptive stage summary stage=%s created=%d retired=%d max_active=%d "
            "ticks=%d scale_up_decisions=%d scale_down_decisions=%d "
            "blocked_decisions=%s",
            self.stage_name,
            self.state.created,
            self.state.retired,
            self.state.max_active,
            self.state.ticks,
            self.state.scale_up_decisions,
            self.state.scale_down_decisions,
            dict(self.state.blocked_decisions),
        )

    async def cancel(self) -> None:
        """Cancel monitor and all consumers."""
        tasks: list[asyncio.Task[None]] = []
        if self.state.monitor_task is not None:
            tasks.append(self.state.monitor_task)
        tasks.extend(task for task in self.state.tasks if not task.done())
        for task in tasks:
            self.busy_state.mark_stopping(task)
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._forget_completed()

    def raise_consumer_failures(self) -> None:
        """Raise the first completed consumer exception, including retired tasks."""
        for task in self.state.tasks:
            raise_task_exception(task)

    def create_consumer(self, *, reason: str = "manual") -> None:
        """Create one stage consumer task."""
        self.state.created += 1
        task = asyncio.create_task(
            self.task_factory(),
            name=f"{self.stage_name}-adaptive-consumer-{self.state.created}",
        )
        self.state.tasks.append(task)
        self.state.max_active = max(self.state.max_active, len(self._active_tasks()))
        logger.debug(
            "Adaptive stage consumer created stage=%s reason=%s task=%s "
            "active=%d created=%d",
            self.stage_name,
            reason,
            task.get_name(),
            len(self._active_tasks()),
            self.state.created,
        )

    async def _monitor(self) -> None:
        """Periodically apply adaptive scale decisions."""
        while True:
            await asyncio.sleep(self.interval_seconds)
            self.raise_consumer_failures()
            self._forget_completed()
            active_tasks = self._active_tasks()
            now = time.monotonic()
            snapshots = self.stage_snapshots()
            pressure = self.dns_pressure_state()
            self.state.ticks += 1
            decision = self.decision_engine.decide(
                AdaptiveDecisionSnapshot(
                    now=now,
                    active_count=len(active_tasks),
                    backlog=self.queue.qsize(),
                    consumer_states=snapshots,
                    dns_capacity_available=pressure.capacity_available,
                    dns_stage_pressure=pressure.stage_pressure,
                    dns_any_provider_pressure=pressure.any_provider_pressure,
                    dns_usable_parallelism=pressure.usable_parallelism,
                )
            )
            self._record_decision(decision)
            for _ in range(decision.scale_up):
                self.create_consumer(reason=decision.reason)
            if decision.scale_down:
                self._retire_idle_consumers(decision.scale_down, reason=decision.reason)
            self.log_decision(
                decision,
                busy_seconds=self._busy_seconds(snapshots, now),
                idle_seconds=self._idle_seconds(snapshots, now),
                pressure_summary=pressure.summary,
                usable_parallelism=pressure.usable_parallelism,
                now=now,
            )

    def _retire_idle_consumers(self, count: int, *, reason: str) -> None:
        """Cancel idle queue-waiting consumers only."""
        snapshots = {
            snapshot.task_name: snapshot for snapshot in self.stage_snapshots()
        }
        retired = 0
        for task in self._active_tasks():
            snapshot = snapshots.get(task.get_name())
            if snapshot is None or snapshot.reason != BusyReason.QUEUE_WAIT:
                continue
            self.busy_state.mark_stopping(task)
            task.cancel()
            self.state.retired += 1
            retired += 1
            logger.debug(
                "Adaptive stage consumer retired stage=%s reason=%s task=%s "
                "active=%d retired=%d backlog=%d",
                self.stage_name,
                reason,
                task.get_name(),
                len(self._active_tasks()),
                self.state.retired,
                self.queue.qsize(),
            )
            if retired >= count:
                break

    def _record_decision(self, decision: AdaptiveStageDecision) -> None:
        """Update per-supervisor decision counters for final summaries."""
        if decision.scale_up:
            self.state.scale_up_decisions += 1
            return
        if decision.scale_down:
            self.state.scale_down_decisions += 1
            return
        if self._is_blocked_reason(decision.reason):
            self.state.blocked_decisions[decision.reason] += 1

    def log_decision(  # pylint: disable=too-many-arguments
        self,
        decision: AdaptiveStageDecision,
        *,
        busy_seconds: float,
        idle_seconds: float,
        pressure_summary: str = "",
        usable_parallelism: int | None = None,
        now: float | None = None,
    ) -> None:
        """Log operator context for one non-stable adaptive decision."""
        pressure = pressure_summary or "unreported"
        parallelism = (
            "unlimited" if usable_parallelism is None else str(usable_parallelism)
        )
        if decision.scale_up:
            logger.debug(
                "Adaptive stage scale-up stage=%s reason=%s created=%d active=%d "
                "min=%d cap=%d backlog=%d busy_seconds=%.3f pressure=%s",
                self.stage_name,
                decision.reason,
                decision.scale_up,
                len(self._active_tasks()),
                self.decision_engine.minimum,
                self.decision_engine.cap,
                self.queue.qsize(),
                busy_seconds,
                pressure,
            )
        if decision.scale_down:
            logger.debug(
                "Adaptive stage scale-down stage=%s reason=%s retired=%d active=%d "
                "min=%d cap=%d backlog=%d idle_seconds=%.3f pressure=%s",
                self.stage_name,
                decision.reason,
                decision.scale_down,
                len(self._active_tasks()),
                self.decision_engine.minimum,
                self.decision_engine.cap,
                self.queue.qsize(),
                idle_seconds,
                pressure,
            )
        if self._is_blocked_reason(decision.reason) and self._should_log_blocker(
            decision.reason, time.monotonic() if now is None else now
        ):
            logger.debug(
                "Adaptive stage decision stage=%s action=blocked reason=%s "
                "active=%d min=%d cap=%d backlog=%d busy_seconds=%.3f "
                "idle_seconds=%.3f usable_parallelism=%s pressure=%s",
                self.stage_name,
                decision.reason,
                len(self._active_tasks()),
                self.decision_engine.minimum,
                self.decision_engine.cap,
                self.queue.qsize(),
                busy_seconds,
                idle_seconds,
                parallelism,
                pressure,
            )

    @staticmethod
    def _is_blocked_reason(reason: str) -> bool:
        """Return whether a zero-action decision is operator-relevant blockage."""
        return reason not in {"stable", "queue_empty", "idle", "busy"}

    def _should_log_blocker(self, reason: str, now: float) -> bool:
        """Return whether a blocked decision should be logged this tick."""
        if self.state.last_logged_blocker != reason:
            self.state.last_logged_blocker = reason
            self.state.last_blocker_log_at = now
            return True
        if now - self.state.last_blocker_log_at >= BLOCKER_LOG_INTERVAL_SECONDS:
            self.state.last_blocker_log_at = now
            return True
        return False

    def _busy_seconds(
        self, snapshots: tuple[BusyStateSnapshot, ...], now: float
    ) -> float:
        """Return the shortest eligible busy age in the current snapshot."""
        ages = [
            now - snapshot.reason_started_at
            for snapshot in snapshots
            if busy_reason_allows_scale_up(snapshot.reason)
        ]
        return max(min(ages), 0.0) if ages else 0.0

    def _idle_seconds(
        self, snapshots: tuple[BusyStateSnapshot, ...], now: float
    ) -> float:
        """Return the longest queue-wait age in the current snapshot."""
        ages = [
            now - snapshot.reason_started_at
            for snapshot in snapshots
            if snapshot.reason == BusyReason.QUEUE_WAIT
        ]
        return max(ages, default=0.0)

    def _active_tasks(self) -> list[asyncio.Task[None]]:
        """Return not-done consumer tasks."""
        return [task for task in self.state.tasks if not task.done()]

    def _forget_completed(self) -> None:
        """Forget completed consumer task state."""
        for task in self.state.tasks:
            if task.done():
                self.busy_state.forget(task)

    def stage_snapshots(self) -> tuple[BusyStateSnapshot, ...]:
        """Return busy snapshots for this supervisor's consumers."""
        prefix = f"{self.stage_name}-adaptive-consumer-"
        return tuple(
            snapshot
            for snapshot in self.busy_state.snapshot()
            if snapshot.task_name.startswith(prefix)
        )
