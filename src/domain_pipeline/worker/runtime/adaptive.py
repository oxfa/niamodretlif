"""Adaptive stage concurrency decision helpers."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import time
from collections.abc import Callable, Coroutine
from typing import Any

from domain_pipeline.worker.runtime.busy_state import (
    BusyReason,
    BusyStateRecorder,
    BusyStateSnapshot,
    busy_reason_allows_scale_up,
)

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class AdaptiveStageDecision:
    """One adaptive supervisor scale decision."""

    scale_up: int
    scale_down: int
    reason: str


@dataclasses.dataclass(frozen=True)
class AdaptiveDNSPressureState:
    """DNS capacity and pressure state used by one adaptive stage tick."""

    recent_pressure: bool = False
    capacity_available: bool = True
    summary: str = "unlimited"


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

    def decide(
        self,
        *,
        now: float,
        active_count: int,
        backlog: int,
        consumer_states: tuple[BusyStateSnapshot, ...],
        recent_dns_pressure: bool,
        dns_capacity_available: bool = True,
    ) -> AdaptiveStageDecision:
        """Return the next scale decision for the current stage snapshot."""
        if active_count > self.minimum:
            scale_down = self._scale_down_count(
                now=now,
                active_count=active_count,
                backlog=backlog,
                consumer_states=consumer_states,
                recent_dns_pressure=recent_dns_pressure,
            )
            if scale_down:
                reason = "dns_pressure" if recent_dns_pressure else "idle"
                return AdaptiveStageDecision(0, scale_down, reason)
        scale_up = self._scale_up_count(
            now=now,
            active_count=active_count,
            backlog=backlog,
            consumer_states=consumer_states,
            recent_dns_pressure=recent_dns_pressure,
            dns_capacity_available=dns_capacity_available,
        )
        if scale_up:
            return AdaptiveStageDecision(scale_up, 0, "busy")
        if (
            backlog > 0
            and not recent_dns_pressure
            and not dns_capacity_available
            and active_count < self.cap
        ):
            return AdaptiveStageDecision(0, 0, "dns_capacity_unavailable")
        return AdaptiveStageDecision(0, 0, "stable")

    def _scale_up_count(
        self,
        *,
        now: float,
        active_count: int,
        backlog: int,
        consumer_states: tuple[BusyStateSnapshot, ...],
        recent_dns_pressure: bool,
        dns_capacity_available: bool,
    ) -> int:
        """Return consumer creation count for this tick."""
        if (
            backlog <= 0
            or recent_dns_pressure
            or not dns_capacity_available
            or active_count >= self.cap
        ):
            return 0
        if active_count <= 0 or backlog / active_count < self.queue_pressure_ratio:
            return 0
        if len(consumer_states) < active_count:
            return 0
        for state in consumer_states:
            if not busy_reason_allows_scale_up(state.reason):
                return 0
            if now - state.reason_started_at < self.busy_scale_up_after_seconds:
                return 0
        return min(self.scale_up_step, self.cap - active_count)

    def _scale_down_count(
        self,
        *,
        now: float,
        active_count: int,
        backlog: int,
        consumer_states: tuple[BusyStateSnapshot, ...],
        recent_dns_pressure: bool,
    ) -> int:
        """Return idle consumer retirement count for this tick."""
        if backlog > 0 and not recent_dns_pressure:
            return 0
        idle_count = 0
        for state in consumer_states:
            if state.reason != BusyReason.QUEUE_WAIT:
                continue
            if now - state.reason_started_at >= self.idle_scale_down_after_seconds:
                idle_count += 1
        surplus = max(active_count - self.minimum, 0)
        return min(self.scale_down_step, surplus, idle_count)


class AdaptiveStageSupervisor:  # pylint: disable=too-many-instance-attributes
    """Own adaptive asyncio consumer creation and idle retirement for one stage."""

    def __init__(
        self,
        *,
        stage_name: str,
        queue: asyncio.Queue[object],
        task_factory: Callable[[], Coroutine[Any, Any, None]],
        busy_state: BusyStateRecorder,
        decision_engine: AdaptiveStageDecisionEngine,
        interval_seconds: float,
        recent_dns_pressure: Callable[[], bool] | None = None,
        dns_pressure_state: Callable[[], AdaptiveDNSPressureState] | None = None,
    ) -> None:
        self.stage_name = stage_name
        self.queue = queue
        self.task_factory = task_factory
        self.busy_state = busy_state
        self.decision_engine = decision_engine
        self.interval_seconds = interval_seconds
        self.dns_pressure_state = dns_pressure_state or (
            lambda: AdaptiveDNSPressureState(
                recent_pressure=bool(
                    recent_dns_pressure() if recent_dns_pressure is not None else False
                )
            )
        )
        self._tasks: list[asyncio.Task[None]] = []
        self._monitor_task: asyncio.Task[None] | None = None
        self._created = 0
        self._retired = 0
        self._max_active = 0

    @property
    def tasks(self) -> list[asyncio.Task[None]]:
        """Return active and completed consumer tasks owned by the supervisor."""
        return list(self._tasks)

    async def start(self) -> None:
        """Start minimum consumers and the monitor loop."""
        for _ in range(self.decision_engine.minimum):
            self._create_consumer()
        self._monitor_task = asyncio.create_task(
            self._monitor(), name=f"{self.stage_name}-adaptive-monitor"
        )

    async def stop_after_drain(self) -> None:
        """Stop monitor, send one sentinel per active consumer, and wait for exit."""
        if self._monitor_task is not None:
            self._monitor_task.cancel()
            await asyncio.gather(self._monitor_task, return_exceptions=True)
        self.raise_consumer_failures()
        active_tasks = [task for task in self._tasks if not task.done()]
        for _ in active_tasks:
            await self.queue.put(None)
        if active_tasks:
            await asyncio.gather(*active_tasks)
        self.raise_consumer_failures()
        self._forget_completed()
        logger.debug(
            "Adaptive stage summary stage=%s created=%d retired=%d max_active=%d",
            self.stage_name,
            self._created,
            self._retired,
            self._max_active,
        )

    async def cancel(self) -> None:
        """Cancel monitor and all consumers."""
        tasks: list[asyncio.Task[None]] = []
        if self._monitor_task is not None:
            tasks.append(self._monitor_task)
        tasks.extend(task for task in self._tasks if not task.done())
        for task in tasks:
            self.busy_state.mark_stopping(task)
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._forget_completed()

    def raise_consumer_failures(self) -> None:
        """Raise the first completed consumer exception, including retired tasks."""
        for task in self._tasks:
            if not task.done() or task.cancelled():
                continue
            exception = task.exception()
            if exception is not None:
                raise exception

    def _create_consumer(self) -> None:
        """Create one stage consumer task."""
        self._created += 1
        task = asyncio.create_task(
            self.task_factory(),
            name=f"{self.stage_name}-adaptive-consumer-{self._created}",
        )
        self._tasks.append(task)
        self._max_active = max(self._max_active, len(self._active_tasks()))

    async def _monitor(self) -> None:
        """Periodically apply adaptive scale decisions."""
        while True:
            await asyncio.sleep(self.interval_seconds)
            self.raise_consumer_failures()
            self._forget_completed()
            active_tasks = self._active_tasks()
            now = time.monotonic()
            snapshots = self._stage_snapshots()
            pressure = self.dns_pressure_state()
            decision = self.decision_engine.decide(
                now=now,
                active_count=len(active_tasks),
                backlog=self.queue.qsize(),
                consumer_states=snapshots,
                recent_dns_pressure=pressure.recent_pressure,
                dns_capacity_available=pressure.capacity_available,
            )
            for _ in range(decision.scale_up):
                self._create_consumer()
            if decision.scale_down:
                self._retire_idle_consumers(decision.scale_down, reason=decision.reason)
            self._log_decision(
                decision,
                busy_seconds=self._busy_seconds(snapshots, now),
                idle_seconds=self._idle_seconds(snapshots, now),
                pressure_summary=pressure.summary,
            )

    def _retire_idle_consumers(self, count: int, *, reason: str) -> None:
        """Cancel idle queue-waiting consumers only."""
        snapshots = {
            snapshot.task_name: snapshot for snapshot in self._stage_snapshots()
        }
        retired = 0
        for task in self._active_tasks():
            snapshot = snapshots.get(task.get_name())
            if snapshot is None or snapshot.reason != BusyReason.QUEUE_WAIT:
                continue
            self.busy_state.mark_stopping(task)
            task.cancel()
            self._retired += 1
            retired += 1
            logger.debug(
                "Adaptive stage scale-down stage=%s reason=%s retired=1 active=%d "
                "backlog=%d",
                self.stage_name,
                reason,
                len(self._active_tasks()),
                self.queue.qsize(),
            )
            if retired >= count:
                break

    def _log_decision(
        self,
        decision: AdaptiveStageDecision,
        *,
        busy_seconds: float,
        idle_seconds: float,
        pressure_summary: str = "",
    ) -> None:
        """Log operator context for one non-stable adaptive decision."""
        pressure = pressure_summary or "unreported"
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
        return [task for task in self._tasks if not task.done()]

    def _forget_completed(self) -> None:
        """Forget completed consumer task state."""
        for task in self._tasks:
            if task.done():
                self.busy_state.forget(task)

    def _stage_snapshots(self) -> tuple[BusyStateSnapshot, ...]:
        """Return busy snapshots for this supervisor's consumers."""
        prefix = f"{self.stage_name}-adaptive-consumer-"
        return tuple(
            snapshot
            for snapshot in self.busy_state.snapshot()
            if snapshot.task_name.startswith(prefix)
        )
