"""Worker task busy-state tracking for adaptive runtime supervision."""

from __future__ import annotations

import asyncio
import dataclasses
import enum
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager


class BusyReason(str, enum.Enum):
    """Internal worker state reason used by adaptive runtime decisions."""

    QUEUE_WAIT = "queue_wait"
    ITEM_PROCESSING = "item_processing"
    CACHE_READ = "cache_read"
    INFLIGHT_JOIN = "inflight_join"
    LIVE_DNS = "live_dns"
    CACHE_WRITE_QUEUE_PUT = "cache_write_queue_put"
    DOWNSTREAM_PUT = "downstream_put"
    RESULT_PUT = "result_put"
    STOPPING = "stopping"


@dataclasses.dataclass(frozen=True)
class BusyStateSnapshot:
    """One async task's current busy reason."""

    task_name: str
    reason: BusyReason
    reason_started_at: float


class BusyStateRecorder:
    """Record current busy reasons by asyncio task."""

    def __init__(self) -> None:
        self._states: dict[asyncio.Task[object], BusyStateSnapshot] = {}

    @asynccontextmanager
    async def track(self, reason: BusyReason) -> AsyncIterator[None]:
        """Track one busy reason for the current asyncio task."""
        task = asyncio.current_task()
        if task is None:
            yield
            return
        previous = self._states.get(task)
        self._states[task] = BusyStateSnapshot(
            task_name=task.get_name(),
            reason=reason,
            reason_started_at=time.monotonic(),
        )
        try:
            yield
        finally:
            if previous is None:
                self._states.pop(task, None)
            else:
                self._states[task] = previous

    def mark_stopping(self, task: asyncio.Task[object]) -> None:
        """Mark a task as stopping before cancellation or retirement."""
        self._states[task] = BusyStateSnapshot(
            task_name=task.get_name(),
            reason=BusyReason.STOPPING,
            reason_started_at=time.monotonic(),
        )

    def forget(self, task: asyncio.Task[object]) -> None:
        """Remove a completed task from the recorder."""
        self._states.pop(task, None)

    def snapshot(self) -> tuple[BusyStateSnapshot, ...]:
        """Return deterministic current busy-state snapshots."""
        return tuple(sorted(self._states.values(), key=lambda item: item.task_name))


def busy_reason_allows_scale_up(reason: BusyReason) -> bool:
    """Return whether a busy reason represents stage DNS capacity pressure."""
    return reason in {BusyReason.LIVE_DNS, BusyReason.INFLIGHT_JOIN}
