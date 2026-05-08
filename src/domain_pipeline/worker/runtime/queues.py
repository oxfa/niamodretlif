"""Runtime queue owner."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from domain_pipeline.worker.runtime.constants import (
    DELEGATION_INPUT_QUEUE_SIZE,
    DELEGATION_TO_HOST_RESOLUTION_QUEUE_SIZE,
    HOST_RESOLUTION_TO_IP_LOCATION_QUEUE_SIZE,
    RESULT_QUEUE_SIZE,
)
from domain_pipeline.worker.runtime.contracts import (
    CompletedHostResult,
    DelegationRootWorkItem,
    IpLocationWorkItem,
    HostResolutionWorkItem,
)


@dataclass
class RuntimeQueueSet:
    """Own root-level delegation and host-level downstream runtime queues."""

    delegation_input: asyncio.Queue[DelegationRootWorkItem | None]
    delegation_to_host_resolution: asyncio.Queue[HostResolutionWorkItem | None]
    host_resolution_to_ip_location: asyncio.Queue[IpLocationWorkItem | None]
    result_queue: asyncio.Queue[CompletedHostResult | None]

    @classmethod
    def create(cls) -> "RuntimeQueueSet":
        """Create the worker-local runtime queues with locked sizes."""
        return cls(
            delegation_input=asyncio.Queue(maxsize=DELEGATION_INPUT_QUEUE_SIZE),
            delegation_to_host_resolution=asyncio.Queue(
                maxsize=DELEGATION_TO_HOST_RESOLUTION_QUEUE_SIZE
            ),
            host_resolution_to_ip_location=asyncio.Queue(
                maxsize=HOST_RESOLUTION_TO_IP_LOCATION_QUEUE_SIZE
            ),
            result_queue=asyncio.Queue(maxsize=RESULT_QUEUE_SIZE),
        )


__all__ = ["RuntimeQueueSet"]
