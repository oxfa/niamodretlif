"""Shared async orchestration primitives."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

from .async_constants import (
    DELEGATION_INPUT_QUEUE_SIZE,
    HOST_RESOLUTION_TO_GEO_QUEUE_SIZE,
    HOST_RESOLUTION_WRITER_QUEUE_SIZE,
    DELEGATION_TO_HOST_RESOLUTION_QUEUE_SIZE,
    DELEGATION_WRITER_QUEUE_SIZE,
    GEO_WRITER_QUEUE_SIZE,
    RESULT_QUEUE_SIZE,
)
from .cache_async import (
    AsyncCacheReadFacade,
    AsyncCacheWriter,
    build_delegation_cache_writer,
    build_geo_cache_writer,
    build_host_resolution_cache_writer,
)
from .contracts import (
    CompletedHostResult,
    GeoWorkItem,
    HostResolutionWorkItem,
    ParsedHostItem,
)


@dataclass
class QueueBundle:
    """Worker-local queues owned by the orchestrator."""

    delegation_input: asyncio.Queue[ParsedHostItem | None]
    delegation_to_host_resolution: asyncio.Queue[HostResolutionWorkItem | None]
    host_resolution_to_geo: asyncio.Queue[GeoWorkItem | None]
    result_queue: asyncio.Queue[CompletedHostResult | None]


@dataclass
class CacheBundle:
    """Async cache services owned by the orchestrator."""

    reader: AsyncCacheReadFacade
    writers: list[AsyncCacheWriter]


def build_queue_bundle() -> QueueBundle:
    """Create the worker-local runtime queues with locked sizes."""
    return QueueBundle(
        delegation_input=asyncio.Queue(maxsize=DELEGATION_INPUT_QUEUE_SIZE),
        delegation_to_host_resolution=asyncio.Queue(
            maxsize=DELEGATION_TO_HOST_RESOLUTION_QUEUE_SIZE
        ),
        host_resolution_to_geo=asyncio.Queue(maxsize=HOST_RESOLUTION_TO_GEO_QUEUE_SIZE),
        result_queue=asyncio.Queue(maxsize=RESULT_QUEUE_SIZE),
    )


def build_cache_bundle(
    cache_path: Path, *, baseline_cache_path: Path | None = None
) -> CacheBundle:
    """Create the async cache facade and dedicated writers."""
    reader = AsyncCacheReadFacade(cache_path, baseline_path=baseline_cache_path)
    delegation_writer = build_delegation_cache_writer(cache_path)
    delegation_writer.queue = asyncio.Queue(maxsize=DELEGATION_WRITER_QUEUE_SIZE)
    host_resolution_writer = build_host_resolution_cache_writer(cache_path)
    host_resolution_writer.queue = asyncio.Queue(
        maxsize=HOST_RESOLUTION_WRITER_QUEUE_SIZE
    )
    geo_writer = build_geo_cache_writer(cache_path)
    geo_writer.queue = asyncio.Queue(maxsize=GEO_WRITER_QUEUE_SIZE)
    return CacheBundle(
        reader=reader,
        writers=[delegation_writer, host_resolution_writer, geo_writer],
    )
