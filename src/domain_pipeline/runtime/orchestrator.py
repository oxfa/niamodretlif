"""Shared async orchestration primitives."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

from .async_constants import (
    DNS_TO_GEO_QUEUE_SIZE,
    DNS_WRITER_QUEUE_SIZE,
    GEO_WRITER_QUEUE_SIZE,
    PARSE_TO_RDAP_QUEUE_SIZE,
    RDAP_TO_DNS_QUEUE_SIZE,
    RESULT_QUEUE_SIZE,
    ROOT_WRITER_QUEUE_SIZE,
)
from .cache_async import (
    AsyncCacheReadFacade,
    AsyncCacheWriter,
    build_dns_cache_writer,
    build_geo_cache_writer,
    build_root_cache_writer,
)
from .contracts import CompletedHostResult, DNSWorkItem, GeoWorkItem, ParsedHostItem


@dataclass
class QueueBundle:
    """Queues owned by the orchestrator."""

    parse_to_rdap: asyncio.Queue[ParsedHostItem | None]
    rdap_to_dns: asyncio.Queue[DNSWorkItem | None]
    dns_to_geo: asyncio.Queue[GeoWorkItem | None]
    result_queue: asyncio.Queue[CompletedHostResult | None]


@dataclass
class CacheBundle:
    """Async cache services owned by the orchestrator."""

    reader: AsyncCacheReadFacade
    writers: list[AsyncCacheWriter]


def build_queue_bundle() -> QueueBundle:
    """Create the runtime queues with locked sizes."""
    return QueueBundle(
        parse_to_rdap=asyncio.Queue(maxsize=PARSE_TO_RDAP_QUEUE_SIZE),
        rdap_to_dns=asyncio.Queue(maxsize=RDAP_TO_DNS_QUEUE_SIZE),
        dns_to_geo=asyncio.Queue(maxsize=DNS_TO_GEO_QUEUE_SIZE),
        result_queue=asyncio.Queue(maxsize=RESULT_QUEUE_SIZE),
    )


def build_cache_bundle(
    cache_path: Path, *, baseline_cache_path: Path | None = None
) -> CacheBundle:
    """Create the async cache facade and dedicated writers."""
    reader = AsyncCacheReadFacade(cache_path, baseline_path=baseline_cache_path)
    root_writer = build_root_cache_writer(cache_path)
    root_writer.queue = asyncio.Queue(maxsize=ROOT_WRITER_QUEUE_SIZE)
    dns_writer = build_dns_cache_writer(cache_path)
    dns_writer.queue = asyncio.Queue(maxsize=DNS_WRITER_QUEUE_SIZE)
    geo_writer = build_geo_cache_writer(cache_path)
    geo_writer.queue = asyncio.Queue(maxsize=GEO_WRITER_QUEUE_SIZE)
    return CacheBundle(reader=reader, writers=[root_writer, dns_writer, geo_writer])
