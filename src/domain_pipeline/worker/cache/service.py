"""Async cache facade and per-table writer tasks."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from domain_pipeline.worker.cache.constants import (
    DELEGATION_WRITER_QUEUE_SIZE,
    GEO_WRITER_QUEUE_SIZE,
    HOST_RESOLUTION_WRITER_QUEUE_SIZE,
)
from domain_pipeline.worker.cache.requests import (
    DelegationCacheWriteRequest,
    GeoCacheWriteRequest,
    HostResolutionCacheWriteRequest,
)
from domain_pipeline.worker.cache.repository import (
    DELEGATION_TABLE,
    DNS_TABLE,
    GEO_TABLE,
    DelegationHistoryRecord,
    GeoHistoryRecord,
    HostResolutionHistoryRecord,
    CacheRepository,
)

logger = logging.getLogger(__name__)
CacheHitSource = Literal["overlay", "baseline"]


def _open_read_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


class AsyncCacheService:
    """Own overlay/baseline read-through cache behavior."""

    def __init__(self, path: Path, baseline_path: Path | None = None) -> None:
        self.path = path
        if baseline_path is not None and baseline_path.resolve(
            strict=False
        ) == path.resolve(strict=False):
            baseline_path = None
        self.baseline_path = baseline_path

    def _candidate_paths(self) -> list[tuple[CacheHitSource, Path]]:
        """Return overlay and optional baseline cache paths in lookup order."""
        candidates: list[tuple[CacheHitSource, Path]] = [("overlay", self.path)]
        if self.baseline_path is not None:
            candidates.append(("baseline", self.baseline_path))
        return candidates

    async def get_fresh_delegation_with_source(
        self, domain: str, resolver_key: str, now: Any
    ) -> tuple[DelegationHistoryRecord | None, CacheHitSource | None]:
        """Return a fresh delegation record and whether it came from overlay or baseline."""
        return await asyncio.to_thread(
            self._get_fresh_delegation_sync_with_source, domain, resolver_key, now
        )

    async def get_fresh_host_resolution_with_source(
        self, host: str, resolver_key: str, now: Any
    ) -> tuple[HostResolutionHistoryRecord | None, CacheHitSource | None]:
        """Return a fresh host-resolution record and cache-hit source."""
        return await asyncio.to_thread(
            self._get_fresh_host_resolution_sync_with_source, host, resolver_key, now
        )

    async def get_fresh_geo_with_source(
        self, provider: str, ip: str, now: Any
    ) -> tuple[GeoHistoryRecord | None, CacheHitSource | None]:
        """Return a fresh geo record and cache-hit source."""
        return await asyncio.to_thread(
            self._get_fresh_geo_sync_with_source, provider, ip, now
        )

    def _fetch_one(
        self,
        *,
        table_name: str,
        columns: str,
        where_sql: str,
        values: tuple[str, ...],
        record_factory: Callable[[sqlite3.Row], Any],
        now: Any,
    ) -> tuple[Any | None, CacheHitSource | None]:
        for source, path in self._candidate_paths():
            if not path.is_file():
                continue
            try:
                with contextlib.closing(_open_read_connection(path)) as connection:
                    row = connection.execute(
                        f"SELECT {columns} FROM {table_name} WHERE {where_sql}",
                        values,
                    ).fetchone()
            except sqlite3.DatabaseError as exc:
                logger.warning(
                    "Skipping unreadable %s cache at %s: %s", source, path, exc
                )
                continue
            if row is None:
                continue
            record = record_factory(row)
            if record.is_expired(now):
                continue
            return record, source
        return None, None

    def _get_fresh_delegation_sync_with_source(
        self, domain: str, resolver_key: str, now: Any
    ) -> tuple[DelegationHistoryRecord | None, CacheHitSource | None]:
        return self._fetch_one(
            table_name=DELEGATION_TABLE,
            columns="*",
            where_sql="domain = ? AND resolver_key = ?",
            values=(domain, resolver_key),
            record_factory=DelegationHistoryRecord.from_row,
            now=now,
        )

    def _get_fresh_host_resolution_sync_with_source(
        self, host: str, resolver_key: str, now: Any
    ) -> tuple[HostResolutionHistoryRecord | None, CacheHitSource | None]:
        return self._fetch_one(
            table_name=DNS_TABLE,
            columns="*",
            where_sql="host = ? AND resolver_key = ?",
            values=(host, resolver_key),
            record_factory=HostResolutionHistoryRecord.from_row,
            now=now,
        )

    def _get_fresh_geo_sync_with_source(
        self, provider: str, ip: str, now: Any
    ) -> tuple[GeoHistoryRecord | None, CacheHitSource | None]:
        return self._fetch_one(
            table_name=GEO_TABLE,
            columns="*",
            where_sql="provider = ? AND ip = ?",
            values=(provider, ip),
            record_factory=GeoHistoryRecord.from_row,
            now=now,
        )


class CacheWriteDispatcher:
    """Own one async cache write queue and its shutdown sentinel."""

    def __init__(
        self, path: Path, handler: Callable[[CacheRepository, Any], None]
    ) -> None:
        self.path = path
        self.handler = handler
        self.queue: asyncio.Queue[Any | None] = asyncio.Queue()

    async def run(self) -> None:
        """Drain cache write requests until a sentinel is received."""
        cache = CacheRepository.load(self.path)
        try:
            while True:
                request = await self.queue.get()
                try:
                    if request is None:
                        return
                    await asyncio.to_thread(self.handler, cache, request)
                finally:
                    self.queue.task_done()
        finally:
            cache.close()


@dataclass
class CacheBundle:
    """Own the worker cache reader and dedicated writer dispatchers."""

    reader: AsyncCacheService
    writers: list[CacheWriteDispatcher]


def _write_delegation(
    cache: CacheRepository, request: DelegationCacheWriteRequest
) -> None:
    cache.put_delegation(**request.__dict__)


def _write_host_resolution(
    cache: CacheRepository, request: HostResolutionCacheWriteRequest
) -> None:
    cache.put_host_resolution(**request.__dict__)


def _write_geo(cache: CacheRepository, request: GeoCacheWriteRequest) -> None:
    cache.put_geo(**request.__dict__)


def build_delegation_cache_writer(path: Path) -> CacheWriteDispatcher:
    """Build the async writer responsible for delegation cache rows."""
    return CacheWriteDispatcher(path, _write_delegation)


def build_host_resolution_cache_writer(path: Path) -> CacheWriteDispatcher:
    """Build the async writer responsible for host-resolution cache rows."""
    return CacheWriteDispatcher(path, _write_host_resolution)


def build_geo_cache_writer(path: Path) -> CacheWriteDispatcher:
    """Build the async writer responsible for geo cache rows."""
    return CacheWriteDispatcher(path, _write_geo)


def build_cache_bundle(
    cache_path: Path, *, baseline_cache_path: Path | None = None
) -> CacheBundle:
    """Create the worker cache reader and dedicated writer dispatchers."""
    reader = AsyncCacheService(cache_path, baseline_path=baseline_cache_path)
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
