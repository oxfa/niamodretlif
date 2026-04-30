"""Async cache facade and per-table writer tasks."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from .contracts import (
    DelegationCacheWriteRequest,
    GeoCacheWriteRequest,
    HostResolutionCacheWriteRequest,
)
from .history import (
    DELEGATION_TABLE,
    DNS_TABLE,
    GEO_TABLE,
    DelegationHistoryRecord,
    GeoHistoryRecord,
    HostResolutionHistoryRecord,
    PipelineCache,
)

logger = logging.getLogger(__name__)
CacheHitSource = Literal["overlay", "baseline"]


def _open_read_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


class AsyncCacheReadFacade:
    """Shared async facade for all cache reads."""

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

    async def get_fresh_delegation(
        self, domain: str, resolver_key: str, now: Any
    ) -> DelegationHistoryRecord | None:
        """Return a fresh delegation record without exposing cache-hit source."""
        record, _source = await self.get_fresh_delegation_with_source(
            domain, resolver_key, now
        )
        return record

    async def get_fresh_delegation_with_source(
        self, domain: str, resolver_key: str, now: Any
    ) -> tuple[DelegationHistoryRecord | None, CacheHitSource | None]:
        """Return a fresh delegation record and whether it came from overlay or baseline."""
        return await asyncio.to_thread(
            self._get_fresh_delegation_sync_with_source, domain, resolver_key, now
        )

    def get_fresh_delegation_sync_with_source(
        self, domain: str, resolver_key: str, now: Any
    ) -> tuple[DelegationHistoryRecord | None, CacheHitSource | None]:
        """Synchronously return a fresh delegation record and cache-hit source."""
        return self._get_fresh_delegation_sync_with_source(domain, resolver_key, now)

    async def get_fresh_dns(
        self, host: str, resolver_key: str, now: Any
    ) -> HostResolutionHistoryRecord | None:
        """Return a fresh host-resolution record without exposing cache-hit source."""
        record, _source = await self.get_fresh_dns_with_source(host, resolver_key, now)
        return record

    async def get_fresh_dns_with_source(
        self, host: str, resolver_key: str, now: Any
    ) -> tuple[HostResolutionHistoryRecord | None, CacheHitSource | None]:
        """Return a fresh host-resolution record and cache-hit source."""
        return await asyncio.to_thread(
            self._get_fresh_dns_sync_with_source, host, resolver_key, now
        )

    def get_fresh_dns_sync_with_source(
        self, host: str, resolver_key: str, now: Any
    ) -> tuple[HostResolutionHistoryRecord | None, CacheHitSource | None]:
        """Synchronously return a fresh host-resolution record and cache-hit source."""
        return self._get_fresh_dns_sync_with_source(host, resolver_key, now)

    async def get_fresh_geo(
        self, provider: str, ip: str, now: Any
    ) -> GeoHistoryRecord | None:
        """Return a fresh geo record without exposing cache-hit source."""
        record, _source = await self.get_fresh_geo_with_source(provider, ip, now)
        return record

    async def get_fresh_geo_with_source(
        self, provider: str, ip: str, now: Any
    ) -> tuple[GeoHistoryRecord | None, CacheHitSource | None]:
        """Return a fresh geo record and cache-hit source."""
        return await asyncio.to_thread(
            self._get_fresh_geo_sync_with_source, provider, ip, now
        )

    def get_fresh_geo_sync_with_source(
        self, provider: str, ip: str, now: Any
    ) -> tuple[GeoHistoryRecord | None, CacheHitSource | None]:
        """Synchronously return a fresh geo record and cache-hit source."""
        return self._get_fresh_geo_sync_with_source(provider, ip, now)

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

    def _get_fresh_dns_sync_with_source(
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


class AsyncCacheWriter:
    """Dedicated async cache writer for one request type."""

    def __init__(
        self, path: Path, handler: Callable[[PipelineCache, Any], None]
    ) -> None:
        self.path = path
        self.handler = handler
        self.queue: asyncio.Queue[Any | None] = asyncio.Queue()

    async def run(self) -> None:
        """Drain cache write requests until a sentinel is received."""
        cache = PipelineCache.load(self.path)
        try:
            while True:
                request = await self.queue.get()
                if request is None:
                    return
                await asyncio.to_thread(self.handler, cache, request)
        finally:
            cache.close()


def _write_delegation(
    cache: PipelineCache, request: DelegationCacheWriteRequest
) -> None:
    cache.put_delegation(**request.__dict__)


def _write_host_resolution(
    cache: PipelineCache, request: HostResolutionCacheWriteRequest
) -> None:
    cache.put_dns(**request.__dict__)


def _write_geo(cache: PipelineCache, request: GeoCacheWriteRequest) -> None:
    cache.put_geo(**request.__dict__)


def build_delegation_cache_writer(path: Path) -> AsyncCacheWriter:
    """Build the async writer responsible for delegation cache rows."""
    return AsyncCacheWriter(path, _write_delegation)


def build_host_resolution_cache_writer(path: Path) -> AsyncCacheWriter:
    """Build the async writer responsible for host-resolution cache rows."""
    return AsyncCacheWriter(path, _write_host_resolution)


build_dns_cache_writer = build_host_resolution_cache_writer
"""Backward-compatible alias for the host-resolution cache writer."""


def build_geo_cache_writer(path: Path) -> AsyncCacheWriter:
    """Build the async writer responsible for geo cache rows."""
    return AsyncCacheWriter(path, _write_geo)
