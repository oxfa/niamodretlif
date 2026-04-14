"""Async cache facade and per-table writer tasks."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from .contracts import (
    DNSCacheWriteRequest,
    GeoCacheWriteRequest,
    RootCacheWriteRequest,
)
from .history import (
    DNSHistoryRecord,
    GeoHistoryRecord,
    PipelineCache,
    RootDomainClassificationRecord,
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
        deduplicated_baseline = False
        if baseline_path is not None and baseline_path.resolve(
            strict=False
        ) == path.resolve(strict=False):
            baseline_path = None
            deduplicated_baseline = True
        self.baseline_path = baseline_path
        logger.debug(
            "Configured cache read facade overlay=%s overlay_exists=%s baseline=%s "
            "baseline_exists=%s baseline_deduplicated=%s",
            self.path,
            self.path.is_file(),
            self.baseline_path if self.baseline_path is not None else "(none)",
            self.baseline_path.is_file() if self.baseline_path is not None else False,
            deduplicated_baseline,
        )

    def _candidate_paths(self) -> list[tuple[CacheHitSource, Path]]:
        candidates: list[tuple[CacheHitSource, Path]] = [("overlay", self.path)]
        if self.baseline_path is not None:
            candidates.append(("baseline", self.baseline_path))
        return candidates

    def _log_missing_cache_layer(
        self, cache_name: str, cache_key: str, *, source: CacheHitSource, path: Path
    ) -> None:
        logger.debug(
            "Skipping missing %s %s cache at %s for %s",
            source,
            cache_name,
            path,
            cache_key,
        )

    def _log_layer_expired(
        self,
        cache_name: str,
        cache_key: str,
        *,
        source: CacheHitSource,
        path: Path,
        expires_at,
        now,
    ) -> None:
        logger.debug(
            "%s cache expired in %s at %s for %s (expired_at=%s now=%s)",
            source.capitalize(),
            cache_name,
            path,
            cache_key,
            expires_at.isoformat(),
            now.isoformat(),
        )

    def _log_layer_hit(
        self,
        cache_name: str,
        cache_key: str,
        *,
        source: CacheHitSource,
        path: Path,
    ) -> None:
        logger.debug(
            "%s cache hit in %s at %s for %s",
            source.capitalize(),
            cache_name,
            path,
            cache_key,
        )

    def _log_cache_miss(self, cache_name: str, cache_key: str) -> None:
        logger.debug(
            "Cache miss in %s across overlay=%s baseline=%s for %s",
            cache_name,
            self.path,
            self.baseline_path if self.baseline_path is not None else "(none)",
            cache_key,
        )

    def _log_invalid_cache(
        self, cache_name: str, *, source: CacheHitSource, path: Path, exc: Exception
    ) -> None:
        logger.warning(
            "Skipping unreadable %s %s cache at %s: %s",
            source,
            cache_name,
            path,
            exc,
        )

    async def get_fresh_root(
        self, domain: str, now
    ) -> RootDomainClassificationRecord | None:
        """Return one fresh cached RDAP root record when present."""
        record, _source = await self.get_fresh_root_with_source(domain, now)
        return record

    async def get_fresh_root_with_source(
        self, domain: str, now
    ) -> tuple[RootDomainClassificationRecord | None, CacheHitSource | None]:
        """Return one fresh cached RDAP root record and the cache layer used."""
        return await asyncio.to_thread(
            self._get_fresh_root_sync_with_source, domain, now
        )

    async def get_fresh_dns(
        self, host: str, resolver_key: str, now
    ) -> DNSHistoryRecord | None:
        """Return one fresh cached DNS record when present."""
        record, _source = await self.get_fresh_dns_with_source(host, resolver_key, now)
        return record

    async def get_fresh_dns_with_source(
        self, host: str, resolver_key: str, now
    ) -> tuple[DNSHistoryRecord | None, CacheHitSource | None]:
        """Return one fresh cached DNS record and the cache layer used."""
        return await asyncio.to_thread(
            self._get_fresh_dns_sync_with_source, host, resolver_key, now
        )

    async def get_fresh_geo(
        self, provider: str, ip: str, now
    ) -> GeoHistoryRecord | None:
        """Return one fresh cached geo record when present."""
        record, _source = await self.get_fresh_geo_with_source(provider, ip, now)
        return record

    async def get_fresh_geo_with_source(
        self, provider: str, ip: str, now
    ) -> tuple[GeoHistoryRecord | None, CacheHitSource | None]:
        """Return one fresh cached geo record and the cache layer used."""
        return await asyncio.to_thread(
            self._get_fresh_geo_sync_with_source, provider, ip, now
        )

    def _get_fresh_root_sync(
        self, domain: str, now
    ) -> RootDomainClassificationRecord | None:
        """Synchronously load one fresh cached RDAP root record."""
        record, _source = self._get_fresh_root_sync_with_source(domain, now)
        return record

    def _get_fresh_root_sync_with_source(
        self, domain: str, now
    ) -> tuple[RootDomainClassificationRecord | None, CacheHitSource | None]:
        """Synchronously load one fresh cached RDAP root record and source."""
        cache_key = f"root={domain}"
        for source, path in self._candidate_paths():
            if not path.is_file():
                self._log_missing_cache_layer(
                    "root_domain_classification_history",
                    cache_key,
                    source=source,
                    path=path,
                )
                continue
            try:
                with contextlib.closing(_open_read_connection(path)) as connection:
                    row = connection.execute(
                        """
                        SELECT
                            domain,
                            classification,
                            statuses,
                            statuses_complete,
                            checked_at,
                            expires_at
                        FROM root_domain_classification_history
                        WHERE domain = ?
                        """,
                        (domain,),
                    ).fetchone()
            except sqlite3.DatabaseError as exc:
                self._log_invalid_cache(
                    "root_domain_classification_history",
                    source=source,
                    path=path,
                    exc=exc,
                )
                continue
            record = (
                RootDomainClassificationRecord.from_row(row)
                if row is not None
                else None
            )
            if record is None:
                continue
            if record.is_expired(now):
                self._log_layer_expired(
                    "root_domain_classification_history",
                    cache_key,
                    source=source,
                    path=path,
                    expires_at=record.expires_at,
                    now=now,
                )
                continue
            self._log_layer_hit(
                "root_domain_classification_history",
                cache_key,
                source=source,
                path=path,
            )
            return record, source
        self._log_cache_miss("root_domain_classification_history", cache_key)
        return None, None

    def _get_fresh_dns_sync(
        self, host: str, resolver_key: str, now
    ) -> DNSHistoryRecord | None:
        """Synchronously load one fresh cached DNS record."""
        record, _source = self._get_fresh_dns_sync_with_source(host, resolver_key, now)
        return record

    def _get_fresh_dns_sync_with_source(
        self, host: str, resolver_key: str, now
    ) -> tuple[DNSHistoryRecord | None, CacheHitSource | None]:
        """Synchronously load one fresh cached DNS record and source."""
        cache_key = f"host={host} resolver={resolver_key}"
        for source, path in self._candidate_paths():
            if not path.is_file():
                self._log_missing_cache_layer(
                    "dns_history",
                    cache_key,
                    source=source,
                    path=path,
                )
                continue
            try:
                with contextlib.closing(_open_read_connection(path)) as connection:
                    row = connection.execute(
                        """
                        SELECT
                            host,
                            resolver_key,
                            a_exists,
                            a_nodata,
                            a_nxdomain,
                            a_timeout,
                            a_servfail,
                            canonical_name,
                            ipv4_addresses,
                            ipv6_addresses,
                            checked_at,
                            expires_at
                        FROM dns_history
                        WHERE host = ? AND resolver_key = ?
                        """,
                        (host, resolver_key),
                    ).fetchone()
            except sqlite3.DatabaseError as exc:
                self._log_invalid_cache(
                    "dns_history",
                    source=source,
                    path=path,
                    exc=exc,
                )
                continue
            record = DNSHistoryRecord.from_row(row) if row is not None else None
            if record is None:
                continue
            if record.is_expired(now):
                self._log_layer_expired(
                    "dns_history",
                    cache_key,
                    source=source,
                    path=path,
                    expires_at=record.expires_at,
                    now=now,
                )
                continue
            self._log_layer_hit(
                "dns_history",
                cache_key,
                source=source,
                path=path,
            )
            return record, source
        self._log_cache_miss("dns_history", cache_key)
        return None, None

    def _get_fresh_geo_sync(
        self, provider: str, ip: str, now
    ) -> GeoHistoryRecord | None:
        """Synchronously load one fresh cached geo record."""
        record, _source = self._get_fresh_geo_sync_with_source(provider, ip, now)
        return record

    def _get_fresh_geo_sync_with_source(
        self, provider: str, ip: str, now
    ) -> tuple[GeoHistoryRecord | None, CacheHitSource | None]:
        """Synchronously load one fresh cached geo record and source."""
        cache_key = f"provider={provider} ip={ip}"
        for source, path in self._candidate_paths():
            if not path.is_file():
                self._log_missing_cache_layer(
                    "geo_history",
                    cache_key,
                    source=source,
                    path=path,
                )
                continue
            try:
                with contextlib.closing(_open_read_connection(path)) as connection:
                    row = connection.execute(
                        """
                        SELECT
                            provider,
                            ip,
                            country_code,
                            region_code,
                            region_name,
                            checked_at,
                            expires_at
                        FROM geo_history
                        WHERE provider = ? AND ip = ?
                        """,
                        (provider, ip),
                    ).fetchone()
            except sqlite3.DatabaseError as exc:
                self._log_invalid_cache(
                    "geo_history",
                    source=source,
                    path=path,
                    exc=exc,
                )
                continue
            record = GeoHistoryRecord.from_row(row) if row is not None else None
            if record is None:
                continue
            if record.is_expired(now):
                self._log_layer_expired(
                    "geo_history",
                    cache_key,
                    source=source,
                    path=path,
                    expires_at=record.expires_at,
                    now=now,
                )
                continue
            self._log_layer_hit(
                "geo_history",
                cache_key,
                source=source,
                path=path,
            )
            return record, source
        self._log_cache_miss("geo_history", cache_key)
        return None, None


class AsyncCacheWriter:
    """Dedicated async writer for a single cache table."""

    def __init__(
        self,
        *,
        path: Path,
        name: str,
        apply_write: Callable[[PipelineCache, object], None],
    ) -> None:
        self.path = path
        self.name = name
        self._apply_write = apply_write
        self.queue: asyncio.Queue[object | None] = asyncio.Queue()

    async def run(self) -> None:
        """Drain queued write requests into the backing SQLite cache."""
        cache = PipelineCache.load(self.path)
        try:
            while True:
                request = await self.queue.get()
                try:
                    if request is None:
                        return
                    self._write_once(cache, request)
                finally:
                    self.queue.task_done()
        finally:
            cache.close()

    def _write_once(self, cache: PipelineCache, request: object) -> None:
        """Apply one queued cache write and flush it to disk."""
        self._apply_write(cache, request)
        cache.save()

    async def close(self) -> None:
        """Request graceful shutdown after queued writes are flushed."""
        await self.queue.put(None)


def build_root_cache_writer(path: Path) -> AsyncCacheWriter:
    """Build the async writer responsible for RDAP root cache rows."""

    def apply_write(cache: PipelineCache, request: object) -> None:
        assert isinstance(request, RootCacheWriteRequest)
        cache.upsert_root(
            request.domain,
            request.classification,
            request.statuses,
            request.statuses_complete,
            request.checked_at,
            request.ttl_days,
        )

    return AsyncCacheWriter(
        path=path, name="root_cache_writer", apply_write=apply_write
    )


def build_dns_cache_writer(path: Path) -> AsyncCacheWriter:
    """Build the async writer responsible for DNS cache rows."""

    def apply_write(cache: PipelineCache, request: object) -> None:
        assert isinstance(request, DNSCacheWriteRequest)
        cache.upsert_dns(
            request.host,
            request.resolver_key,
            a_exists=request.a_exists,
            a_nodata=request.a_nodata,
            a_nxdomain=request.a_nxdomain,
            a_timeout=request.a_timeout,
            a_servfail=request.a_servfail,
            canonical_name=request.canonical_name,
            ipv4_addresses=request.ipv4_addresses,
            ipv6_addresses=request.ipv6_addresses,
            checked_at=request.checked_at,
            ttl_days=request.ttl_days,
        )

    return AsyncCacheWriter(path=path, name="dns_cache_writer", apply_write=apply_write)


def build_geo_cache_writer(path: Path) -> AsyncCacheWriter:
    """Build the async writer responsible for geo cache rows."""

    def apply_write(cache: PipelineCache, request: object) -> None:
        assert isinstance(request, GeoCacheWriteRequest)
        cache.upsert_geo(
            request.provider,
            request.ip,
            request.country_code,
            request.region_code,
            request.region_name,
            request.checked_at,
            request.ttl_days,
        )

    return AsyncCacheWriter(path=path, name="geo_cache_writer", apply_write=apply_write)


async def start_writer_tasks(
    writers: list[AsyncCacheWriter],
) -> list[asyncio.Task[None]]:
    """Start dedicated cache writer tasks."""
    return [asyncio.create_task(writer.run(), name=writer.name) for writer in writers]


async def stop_writer_tasks(
    writers: list[AsyncCacheWriter],
    tasks: list[asyncio.Task[None]],
) -> None:
    """Flush and stop cache writer tasks."""
    for writer in writers:
        await writer.close()
    for writer in writers:
        await writer.queue.join()
    for task in tasks:
        await task
