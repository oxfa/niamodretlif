"""Aggregate cache merge owner."""

from __future__ import annotations

import dataclasses
import json
import logging
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from domain_pipeline.prepare.assignment import relative_path
from domain_pipeline.worker.cache.repository import (
    CacheRepository,
    DELEGATION_TABLE,
    IP_LOCATION_TABLE,
    HOST_RESOLUTION_TABLE,
)

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class AggregateCacheRows:
    """Merged cache rows keyed by each table's identity columns."""

    delegation: dict[tuple[str, ...], sqlite3.Row] = dataclasses.field(
        default_factory=dict
    )
    host_resolution: dict[tuple[str, ...], sqlite3.Row] = dataclasses.field(
        default_factory=dict
    )
    ip_location: dict[tuple[str, ...], sqlite3.Row] = dataclasses.field(
        default_factory=dict
    )


@dataclasses.dataclass
class AggregateCacheMergeCounts:
    """Aggregate cache merge outcome counters."""

    candidate_cache_count: int
    merged_cache_count: int = 0
    missing_cache_count: int = 0
    invalid_cache_count: int = 0


class AggregateCacheMerger:
    """Merge deterministic worker cache fragments into the shared cache path."""

    def merge(
        self, *, source_paths: Iterable[Path], target_path: Path
    ) -> dict[str, Any]:
        """Merge worker cache files into the target SQLite cache."""
        candidate_source_paths = list(source_paths)
        logger.debug(
            "Merging cache databases into %s from %d candidate worker caches",
            target_path,
            len(candidate_source_paths),
        )
        target_cache = CacheRepository.load(target_path)
        rows = AggregateCacheRows()
        counts = AggregateCacheMergeCounts(
            candidate_cache_count=len(candidate_source_paths)
        )
        try:
            self.merge_source_cache_rows(rows=rows, cache_path=target_path)
            for cache_path in candidate_source_paths:
                self.merge_candidate_cache(
                    rows=rows, counts=counts, cache_path=cache_path
                )
            target_cache.replace_cache_table_rows(
                delegation_rows=rows.delegation.values(),
                host_resolution_rows=rows.host_resolution.values(),
                ip_location_rows=rows.ip_location.values(),
            )
            logger.debug(
                "Finished cache merge into %s with delegation_rows=%d "
                "host_resolution_rows=%d ip_location_rows=%d "
                "merged_cache_count=%d missing_cache_count=%d invalid_cache_count=%d",
                target_path,
                len(rows.delegation),
                len(rows.host_resolution),
                len(rows.ip_location),
                counts.merged_cache_count,
                counts.missing_cache_count,
                counts.invalid_cache_count,
            )
        finally:
            target_cache.close()
        return {
            "candidate_cache_count": counts.candidate_cache_count,
            "merged_cache_count": counts.merged_cache_count,
            "missing_cache_count": counts.missing_cache_count,
            "invalid_cache_count": counts.invalid_cache_count,
            "final_cache_path": relative_path(target_path),
        }

    def merge_candidate_cache(
        self,
        *,
        rows: AggregateCacheRows,
        counts: AggregateCacheMergeCounts,
        cache_path: Path,
    ) -> None:
        """Merge one worker cache candidate and update outcome counts."""
        if not cache_path.exists():
            counts.missing_cache_count += 1
            logger.debug("Skipping missing worker cache %s", cache_path)
            return
        try:
            row_counts = self.merge_source_cache_rows(rows=rows, cache_path=cache_path)
        except sqlite3.DatabaseError as exc:
            counts.invalid_cache_count += 1
            logger.warning("Skipping invalid worker cache %s: %s", cache_path, exc)
            return
        counts.merged_cache_count += 1
        logger.debug(
            "Merged worker cache %s with delegation_rows=%d "
            "host_resolution_rows=%d ip_location_rows=%d",
            cache_path,
            row_counts[DELEGATION_TABLE],
            row_counts[HOST_RESOLUTION_TABLE],
            row_counts[IP_LOCATION_TABLE],
        )

    def merge_source_cache_rows(
        self, *, rows: AggregateCacheRows, cache_path: Path
    ) -> dict[str, int]:
        """Merge all cache tables from one SQLite cache path."""
        row_counts = {
            DELEGATION_TABLE: self.merge_cache_table(
                rows_by_key=rows.delegation,
                cache_path=cache_path,
                table_name=DELEGATION_TABLE,
                key_columns=("domain", "resolver_key"),
            ),
            HOST_RESOLUTION_TABLE: self.merge_cache_table(
                rows_by_key=rows.host_resolution,
                cache_path=cache_path,
                table_name=HOST_RESOLUTION_TABLE,
                key_columns=("host", "resolver_key"),
            ),
            IP_LOCATION_TABLE: self.merge_cache_table(
                rows_by_key=rows.ip_location,
                cache_path=cache_path,
                table_name=IP_LOCATION_TABLE,
                key_columns=("provider", "ip"),
            ),
        }
        logger.debug(
            "Read cache rows from %s with delegation_rows=%d "
            "host_resolution_rows=%d ip_location_rows=%d",
            cache_path,
            row_counts[DELEGATION_TABLE],
            row_counts[HOST_RESOLUTION_TABLE],
            row_counts[IP_LOCATION_TABLE],
        )
        return row_counts

    def choose_cache_row(
        self, existing: sqlite3.Row | None, candidate: sqlite3.Row
    ) -> sqlite3.Row:
        """Choose the deterministic winning row for one cache identity."""
        if existing is None:
            return candidate
        existing_key = (
            str(existing["checked_at"]),
            str(existing["expires_at"]),
            json.dumps([existing[column] for column in existing.keys()], default=str),
        )
        candidate_key = (
            str(candidate["checked_at"]),
            str(candidate["expires_at"]),
            json.dumps([candidate[column] for column in candidate.keys()], default=str),
        )
        return candidate if candidate_key >= existing_key else existing

    def merge_cache_table(
        self,
        *,
        rows_by_key: dict[tuple[str, ...], sqlite3.Row],
        cache_path: Path,
        table_name: str,
        key_columns: tuple[str, ...],
    ) -> int:
        """Merge one physical cache table from a SQLite cache file."""
        if not cache_path.exists():
            return 0
        connection = sqlite3.connect(cache_path)
        connection.row_factory = sqlite3.Row
        row_count = 0
        try:
            for row in connection.execute(f"SELECT * FROM {table_name}"):
                row_count += 1
                key = tuple(str(row[column]) for column in key_columns)
                rows_by_key[key] = self.choose_cache_row(rows_by_key.get(key), row)
        finally:
            connection.close()
        return row_count
