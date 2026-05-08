"""Aggregate cache merge owner."""

from __future__ import annotations

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
        rows_by_key: dict[str, dict[tuple[str, ...], sqlite3.Row]] = {
            DELEGATION_TABLE: {},
            HOST_RESOLUTION_TABLE: {},
            IP_LOCATION_TABLE: {},
        }
        target_delegation_rows = self._merge_cache_table(
            rows_by_key=rows_by_key[DELEGATION_TABLE],
            cache_path=target_path,
            table_name=DELEGATION_TABLE,
            key_columns=("domain", "resolver_key"),
        )
        target_host_resolution_rows = self._merge_cache_table(
            rows_by_key=rows_by_key[HOST_RESOLUTION_TABLE],
            cache_path=target_path,
            table_name=HOST_RESOLUTION_TABLE,
            key_columns=("host", "resolver_key"),
        )
        target_ip_location_rows = self._merge_cache_table(
            rows_by_key=rows_by_key[IP_LOCATION_TABLE],
            cache_path=target_path,
            table_name=IP_LOCATION_TABLE,
            key_columns=("provider", "ip"),
        )
        logger.debug(
            "Seeded cache merge target %s with delegation_rows=%d "
            "host_resolution_rows=%d ip_location_rows=%d",
            target_path,
            target_delegation_rows,
            target_host_resolution_rows,
            target_ip_location_rows,
        )
        merged_cache_count = 0
        missing_cache_count = 0
        invalid_cache_count = 0
        try:
            for cache_path in candidate_source_paths:
                if not cache_path.exists():
                    missing_cache_count += 1
                    logger.debug("Skipping missing worker cache %s", cache_path)
                    continue
                try:
                    source_delegation_rows = self._merge_cache_table(
                        rows_by_key=rows_by_key[DELEGATION_TABLE],
                        cache_path=cache_path,
                        table_name=DELEGATION_TABLE,
                        key_columns=("domain", "resolver_key"),
                    )
                    source_host_resolution_rows = self._merge_cache_table(
                        rows_by_key=rows_by_key[HOST_RESOLUTION_TABLE],
                        cache_path=cache_path,
                        table_name=HOST_RESOLUTION_TABLE,
                        key_columns=("host", "resolver_key"),
                    )
                    source_ip_location_rows = self._merge_cache_table(
                        rows_by_key=rows_by_key[IP_LOCATION_TABLE],
                        cache_path=cache_path,
                        table_name=IP_LOCATION_TABLE,
                        key_columns=("provider", "ip"),
                    )
                except sqlite3.DatabaseError as exc:
                    invalid_cache_count += 1
                    logger.warning(
                        "Skipping invalid worker cache %s: %s", cache_path, exc
                    )
                    continue
                merged_cache_count += 1
                logger.debug(
                    "Merged worker cache %s with delegation_rows=%d "
                    "host_resolution_rows=%d ip_location_rows=%d",
                    cache_path,
                    source_delegation_rows,
                    source_host_resolution_rows,
                    source_ip_location_rows,
                )
            target_cache.replace_cache_table_rows(
                delegation_rows=rows_by_key[DELEGATION_TABLE].values(),
                host_resolution_rows=rows_by_key[HOST_RESOLUTION_TABLE].values(),
                ip_location_rows=rows_by_key[IP_LOCATION_TABLE].values(),
            )
            logger.debug(
                "Finished cache merge into %s with delegation_rows=%d "
                "host_resolution_rows=%d ip_location_rows=%d "
                "merged_cache_count=%d missing_cache_count=%d invalid_cache_count=%d",
                target_path,
                len(rows_by_key[DELEGATION_TABLE]),
                len(rows_by_key[HOST_RESOLUTION_TABLE]),
                len(rows_by_key[IP_LOCATION_TABLE]),
                merged_cache_count,
                missing_cache_count,
                invalid_cache_count,
            )
        finally:
            target_cache.close()
        return {
            "candidate_cache_count": len(candidate_source_paths),
            "merged_cache_count": merged_cache_count,
            "missing_cache_count": missing_cache_count,
            "invalid_cache_count": invalid_cache_count,
            "final_cache_path": relative_path(target_path),
        }

    def _choose_cache_row(
        self, existing: sqlite3.Row | None, candidate: sqlite3.Row
    ) -> sqlite3.Row:
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

    def _merge_cache_table(
        self,
        *,
        rows_by_key: dict[tuple[str, ...], sqlite3.Row],
        cache_path: Path,
        table_name: str,
        key_columns: tuple[str, ...],
    ) -> int:
        if not cache_path.exists():
            return 0
        connection = sqlite3.connect(cache_path)
        connection.row_factory = sqlite3.Row
        row_count = 0
        try:
            for row in connection.execute(f"SELECT * FROM {table_name}"):
                row_count += 1
                key = tuple(str(row[column]) for column in key_columns)
                rows_by_key[key] = self._choose_cache_row(rows_by_key.get(key), row)
        finally:
            connection.close()
        return row_count
