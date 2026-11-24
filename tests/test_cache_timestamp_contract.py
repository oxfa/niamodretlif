"""Strict timezone contract for persisted cache timestamps."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from domain_pipeline.aggregate.cache_merge import (
    AggregateCacheMergeCounts,
    AggregateCacheMerger,
    AggregateCacheRows,
)
from domain_pipeline.worker.cache.repository import (
    CacheRepository,
    DELEGATION_COLUMNS,
    DELEGATION_TABLE,
    HOST_RESOLUTION_TABLE,
    IP_LOCATION_TABLE,
    parse_cache_timestamp,
)
from domain_pipeline.worker.cache.requests import CacheTimestamps
from domain_pipeline.worker.cache.service import AsyncCacheService, CacheFetchRequest


def _write_delegation_cache_row(
    path: Path, *, checked_at: str, expires_at: str
) -> None:
    repository = CacheRepository.load(path)
    repository.close()
    values = {
        "domain": "example.com",
        "resolver_key": "resolver",
        "ns_records_exist": 1,
        "ns_nodata": 0,
        "ns_nxdomain": 0,
        "ns_retry_exhausted": 0,
        "ns_lookup_error": 0,
        "soa_exists": 1,
        "soa_absent": 0,
        "soa_retry_exhausted": 0,
        "no_nameservers": 0,
        "nameservers": "[]",
        "checked_at": checked_at,
        "expires_at": expires_at,
    }
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            f"INSERT OR REPLACE INTO {DELEGATION_TABLE} "
            f"({', '.join(DELEGATION_COLUMNS)}) "
            f"VALUES ({', '.join('?' for _ in DELEGATION_COLUMNS)})",
            tuple(values[column] for column in DELEGATION_COLUMNS),
        )
        connection.commit()
    finally:
        connection.close()


def _add_unexpected_cache_column(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            f"ALTER TABLE {DELEGATION_TABLE} ADD COLUMN unexpected_value TEXT"
        )
        connection.commit()
    finally:
        connection.close()


def _remove_delegation_identity_key(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        columns = connection.execute(
            f"PRAGMA table_xinfo('{DELEGATION_TABLE}')"
        ).fetchall()
        definitions = [
            f"{row[1]} {row[2]} NOT NULL"
            for row in columns
            if int(row[6]) == 0
        ]
        connection.execute(
            f"CREATE TABLE delegation_history_without_key ({', '.join(definitions)})"
        )
        connection.execute(f"DROP TABLE {DELEGATION_TABLE}")
        connection.execute(
            "ALTER TABLE delegation_history_without_key "
            f"RENAME TO {DELEGATION_TABLE}"
        )
        connection.commit()
    finally:
        connection.close()


def test_cache_timestamp_parser_requires_timezone_offset() -> None:
    with pytest.raises(ValueError, match="timezone offset"):
        parse_cache_timestamp("2026-11-24T00:00:00")


def test_cache_timestamps_reject_naive_write_values() -> None:
    naive = datetime(2026, 11, 24)
    with pytest.raises(ValueError, match="checked_at must be timezone-aware"):
        CacheTimestamps(checked_at=naive)
    with pytest.raises(ValueError, match="expires_at must be timezone-aware"):
        CacheTimestamps(
            checked_at=datetime(2026, 11, 24, tzinfo=timezone.utc),
            expires_at=naive,
        )


def test_cache_fetch_request_rejects_naive_read_cutoff() -> None:
    with pytest.raises(ValueError, match="cache read timestamp must be timezone-aware"):
        CacheFetchRequest(
            table_name="timestamp_rows",
            columns="*",
            where_sql="identity = ?",
            values=("item",),
            record_factory=lambda row: None,
            now=datetime(2026, 11, 24),
        )


def test_cache_timestamp_parser_normalizes_aware_offset_to_utc() -> None:
    parsed = parse_cache_timestamp("2026-11-24T08:00:00+08:00")
    assert parsed == datetime(2026, 11, 24, tzinfo=timezone.utc)


def test_invalid_overlay_timestamp_falls_through_to_valid_baseline(tmp_path: Path) -> None:
    overlay = tmp_path / "overlay.sqlite3"
    baseline = tmp_path / "baseline.sqlite3"
    _write_delegation_cache_row(
        overlay,
        checked_at="2026-11-24T00:00:00",
        expires_at="2099-01-01T00:00:00Z",
    )
    _write_delegation_cache_row(
        baseline,
        checked_at="2026-11-24T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
    )
    service = AsyncCacheService(overlay, baseline_path=baseline)
    record, source = service._get_fresh_delegation_sync_with_source(
        "example.com", "resolver", datetime(2026, 11, 24, tzinfo=timezone.utc)
    )

    assert source == "baseline"
    assert record is not None
    assert record.timestamps.checked_at == datetime(2026, 11, 24, tzinfo=timezone.utc)


def test_invalid_overlay_schema_falls_through_to_valid_baseline(
    tmp_path: Path,
) -> None:
    overlay = tmp_path / "overlay.sqlite3"
    baseline = tmp_path / "baseline.sqlite3"
    _write_delegation_cache_row(
        overlay,
        checked_at="2026-11-24T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
    )
    _add_unexpected_cache_column(overlay)
    _write_delegation_cache_row(
        baseline,
        checked_at="2025-01-01T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
    )
    service = AsyncCacheService(overlay, baseline_path=baseline)

    record, source = service._get_fresh_delegation_sync_with_source(
        "example.com", "resolver", datetime(2026, 11, 24, tzinfo=timezone.utc)
    )

    assert source == "baseline"
    assert record is not None
    assert record.timestamps.checked_at == datetime(2025, 1, 1, tzinfo=timezone.utc)


def test_cache_repository_rejects_partial_database_without_filling_tables(
    tmp_path: Path,
) -> None:
    path = tmp_path / "partial.sqlite3"
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            f"CREATE TABLE {DELEGATION_TABLE} (domain TEXT PRIMARY KEY)"
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(sqlite3.DatabaseError, match="current schema"):
        CacheRepository.load(path)

    connection = sqlite3.connect(path)
    try:
        table_names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table' "
                "AND name NOT GLOB 'sqlite_*'"
            )
        }
    finally:
        connection.close()
    assert table_names == {DELEGATION_TABLE}


def test_cache_repository_rejects_preexisting_empty_database_without_mutation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "empty.sqlite3"
    connection = sqlite3.connect(path)
    connection.close()
    original_bytes = path.read_bytes()

    with pytest.raises(sqlite3.DatabaseError, match="current schema"):
        CacheRepository.load(path)

    assert path.read_bytes() == original_bytes
    connection = sqlite3.connect(path)
    try:
        table_names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table' "
                "AND name NOT GLOB 'sqlite_*'"
            )
        }
    finally:
        connection.close()
    assert table_names == set()


def test_cache_repository_initializes_missing_database_path(tmp_path: Path) -> None:
    path = tmp_path / "new-cache.sqlite3"
    assert not path.exists()

    repository = CacheRepository.load(path)
    repository.close()

    connection = sqlite3.connect(path)
    try:
        table_names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table' "
                "AND name NOT GLOB 'sqlite_*'"
            )
        }
    finally:
        connection.close()
    assert table_names == {
        DELEGATION_TABLE,
        HOST_RESOLUTION_TABLE,
        IP_LOCATION_TABLE,
    }


def test_cache_repository_rejects_unexpected_column(tmp_path: Path) -> None:
    path = tmp_path / "extra-column.sqlite3"
    repository = CacheRepository.load(path)
    repository.close()
    _add_unexpected_cache_column(path)

    with pytest.raises(sqlite3.DatabaseError, match="current schema"):
        CacheRepository.load(path)


def test_cache_repository_rejects_missing_identity_key(tmp_path: Path) -> None:
    path = tmp_path / "missing-key.sqlite3"
    repository = CacheRepository.load(path)
    repository.close()
    _remove_delegation_identity_key(path)

    with pytest.raises(sqlite3.DatabaseError, match="current schema"):
        CacheRepository.load(path)


@pytest.mark.parametrize("invalid_source", ["target", "candidate"])
@pytest.mark.parametrize("invalid_column", ["checked_at", "expires_at"])
def test_aggregate_cache_merge_skips_invalid_timestamp_rows(
    tmp_path: Path, invalid_source: str, invalid_column: str
) -> None:
    target = tmp_path / "target.sqlite3"
    candidate = tmp_path / "candidate.sqlite3"
    valid_timestamps = {
        "checked_at": "2025-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
    }
    invalid_timestamps = {
        **valid_timestamps,
        invalid_column: "9999-01-01T00:00:00",
    }
    _write_delegation_cache_row(
        target,
        **(invalid_timestamps if invalid_source == "target" else valid_timestamps),
    )
    _write_delegation_cache_row(
        candidate,
        **(invalid_timestamps if invalid_source == "candidate" else valid_timestamps),
    )

    AggregateCacheMerger().merge(source_paths=[candidate], target_path=target)

    connection = sqlite3.connect(target)
    try:
        row = connection.execute(
            f"SELECT checked_at, expires_at FROM {DELEGATION_TABLE} "
            "WHERE domain = ? AND resolver_key = ?",
            ("example.com", "resolver"),
        ).fetchone()
    finally:
        connection.close()
    assert row == (
        valid_timestamps["checked_at"],
        valid_timestamps["expires_at"],
    )


def test_aggregate_cache_merge_skips_invalid_schema_before_reading_any_rows(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.sqlite3"
    candidate = tmp_path / "candidate.sqlite3"
    target_cache = CacheRepository.load(target)
    target_cache.close()
    _write_delegation_cache_row(
        candidate,
        checked_at="2025-01-01T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
    )
    _add_unexpected_cache_column(candidate)

    result = AggregateCacheMerger().merge(
        source_paths=[candidate], target_path=target
    )

    assert result["invalid_cache_count"] == 1
    connection = sqlite3.connect(target)
    try:
        row = connection.execute(
            f"SELECT domain FROM {DELEGATION_TABLE}"
        ).fetchone()
    finally:
        connection.close()
    assert row is None


def test_aggregate_cache_merge_discards_candidate_after_late_read_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "candidate.sqlite3"
    _write_delegation_cache_row(
        candidate,
        checked_at="2025-01-01T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
    )
    rows = AggregateCacheRows()
    counts = AggregateCacheMergeCounts(candidate_cache_count=1)
    merger = AggregateCacheMerger()
    merge_cache_table = merger.merge_cache_table
    table_reads = 0

    def fail_on_second_table_read(
        *,
        rows_by_key: dict[tuple[str, ...], sqlite3.Row],
        connection: sqlite3.Connection,
        source_path: Path,
        table_name: str,
        key_columns: tuple[str, ...],
    ) -> int:
        nonlocal table_reads
        table_reads += 1
        if table_reads == 2:
            raise sqlite3.DatabaseError("simulated unreadable cache table")
        return merge_cache_table(
            rows_by_key=rows_by_key,
            connection=connection,
            source_path=source_path,
            table_name=table_name,
            key_columns=key_columns,
        )

    monkeypatch.setattr(merger, "merge_cache_table", fail_on_second_table_read)
    merger.merge_candidate_cache(rows=rows, counts=counts, cache_path=candidate)

    assert counts.invalid_cache_count == 1
    assert counts.merged_cache_count == 0
    assert rows.delegation == {}
