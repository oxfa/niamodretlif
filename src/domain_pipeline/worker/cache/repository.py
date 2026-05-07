"""Persistent cache storage for delegation, host DNS, and IP geo data."""

# pylint: disable=too-many-instance-attributes

from __future__ import annotations

import dataclasses
import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)

DELEGATION_TABLE = "delegation_history"
DNS_TABLE = "dns_history"
GEO_TABLE = "geo_history"
DELEGATION_COLUMNS = (
    "domain",
    "resolver_key",
    "ns_exists",
    "ns_nodata",
    "ns_nxdomain",
    "ns_timeout",
    "ns_servfail",
    "soa_exists",
    "soa_nodata",
    "soa_nxdomain",
    "soa_timeout",
    "soa_servfail",
    "no_nameservers",
    "nameservers",
    "checked_at",
    "expires_at",
)
DELEGATION_SOA_COLUMN_DEFAULTS = {
    "soa_exists": 0,
    "soa_nodata": 0,
    "soa_nxdomain": 0,
    "soa_timeout": 0,
    "soa_servfail": 0,
}


def utc_now() -> datetime:
    """Return the current UTC time."""
    return datetime.now(timezone.utc)


def _parse_datetime(raw_value: str) -> datetime:
    parsed = datetime.fromisoformat(raw_value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_string_list(raw_value: str) -> list[str]:
    try:
        payload = json.loads(raw_value)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, list):
        return []
    return [value for value in payload if isinstance(value, str)]


@dataclasses.dataclass(frozen=True)
class DelegationHistoryRecord:
    """A cached delegation lookup keyed by domain and resolver settings."""

    domain: str
    resolver_key: str
    ns_exists: bool
    ns_nodata: bool
    ns_nxdomain: bool
    ns_timeout: bool
    ns_servfail: bool
    soa_exists: bool
    soa_nodata: bool
    soa_nxdomain: bool
    soa_timeout: bool
    soa_servfail: bool
    no_nameservers: bool
    nameservers: list[str]
    checked_at: datetime
    expires_at: datetime

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "DelegationHistoryRecord":
        """Build a delegation cache record from one SQLite row."""
        return cls(
            domain=str(row["domain"]),
            resolver_key=str(row["resolver_key"]),
            ns_exists=bool(row["ns_exists"]),
            ns_nodata=bool(row["ns_nodata"]),
            ns_nxdomain=bool(row["ns_nxdomain"]),
            ns_timeout=bool(row["ns_timeout"]),
            ns_servfail=bool(row["ns_servfail"]),
            soa_exists=bool(row["soa_exists"]),
            soa_nodata=bool(row["soa_nodata"]),
            soa_nxdomain=bool(row["soa_nxdomain"]),
            soa_timeout=bool(row["soa_timeout"]),
            soa_servfail=bool(row["soa_servfail"]),
            no_nameservers=bool(row["no_nameservers"]),
            nameservers=_parse_string_list(str(row["nameservers"])),
            checked_at=_parse_datetime(str(row["checked_at"])),
            expires_at=_parse_datetime(str(row["expires_at"])),
        )

    def is_expired(self, now: datetime) -> bool:
        """Return whether this cache row has expired."""
        return self.expires_at <= now


@dataclasses.dataclass(frozen=True)
class HostResolutionHistoryRecord:
    """A cached host-resolution lookup keyed by host and resolver settings."""

    host: str
    resolver_key: str
    a_exists: bool
    a_nodata: bool
    a_nxdomain: bool
    a_timeout: bool
    a_servfail: bool
    canonical_name: str
    ipv4_addresses: list[str]
    ipv6_addresses: list[str]
    checked_at: datetime
    expires_at: datetime

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "HostResolutionHistoryRecord":
        """Build a host-resolution cache record from one SQLite row."""
        return cls(
            host=str(row["host"]),
            resolver_key=str(row["resolver_key"]),
            a_exists=bool(row["a_exists"]),
            a_nodata=bool(row["a_nodata"]),
            a_nxdomain=bool(row["a_nxdomain"]),
            a_timeout=bool(row["a_timeout"]),
            a_servfail=bool(row["a_servfail"]),
            canonical_name=str(row["canonical_name"]),
            ipv4_addresses=_parse_string_list(str(row["ipv4_addresses"])),
            ipv6_addresses=_parse_string_list(str(row["ipv6_addresses"])),
            checked_at=_parse_datetime(str(row["checked_at"])),
            expires_at=_parse_datetime(str(row["expires_at"])),
        )

    def is_expired(self, now: datetime) -> bool:
        """Return whether this cache row has expired."""
        return self.expires_at <= now


@dataclasses.dataclass(frozen=True)
class GeoHistoryRecord:
    """A cached IP geolocation lookup record."""

    provider: str
    ip: str
    country_code: str
    region_code: str
    region_name: str
    checked_at: datetime
    expires_at: datetime

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "GeoHistoryRecord":
        """Build a geo cache record from one SQLite row."""
        return cls(
            provider=str(row["provider"]),
            ip=str(row["ip"]),
            country_code=str(row["country_code"]),
            region_code=str(row["region_code"]),
            region_name=str(row["region_name"]),
            checked_at=_parse_datetime(str(row["checked_at"])),
            expires_at=_parse_datetime(str(row["expires_at"])),
        )

    def is_expired(self, now: datetime) -> bool:
        """Return whether this cache row has expired."""
        return self.expires_at <= now


class CacheRepository:
    """Persistent SQLite-backed cache for DNS and geo results."""

    def __init__(self, path: Path, connection: sqlite3.Connection) -> None:
        self.path = path
        self._connection = connection
        self._connection.row_factory = sqlite3.Row
        self._initialize_schema()

    @classmethod
    def load(cls, path: Path) -> "CacheRepository":
        """Open the SQLite cache and initialize the current schema."""
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path, check_same_thread=False)
        return cls(path, connection)

    def _initialize_schema(self) -> None:
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=NORMAL")
        self._connection.execute(f"""
            CREATE TABLE IF NOT EXISTS {DELEGATION_TABLE} (
                domain TEXT NOT NULL,
                resolver_key TEXT NOT NULL,
                ns_exists INTEGER NOT NULL,
                ns_nodata INTEGER NOT NULL,
                ns_nxdomain INTEGER NOT NULL,
                ns_timeout INTEGER NOT NULL,
                ns_servfail INTEGER NOT NULL,
                soa_exists INTEGER NOT NULL DEFAULT 0,
                soa_nodata INTEGER NOT NULL DEFAULT 0,
                soa_nxdomain INTEGER NOT NULL DEFAULT 0,
                soa_timeout INTEGER NOT NULL DEFAULT 0,
                soa_servfail INTEGER NOT NULL DEFAULT 0,
                no_nameservers INTEGER NOT NULL,
                nameservers TEXT NOT NULL,
                checked_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY (domain, resolver_key)
            )
            """)
        self._ensure_delegation_soa_columns()
        self._connection.execute(f"""
            CREATE TABLE IF NOT EXISTS {DNS_TABLE} (
                host TEXT NOT NULL,
                resolver_key TEXT NOT NULL,
                a_exists INTEGER NOT NULL,
                a_nodata INTEGER NOT NULL,
                a_nxdomain INTEGER NOT NULL,
                a_timeout INTEGER NOT NULL,
                a_servfail INTEGER NOT NULL,
                canonical_name TEXT NOT NULL,
                ipv4_addresses TEXT NOT NULL,
                ipv6_addresses TEXT NOT NULL,
                checked_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY (host, resolver_key)
            )
            """)
        self._connection.execute(f"""
            CREATE TABLE IF NOT EXISTS {GEO_TABLE} (
                provider TEXT NOT NULL,
                ip TEXT NOT NULL,
                country_code TEXT NOT NULL,
                region_code TEXT NOT NULL,
                region_name TEXT NOT NULL,
                checked_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY (provider, ip)
            )
            """)
        self._connection.commit()

    def _ensure_delegation_soa_columns(self) -> None:
        """Add SOA fallback columns to restored delegation caches when missing."""
        existing_columns = {
            str(row["name"])
            for row in self._connection.execute(
                f"PRAGMA table_info({DELEGATION_TABLE})"
            )
        }
        for column_name, default_value in DELEGATION_SOA_COLUMN_DEFAULTS.items():
            if column_name in existing_columns:
                continue
            self._connection.execute(f"""
                ALTER TABLE {DELEGATION_TABLE}
                ADD COLUMN {column_name} INTEGER NOT NULL DEFAULT {default_value}
                """)

    def get_delegation(
        self, domain: str, resolver_key: str, now: datetime
    ) -> DelegationHistoryRecord | None:
        """Return a fresh delegation cache record when present."""
        row = self._connection.execute(
            f"SELECT * FROM {DELEGATION_TABLE} WHERE domain = ? AND resolver_key = ?",
            (domain, resolver_key),
        ).fetchone()
        if row is None:
            return None
        record = DelegationHistoryRecord.from_row(row)
        return None if record.is_expired(now) else record

    def put_delegation(
        self,
        *,
        domain: str,
        resolver_key: str,
        ns_exists: bool,
        ns_nodata: bool,
        ns_nxdomain: bool,
        ns_timeout: bool,
        ns_servfail: bool,
        no_nameservers: bool,
        nameservers: list[str],
        checked_at: datetime,
        ttl_days: int,
        soa_exists: bool = False,
        soa_nodata: bool = False,
        soa_nxdomain: bool = False,
        soa_timeout: bool = False,
        soa_servfail: bool = False,
    ) -> None:
        """Store one delegation lookup result."""
        expires_at = checked_at + timedelta(days=ttl_days)
        self._connection.execute(
            f"""
            INSERT OR REPLACE INTO {DELEGATION_TABLE} (
                domain, resolver_key, ns_exists, ns_nodata, ns_nxdomain, ns_timeout,
                ns_servfail, soa_exists, soa_nodata, soa_nxdomain, soa_timeout,
                soa_servfail, no_nameservers, nameservers, checked_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                domain,
                resolver_key,
                int(ns_exists),
                int(ns_nodata),
                int(ns_nxdomain),
                int(ns_timeout),
                int(ns_servfail),
                int(soa_exists),
                int(soa_nodata),
                int(soa_nxdomain),
                int(soa_timeout),
                int(soa_servfail),
                int(no_nameservers),
                json.dumps(nameservers, sort_keys=True),
                checked_at.isoformat(),
                expires_at.isoformat(),
            ),
        )
        self._connection.commit()

    def get_host_resolution(
        self, host: str, resolver_key: str, now: datetime
    ) -> HostResolutionHistoryRecord | None:
        """Return a fresh host-resolution cache record when present."""
        row = self._connection.execute(
            f"SELECT * FROM {DNS_TABLE} WHERE host = ? AND resolver_key = ?",
            (host, resolver_key),
        ).fetchone()
        if row is None:
            return None
        record = HostResolutionHistoryRecord.from_row(row)
        return None if record.is_expired(now) else record

    def put_host_resolution(
        self,
        *,
        host: str,
        resolver_key: str,
        a_exists: bool,
        a_nodata: bool,
        a_nxdomain: bool,
        a_timeout: bool,
        a_servfail: bool,
        canonical_name: str,
        ipv4_addresses: list[str],
        ipv6_addresses: list[str],
        checked_at: datetime,
        ttl_days: int,
    ) -> None:
        """Store one host-resolution lookup result."""
        expires_at = checked_at + timedelta(days=ttl_days)
        self._connection.execute(
            f"""
            INSERT OR REPLACE INTO {DNS_TABLE} (
                host, resolver_key, a_exists, a_nodata, a_nxdomain, a_timeout,
                a_servfail, canonical_name, ipv4_addresses, ipv6_addresses,
                checked_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                host,
                resolver_key,
                int(a_exists),
                int(a_nodata),
                int(a_nxdomain),
                int(a_timeout),
                int(a_servfail),
                canonical_name,
                json.dumps(ipv4_addresses, sort_keys=True),
                json.dumps(ipv6_addresses, sort_keys=True),
                checked_at.isoformat(),
                expires_at.isoformat(),
            ),
        )
        self._connection.commit()

    def get_geo(self, provider: str, ip: str, now: datetime) -> GeoHistoryRecord | None:
        """Return a fresh geo cache record when present."""
        row = self._connection.execute(
            f"SELECT * FROM {GEO_TABLE} WHERE provider = ? AND ip = ?",
            (provider, ip),
        ).fetchone()
        if row is None:
            return None
        record = GeoHistoryRecord.from_row(row)
        return None if record.is_expired(now) else record

    def put_geo(
        self,
        *,
        provider: str,
        ip: str,
        country_code: str,
        region_code: str,
        region_name: str,
        checked_at: datetime,
        ttl_days: int,
    ) -> None:
        """Store one geo lookup result."""
        expires_at = checked_at + timedelta(days=ttl_days)
        self._connection.execute(
            f"""
            INSERT OR REPLACE INTO {GEO_TABLE} (
                provider, ip, country_code, region_code, region_name, checked_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                provider,
                ip,
                country_code,
                region_code,
                region_name,
                checked_at.isoformat(),
                expires_at.isoformat(),
            ),
        )
        self._connection.commit()

    def replace_cache_table_rows(
        self,
        *,
        delegation_rows: Iterable[sqlite3.Row],
        dns_rows: Iterable[sqlite3.Row],
        geo_rows: Iterable[sqlite3.Row],
    ) -> None:
        """Replace all physical cache tables with already-merged SQLite rows."""
        self._connection.execute(f"DELETE FROM {DELEGATION_TABLE}")
        self._connection.execute(f"DELETE FROM {DNS_TABLE}")
        self._connection.execute(f"DELETE FROM {GEO_TABLE}")
        for row in delegation_rows:
            self._connection.execute(
                f"""
                INSERT OR REPLACE INTO {DELEGATION_TABLE} (
                    domain, resolver_key, ns_exists, ns_nodata, ns_nxdomain, ns_timeout,
                    ns_servfail, soa_exists, soa_nodata, soa_nxdomain, soa_timeout,
                    soa_servfail, no_nameservers, nameservers, checked_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._delegation_row_values(row),
            )
        for row in dns_rows:
            self._connection.execute(
                f"""
                INSERT OR REPLACE INTO {DNS_TABLE} (
                    host, resolver_key, a_exists, a_nodata, a_nxdomain, a_timeout,
                    a_servfail, canonical_name, ipv4_addresses, ipv6_addresses,
                    checked_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(row[column] for column in row.keys()),
            )
        for row in geo_rows:
            self._connection.execute(
                f"""
                INSERT OR REPLACE INTO {GEO_TABLE} (
                    provider, ip, country_code, region_code, region_name, checked_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(row[column] for column in row.keys()),
            )
        self._connection.commit()

    def _delegation_row_values(self, row: sqlite3.Row) -> tuple[Any, ...]:
        """Return delegation row values normalized to the current cache schema."""
        row_keys = set(row.keys())
        return tuple(
            (
                DELEGATION_SOA_COLUMN_DEFAULTS[column]
                if column in DELEGATION_SOA_COLUMN_DEFAULTS and column not in row_keys
                else row[column]
            )
            for column in DELEGATION_COLUMNS
        )

    def close(self) -> None:
        """Close the cache database."""
        self._connection.close()


PipelineCache = CacheRepository
