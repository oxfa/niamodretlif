"""Persistent cache storage for delegation, host resolution, and IP-location data."""

from __future__ import annotations

import dataclasses
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from domain_pipeline.worker.cache.requests import (
    CacheIdentity,
    CacheTimestamps,
    DelegationCacheWriteRequest,
    HostResolutionCacheWriteRequest,
    IpLocationCacheEvidence,
    IpLocationCacheIdentity,
    IpLocationCacheWriteRequest,
    cache_identity_from_mapping,
    delegation_dns_evidence_from_mapping,
    delegation_soa_evidence_from_mapping,
    host_resolution_dns_evidence_from_mapping,
)
from domain_pipeline.worker.delegation.lookup import (
    DelegationDnsEvidence,
    DelegationSoaEvidence,
)
from domain_pipeline.worker.host_resolution.lookup import (
    HostResolutionAddressEvidence,
    HostResolutionDnsEvidence,
)

logger = logging.getLogger(__name__)

DELEGATION_TABLE = "delegation_history"
HOST_RESOLUTION_TABLE = "host_resolution_history"
IP_LOCATION_TABLE = "ip_location_history"
CACHE_TABLE_COLUMN_SPECS: dict[str, tuple[tuple[str, str, int], ...]] = {
    DELEGATION_TABLE: (
        ("domain", "TEXT", 1),
        ("resolver_key", "TEXT", 2),
        ("ns_records_exist", "INTEGER", 0),
        ("ns_nodata", "INTEGER", 0),
        ("ns_nxdomain", "INTEGER", 0),
        ("ns_retry_exhausted", "INTEGER", 0),
        ("ns_lookup_error", "INTEGER", 0),
        ("soa_exists", "INTEGER", 0),
        ("soa_absent", "INTEGER", 0),
        ("soa_retry_exhausted", "INTEGER", 0),
        ("no_nameservers", "INTEGER", 0),
        ("nameservers", "TEXT", 0),
        ("checked_at", "TEXT", 0),
        ("expires_at", "TEXT", 0),
    ),
    HOST_RESOLUTION_TABLE: (
        ("host", "TEXT", 1),
        ("resolver_key", "TEXT", 2),
        ("a_exists", "INTEGER", 0),
        ("a_nodata", "INTEGER", 0),
        ("a_nxdomain", "INTEGER", 0),
        ("a_timeout", "INTEGER", 0),
        ("a_servfail", "INTEGER", 0),
        ("canonical_name", "TEXT", 0),
        ("ipv4_addresses", "TEXT", 0),
        ("ipv6_addresses", "TEXT", 0),
        ("checked_at", "TEXT", 0),
        ("expires_at", "TEXT", 0),
    ),
    IP_LOCATION_TABLE: (
        ("provider", "TEXT", 1),
        ("ip", "TEXT", 2),
        ("country_code", "TEXT", 0),
        ("region_code", "TEXT", 0),
        ("region_name", "TEXT", 0),
        ("checked_at", "TEXT", 0),
        ("expires_at", "TEXT", 0),
    ),
}


def _column_names(table_name: str) -> tuple[str, ...]:
    return tuple(
        name
        for name, _declared_type, _primary_key_position in CACHE_TABLE_COLUMN_SPECS[
            table_name
        ]
    )


DELEGATION_COLUMNS = _column_names(DELEGATION_TABLE)
HOST_RESOLUTION_COLUMNS = _column_names(HOST_RESOLUTION_TABLE)
IP_LOCATION_COLUMNS = _column_names(IP_LOCATION_TABLE)


def _user_schema_objects(connection: sqlite3.Connection) -> set[tuple[str, str]]:
    return {
        (str(row[0]), str(row[1]))
        for row in connection.execute(
            "SELECT type, name FROM sqlite_schema "
            "WHERE name NOT GLOB 'sqlite_*' "
            "AND type IN ('table', 'index', 'view', 'trigger')"
        )
    }


def validate_cache_schema(connection: sqlite3.Connection) -> None:
    """Require exactly the current cache tables and column definitions."""
    expected_objects = {
        ("table", table_name) for table_name in CACHE_TABLE_COLUMN_SPECS
    }
    actual_objects = _user_schema_objects(connection)
    if actual_objects != expected_objects:
        missing = sorted(expected_objects - actual_objects)
        unexpected = sorted(actual_objects - expected_objects)
        raise sqlite3.DatabaseError(
            f"cache database schema does not match current schema: "
            f"missing={missing!r}, unexpected={unexpected!r}"
        )

    for table_name, column_specs in CACHE_TABLE_COLUMN_SPECS.items():
        expected_columns = tuple(
            (name, declared_type, 1, None, primary_key_position, 0)
            for name, declared_type, primary_key_position in column_specs
        )
        actual_columns = tuple(
            (
                str(row[1]),
                str(row[2]).upper(),
                int(row[3]),
                row[4],
                int(row[5]),
                int(row[6]),
            )
            for row in connection.execute(f"PRAGMA table_xinfo('{table_name}')")
        )
        if actual_columns != expected_columns:
            raise sqlite3.DatabaseError(
                f"cache table {table_name} does not match current schema"
            )


def _create_current_schema(connection: sqlite3.Connection) -> None:
    for table_name, column_specs in CACHE_TABLE_COLUMN_SPECS.items():
        definitions = [
            f"{name} {declared_type} NOT NULL"
            for name, declared_type, _primary_key_position in column_specs
        ]
        primary_key_columns = [
            name
            for primary_key_position, name in sorted(
                (primary_key_position, name)
                for name, _declared_type, primary_key_position in column_specs
                if primary_key_position
            )
        ]
        definitions.append(f"PRIMARY KEY ({', '.join(primary_key_columns)})")
        connection.execute(
            f"CREATE TABLE {table_name} ({', '.join(definitions)})"
        )


def utc_now() -> datetime:
    """Return the current UTC time."""
    return datetime.now(timezone.utc)


def parse_cache_timestamp(raw_value: str) -> datetime:
    """Parse a persisted cache timestamp and normalize it to UTC."""
    parsed = datetime.fromisoformat(raw_value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("cache timestamp must include a timezone offset")
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

    payload: DelegationCacheWriteRequest

    @property
    def identity(self) -> CacheIdentity:
        """Return the cache row identity."""
        return self.payload.identity

    @property
    def dns(self) -> DelegationDnsEvidence:
        """Return cached NS evidence."""
        return self.payload.dns

    @property
    def soa(self) -> DelegationSoaEvidence:
        """Return cached SOA fallback evidence."""
        return self.payload.soa

    @property
    def no_nameservers(self) -> bool:
        """Return whether cached NS response had no nameserver values."""
        return self.payload.no_nameservers

    @property
    def nameservers(self) -> list[str]:
        """Return cached nameserver values."""
        return self.payload.nameservers

    @property
    def timestamps(self) -> CacheTimestamps:
        """Return cache row timestamps."""
        return self.payload.timestamps

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "DelegationHistoryRecord":
        """Build a delegation cache record from one SQLite row."""
        return cls(
            payload=DelegationCacheWriteRequest(
                identity=cache_identity_from_mapping(row, name_field="domain"),
                dns=delegation_dns_evidence_from_mapping(row),
                soa=delegation_soa_evidence_from_mapping(row),
                no_nameservers=bool(row["no_nameservers"]),
                nameservers=_parse_string_list(str(row["nameservers"])),
                timestamps=CacheTimestamps(
                    checked_at=parse_cache_timestamp(str(row["checked_at"])),
                    expires_at=parse_cache_timestamp(str(row["expires_at"])),
                ),
            ),
        )

    def is_expired(self, now: datetime) -> bool:
        """Return whether this cache row has expired."""
        return self.timestamps.effective_expires_at() <= now


@dataclasses.dataclass(frozen=True)
class HostResolutionHistoryRecord:
    """A cached host-resolution lookup keyed by host and resolver settings."""

    identity: CacheIdentity
    dns: HostResolutionDnsEvidence
    addresses: HostResolutionAddressEvidence
    timestamps: CacheTimestamps

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "HostResolutionHistoryRecord":
        """Build a host-resolution cache record from one SQLite row."""
        return cls(
            identity=cache_identity_from_mapping(row, name_field="host"),
            dns=host_resolution_dns_evidence_from_mapping(row),
            addresses=HostResolutionAddressEvidence(
                canonical_name=str(row["canonical_name"]),
                ipv4_addresses=_parse_string_list(str(row["ipv4_addresses"])),
                ipv6_addresses=_parse_string_list(str(row["ipv6_addresses"])),
            ),
            timestamps=CacheTimestamps(
                checked_at=parse_cache_timestamp(str(row["checked_at"])),
                expires_at=parse_cache_timestamp(str(row["expires_at"])),
            ),
        )

    def is_expired(self, now: datetime) -> bool:
        """Return whether this cache row has expired."""
        return self.timestamps.effective_expires_at() <= now


@dataclasses.dataclass(frozen=True)
class IpLocationHistoryRecord:
    """A cached IP-location lookup record."""

    identity: IpLocationCacheIdentity
    evidence: IpLocationCacheEvidence
    timestamps: CacheTimestamps

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "IpLocationHistoryRecord":
        """Build an IP-location cache record from one SQLite row."""
        return cls(
            identity=IpLocationCacheIdentity(
                provider=str(row["provider"]),
                ip=str(row["ip"]),
            ),
            evidence=IpLocationCacheEvidence(
                country_code=str(row["country_code"]),
                region_code=str(row["region_code"]),
                region_name=str(row["region_name"]),
            ),
            timestamps=CacheTimestamps(
                checked_at=parse_cache_timestamp(str(row["checked_at"])),
                expires_at=parse_cache_timestamp(str(row["expires_at"])),
            ),
        )

    def is_expired(self, now: datetime) -> bool:
        """Return whether this cache row has expired."""
        return self.timestamps.effective_expires_at() <= now


class CacheRepository:
    """Persistent SQLite-backed cache for DNS and IP-location results."""

    def __init__(self, path: Path, connection: sqlite3.Connection) -> None:
        self.path = path
        self._connection = connection
        self._connection.row_factory = sqlite3.Row
        self._initialize_schema()

    @classmethod
    def load(cls, path: Path) -> "CacheRepository":
        """Open the SQLite cache and initialize the current schema."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path_existed_before_open = path.exists()
        connection = sqlite3.connect(path, check_same_thread=False)
        try:
            if path_existed_before_open and not _user_schema_objects(connection):
                validate_cache_schema(connection)
            return cls(path, connection)
        except Exception:
            connection.close()
            raise

    def _initialize_schema(self) -> None:
        if _user_schema_objects(self._connection):
            validate_cache_schema(self._connection)
        else:
            _create_current_schema(self._connection)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=NORMAL")
        self._connection.commit()

    def put_delegation(self, request: DelegationCacheWriteRequest) -> None:
        """Store one delegation lookup result."""
        expires_at = request.timestamps.effective_expires_at()
        self._connection.execute(
            f"""
            INSERT OR REPLACE INTO {DELEGATION_TABLE} (
                domain, resolver_key, ns_records_exist, ns_nodata, ns_nxdomain,
                ns_retry_exhausted, ns_lookup_error, soa_exists, soa_absent,
                soa_retry_exhausted, no_nameservers, nameservers, checked_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.identity.name,
                request.identity.resolver_key,
                int(request.dns.ns_records_exist),
                int(request.dns.ns_nodata),
                int(request.dns.ns_nxdomain),
                int(request.dns.ns_retry_exhausted),
                int(request.dns.ns_lookup_error),
                int(request.soa.soa_exists),
                int(request.soa.soa_absent),
                int(request.soa.soa_retry_exhausted),
                int(request.no_nameservers),
                json.dumps(request.nameservers, sort_keys=True),
                request.timestamps.checked_at.isoformat(),
                expires_at.isoformat(),
            ),
        )
        self._connection.commit()

    def put_host_resolution(self, request: HostResolutionCacheWriteRequest) -> None:
        """Store one host-resolution lookup result."""
        expires_at = request.timestamps.effective_expires_at()
        self._connection.execute(
            f"""
            INSERT OR REPLACE INTO {HOST_RESOLUTION_TABLE} (
                host, resolver_key, a_exists, a_nodata, a_nxdomain, a_timeout,
                a_servfail, canonical_name, ipv4_addresses, ipv6_addresses,
                checked_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.identity.name,
                request.identity.resolver_key,
                int(request.dns.a_exists),
                int(request.dns.a_nodata),
                int(request.dns.a_nxdomain),
                int(request.dns.a_timeout),
                int(request.dns.a_servfail),
                request.addresses.canonical_name or "",
                json.dumps(request.addresses.ipv4_addresses, sort_keys=True),
                json.dumps(request.addresses.ipv6_addresses, sort_keys=True),
                request.timestamps.checked_at.isoformat(),
                expires_at.isoformat(),
            ),
        )
        self._connection.commit()

    def put_ip_location(self, request: IpLocationCacheWriteRequest) -> None:
        """Store one IP-location lookup result."""
        expires_at = request.timestamps.effective_expires_at()
        self._connection.execute(
            f"""
            INSERT OR REPLACE INTO {IP_LOCATION_TABLE} (
                provider, ip, country_code, region_code, region_name, checked_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.identity.provider,
                request.identity.ip,
                request.evidence.country_code,
                request.evidence.region_code,
                request.evidence.region_name,
                request.timestamps.checked_at.isoformat(),
                expires_at.isoformat(),
            ),
        )
        self._connection.commit()

    def replace_cache_table_rows(
        self,
        *,
        delegation_rows: Iterable[sqlite3.Row],
        host_resolution_rows: Iterable[sqlite3.Row],
        ip_location_rows: Iterable[sqlite3.Row],
    ) -> None:
        """Replace all physical cache tables with already-merged SQLite rows."""
        self._connection.execute(f"DELETE FROM {DELEGATION_TABLE}")
        self._connection.execute(f"DELETE FROM {HOST_RESOLUTION_TABLE}")
        self._connection.execute(f"DELETE FROM {IP_LOCATION_TABLE}")
        for row in delegation_rows:
            self._connection.execute(
                f"""
                INSERT OR REPLACE INTO {DELEGATION_TABLE} (
                    domain, resolver_key, ns_records_exist, ns_nodata, ns_nxdomain,
                    ns_retry_exhausted, ns_lookup_error, soa_exists, soa_absent,
                    soa_retry_exhausted, no_nameservers, nameservers, checked_at,
                    expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(row[column] for column in DELEGATION_COLUMNS),
            )
        for row in host_resolution_rows:
            self._connection.execute(
                f"""
                INSERT OR REPLACE INTO {HOST_RESOLUTION_TABLE} (
                    host, resolver_key, a_exists, a_nodata, a_nxdomain, a_timeout,
                    a_servfail, canonical_name, ipv4_addresses, ipv6_addresses,
                    checked_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(row[column] for column in HOST_RESOLUTION_COLUMNS),
            )
        for row in ip_location_rows:
            self._connection.execute(
                f"""
                INSERT OR REPLACE INTO {IP_LOCATION_TABLE} (
                    provider, ip, country_code, region_code, region_name, checked_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(row[column] for column in IP_LOCATION_COLUMNS),
            )
        self._connection.commit()

    def close(self) -> None:
        """Close the cache database."""
        self._connection.close()
