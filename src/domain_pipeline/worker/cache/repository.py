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
DELEGATION_COLUMNS = (
    "domain",
    "resolver_key",
    "ns_records_exist",
    "ns_nodata",
    "ns_nxdomain",
    "ns_retry_exhausted",
    "ns_lookup_error",
    "soa_exists",
    "soa_absent",
    "soa_retry_exhausted",
    "no_nameservers",
    "nameservers",
    "checked_at",
    "expires_at",
)


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
                    checked_at=_parse_datetime(str(row["checked_at"])),
                    expires_at=_parse_datetime(str(row["expires_at"])),
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
                checked_at=_parse_datetime(str(row["checked_at"])),
                expires_at=_parse_datetime(str(row["expires_at"])),
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
                checked_at=_parse_datetime(str(row["checked_at"])),
                expires_at=_parse_datetime(str(row["expires_at"])),
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
        connection = sqlite3.connect(path, check_same_thread=False)
        return cls(path, connection)

    def _initialize_schema(self) -> None:
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=NORMAL")
        self._connection.execute(f"""
            CREATE TABLE IF NOT EXISTS {DELEGATION_TABLE} (
                domain TEXT NOT NULL,
                resolver_key TEXT NOT NULL,
                ns_records_exist INTEGER NOT NULL,
                ns_nodata INTEGER NOT NULL,
                ns_nxdomain INTEGER NOT NULL,
                ns_retry_exhausted INTEGER NOT NULL,
                ns_lookup_error INTEGER NOT NULL,
                soa_exists INTEGER NOT NULL,
                soa_absent INTEGER NOT NULL,
                soa_retry_exhausted INTEGER NOT NULL,
                no_nameservers INTEGER NOT NULL,
                nameservers TEXT NOT NULL,
                checked_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY (domain, resolver_key)
            )
            """)
        self._connection.execute(f"""
            CREATE TABLE IF NOT EXISTS {HOST_RESOLUTION_TABLE} (
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
            CREATE TABLE IF NOT EXISTS {IP_LOCATION_TABLE} (
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
        self._validate_current_schema()
        self._connection.commit()

    def _validate_current_schema(self) -> None:
        """Reject restored cache databases that do not match the current schema."""
        expected_columns = {
            DELEGATION_TABLE: set(DELEGATION_COLUMNS),
            HOST_RESOLUTION_TABLE: {
                "host",
                "resolver_key",
                "a_exists",
                "a_nodata",
                "a_nxdomain",
                "a_timeout",
                "a_servfail",
                "canonical_name",
                "ipv4_addresses",
                "ipv6_addresses",
                "checked_at",
                "expires_at",
            },
            IP_LOCATION_TABLE: {
                "provider",
                "ip",
                "country_code",
                "region_code",
                "region_name",
                "checked_at",
                "expires_at",
            },
        }
        for table_name, required_columns in expected_columns.items():
            columns = {
                str(row["name"])
                for row in self._connection.execute(f"PRAGMA table_info({table_name})")
            }
            missing_columns = sorted(required_columns - columns)
            if missing_columns:
                raise sqlite3.DatabaseError(
                    f"cache table {table_name} is missing required columns: "
                    + ", ".join(missing_columns)
                )

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
                tuple(row[column] for column in row.keys()),
            )
        for row in ip_location_rows:
            self._connection.execute(
                f"""
                INSERT OR REPLACE INTO {IP_LOCATION_TABLE} (
                    provider, ip, country_code, region_code, region_name, checked_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(row[column] for column in row.keys()),
            )
        self._connection.commit()

    def close(self) -> None:
        """Close the cache database."""
        self._connection.close()
