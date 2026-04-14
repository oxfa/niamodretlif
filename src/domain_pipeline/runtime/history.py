"""Persistent cache storage for root RDAP, host DNS, and IP geo data."""

from __future__ import annotations

import dataclasses
import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional

from domain_pipeline.classifications import (
    ROOT_CACHE_CLASSIFICATIONS,
    ROOT_CLASSIFICATION_RDAP_LOOKUP_UNAVAILABLE,
    ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_REGISTERED,
    ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED,
)

logger = logging.getLogger(__name__)

ROOT_CLASSIFICATION_TABLE = "root_domain_classification_history"
RDAP_UNAVAILABLE_CACHE_SENTINEL = "__rdap_unavailable__"


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


def _normalize_root_classification(
    classification: str,
    *,
    statuses: list[str],
    statuses_complete: bool,
) -> str:
    """Map legacy cache labels onto the current explicit root taxonomy."""
    if classification == "alive":
        if not statuses_complete and statuses == [RDAP_UNAVAILABLE_CACHE_SENTINEL]:
            return ROOT_CLASSIFICATION_RDAP_LOOKUP_UNAVAILABLE
        return ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_REGISTERED
    if classification == "dead":
        return ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED
    return classification


@dataclasses.dataclass
class RootDomainClassificationRecord:
    """A cached RDAP verdict for one registrable domain."""

    domain: str
    classification: str
    statuses: list[str]
    statuses_complete: bool
    checked_at: datetime
    expires_at: datetime

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "RootDomainClassificationRecord":
        """Build a root classification record from a SQLite row."""
        statuses = _parse_string_list(str(row["statuses"]))
        statuses_complete = bool(row["statuses_complete"])
        return cls(
            domain=str(row["domain"]),
            classification=_normalize_root_classification(
                str(row["classification"]),
                statuses=statuses,
                statuses_complete=statuses_complete,
            ),
            statuses=statuses,
            statuses_complete=statuses_complete,
            checked_at=_parse_datetime(str(row["checked_at"])),
            expires_at=_parse_datetime(str(row["expires_at"])),
        )

    def is_expired(self, now: datetime) -> bool:
        """Return True when the cached record has expired."""
        return self.expires_at <= now

    def is_cached_rdap_unavailable(self) -> bool:
        """Return True when this cached root encodes a reusable RDAP-unavailable state."""
        return self.classification == ROOT_CLASSIFICATION_RDAP_LOOKUP_UNAVAILABLE


@dataclasses.dataclass
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
        """Build a geo cache record from a SQLite row."""
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
        """Return True when the cached record has expired."""
        return self.expires_at <= now


# pylint: disable=duplicate-code,too-many-instance-attributes
@dataclasses.dataclass
class DNSHistoryRecord:
    """A cached DNS lookup record keyed by host and resolver settings."""

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
    def from_row(cls, row: sqlite3.Row) -> "DNSHistoryRecord":
        """Build a DNS cache record from a SQLite row."""
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
        """Return True when the cached record has expired."""
        return self.expires_at <= now


# pylint: disable=too-many-public-methods
class PipelineCache:
    """Persistent SQLite-backed cache for root RDAP, DNS, and geo results."""

    def __init__(self, path: Path, connection: sqlite3.Connection) -> None:
        self.path = path
        self._connection = connection
        self._connection.row_factory = sqlite3.Row
        self._initialize_schema()

    @classmethod
    def load(cls, path: Path) -> "PipelineCache":
        """Open the SQLite cache and initialize the current schema."""
        path.parent.mkdir(parents=True, exist_ok=True)
        existed_before_open = path.exists()
        logger.debug(
            "Opening cache database at %s existed_before_open=%s",
            path,
            existed_before_open,
        )
        connection = sqlite3.connect(path)
        return cls(path, connection)

    def _initialize_schema(self) -> None:
        journal_mode = self._connection.execute("PRAGMA journal_mode=WAL").fetchone()
        synchronous_mode = self._connection.execute(
            "PRAGMA synchronous=NORMAL"
        ).fetchone()
        self._connection.execute(f"""
            CREATE TABLE IF NOT EXISTS {ROOT_CLASSIFICATION_TABLE} (
                domain TEXT PRIMARY KEY,
                classification TEXT NOT NULL,
                statuses TEXT NOT NULL DEFAULT '[]',
                statuses_complete INTEGER NOT NULL DEFAULT 0,
                checked_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """)
        self._connection.execute(f"""
            CREATE INDEX IF NOT EXISTS idx_{ROOT_CLASSIFICATION_TABLE}_expires_at
            ON {ROOT_CLASSIFICATION_TABLE}(expires_at)
            """)
        root_columns = {
            str(row["name"])
            for row in self._connection.execute(
                f"PRAGMA table_info({ROOT_CLASSIFICATION_TABLE})"
            )
        }
        if "statuses" not in root_columns:
            self._connection.execute(f"""
                ALTER TABLE {ROOT_CLASSIFICATION_TABLE}
                ADD COLUMN statuses TEXT NOT NULL DEFAULT '[]'
                """)
        if "statuses_complete" not in root_columns:
            self._connection.execute(f"""
                ALTER TABLE {ROOT_CLASSIFICATION_TABLE}
                ADD COLUMN statuses_complete INTEGER NOT NULL DEFAULT 0
                """)
        self._connection.execute("""
            CREATE TABLE IF NOT EXISTS geo_history (
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
        self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_geo_history_expires_at
            ON geo_history(expires_at)
            """)
        self._connection.execute("""
            CREATE TABLE IF NOT EXISTS dns_history (
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
        self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_dns_history_expires_at
            ON dns_history(expires_at)
            """)
        self._connection.commit()
        logger.debug(
            "Initialized cache schema at %s journal_mode=%s synchronous=%s",
            self.path,
            journal_mode[0] if journal_mode is not None else "(unknown)",
            synchronous_mode[0] if synchronous_mode is not None else "(unknown)",
        )

    def close(self) -> None:
        """Close the underlying database connection."""
        logger.debug("Closing cache database at %s", self.path)
        self._connection.close()

    def save(self, path: Optional[Path] = None) -> None:
        """Flush pending changes to disk."""
        del path
        logger.debug("Saving cache database at %s", self.path)
        self._connection.commit()

    # The cache lookup helper intentionally takes a few fields so call sites
    # can log the exact cache table, key, and expiration state in one place.
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def _log_cache_lookup(
        self,
        cache_name: str,
        cache_key: str,
        record: object | None,
        now: datetime,
        *,
        expires_at: datetime | None = None,
    ) -> None:
        if record is None:
            logger.debug(
                "Cache miss in %s at %s for %s", cache_name, self.path, cache_key
            )
            return
        if expires_at is not None and expires_at <= now:
            logger.debug(
                "Cache expired in %s at %s for %s (expired_at=%s now=%s)",
                cache_name,
                self.path,
                cache_key,
                expires_at.isoformat(),
                now.isoformat(),
            )
            return
        logger.debug("Cache hit in %s at %s for %s", cache_name, self.path, cache_key)

    def get_root(self, domain: str) -> Optional[RootDomainClassificationRecord]:
        """Return the cached RDAP verdict for a registrable domain if present."""
        row = self._connection.execute(
            f"""
            SELECT domain, classification, statuses, statuses_complete, checked_at, expires_at
            FROM {ROOT_CLASSIFICATION_TABLE}
            WHERE domain = ?
            """,
            (domain,),
        ).fetchone()
        if row is None:
            return None
        return RootDomainClassificationRecord.from_row(row)

    def get_fresh_root(
        self, domain: str, now: datetime
    ) -> Optional[RootDomainClassificationRecord]:
        """Return the cached root verdict when present and not expired."""
        record = self.get_root(domain)
        self._log_cache_lookup(
            ROOT_CLASSIFICATION_TABLE,
            f"root={domain}",
            record,
            now,
            expires_at=record.expires_at if record is not None else None,
        )
        if record is None or record.is_expired(now):
            return None
        return record

    # These write helpers mirror the cache table schema for readability.
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def upsert_root(
        self,
        domain: str,
        classification: str,
        statuses: list[str],
        statuses_complete: bool,
        checked_at: datetime,
        ttl_days: int,
    ) -> None:
        """Insert or update a cached RDAP verdict for a registrable domain."""
        classification = _normalize_root_classification(
            classification,
            statuses=statuses,
            statuses_complete=statuses_complete,
        )
        if classification not in ROOT_CACHE_CLASSIFICATIONS:
            raise ValueError(
                f"unsupported root classification for cache: {classification!r}"
            )
        checked_at = checked_at.astimezone(timezone.utc)
        expires_at = checked_at + timedelta(days=ttl_days)
        logger.debug(
            "Upserting root cache record at %s for root=%s classification=%s ttl_days=%d",
            self.path,
            domain,
            classification,
            ttl_days,
        )
        self._connection.execute(
            f"""
            INSERT INTO {ROOT_CLASSIFICATION_TABLE} (
                domain,
                classification,
                statuses,
                statuses_complete,
                checked_at,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                classification = excluded.classification,
                statuses = excluded.statuses,
                statuses_complete = excluded.statuses_complete,
                checked_at = excluded.checked_at,
                expires_at = excluded.expires_at
            """,
            (
                domain,
                classification,
                json.dumps(statuses),
                int(statuses_complete),
                checked_at.isoformat(),
                expires_at.isoformat(),
            ),
        )

    def remove_root(self, domain: str) -> bool:
        """Remove a cached root verdict if it exists."""
        cursor = self._connection.execute(
            f"DELETE FROM {ROOT_CLASSIFICATION_TABLE} WHERE domain = ?",
            (domain,),
        )
        if cursor.rowcount > 0:
            logger.debug(
                "Removed root cache record at %s for root=%s", self.path, domain
            )
        return cursor.rowcount > 0

    def items(self) -> Iterable[tuple[str, RootDomainClassificationRecord]]:
        """Return cached root classification entries."""
        cursor = self._connection.execute(f"""
            SELECT domain, classification, statuses, statuses_complete, checked_at, expires_at
            FROM {ROOT_CLASSIFICATION_TABLE}
            ORDER BY domain
            """)
        return ((record.domain, record) for record in self._iter_root_records(cursor))

    def _iter_root_records(
        self, cursor: sqlite3.Cursor
    ) -> Iterator[RootDomainClassificationRecord]:
        for row in cursor:
            yield RootDomainClassificationRecord.from_row(row)

    def get_geo(self, provider: str, ip: str) -> Optional[GeoHistoryRecord]:
        """Return the cached record for a provider/IP pair if present."""
        row = self._connection.execute(
            """
            SELECT provider, ip, country_code, region_code, region_name, checked_at, expires_at
            FROM geo_history
            WHERE provider = ? AND ip = ?
            """,
            (provider, ip),
        ).fetchone()
        if row is None:
            return None
        return GeoHistoryRecord.from_row(row)

    def get_fresh_geo(
        self, provider: str, ip: str, now: datetime
    ) -> Optional[GeoHistoryRecord]:
        """Return the cached geo record when present and not expired."""
        record = self.get_geo(provider, ip)
        self._log_cache_lookup(
            "geo_history",
            f"provider={provider} ip={ip}",
            record,
            now,
            expires_at=record.expires_at if record is not None else None,
        )
        if record is None or record.is_expired(now):
            return None
        return record

    # These write helpers mirror the cache table schema for readability.
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def upsert_geo(
        self,
        provider: str,
        ip: str,
        country_code: str,
        region_code: str,
        region_name: str,
        checked_at: datetime,
        ttl_days: int,
    ) -> None:
        """Insert or update a cached geo lookup record."""
        checked_at = checked_at.astimezone(timezone.utc)
        expires_at = checked_at + timedelta(days=ttl_days)
        logger.debug(
            "Upserting geo cache record at %s provider=%s ip=%s country=%s region=%s ttl_days=%d",
            self.path,
            provider,
            ip,
            country_code or "(none)",
            region_code or "(none)",
            ttl_days,
        )
        self._connection.execute(
            """
            INSERT INTO geo_history (
                provider,
                ip,
                country_code,
                region_code,
                region_name,
                checked_at,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider, ip) DO UPDATE SET
                country_code = excluded.country_code,
                region_code = excluded.region_code,
                region_name = excluded.region_name,
                checked_at = excluded.checked_at,
                expires_at = excluded.expires_at
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

    def remove_geo(self, provider: str, ip: str) -> bool:
        """Remove a cached geo lookup record if it exists."""
        cursor = self._connection.execute(
            "DELETE FROM geo_history WHERE provider = ? AND ip = ?",
            (provider, ip),
        )
        if cursor.rowcount > 0:
            logger.debug(
                "Removed geo cache record at %s provider=%s ip=%s",
                self.path,
                provider,
                ip,
            )
        return cursor.rowcount > 0

    def get_dns(self, host: str, resolver_key: str) -> Optional[DNSHistoryRecord]:
        """Return the cached DNS record for a host/resolver pair if present."""
        row = self._connection.execute(
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
        if row is None:
            return None
        return DNSHistoryRecord.from_row(row)

    def get_fresh_dns(
        self, host: str, resolver_key: str, now: datetime
    ) -> Optional[DNSHistoryRecord]:
        """Return the cached DNS record when present and not expired."""
        record = self.get_dns(host, resolver_key)
        self._log_cache_lookup(
            "dns_history",
            f"host={host} resolver={resolver_key}",
            record,
            now,
            expires_at=record.expires_at if record is not None else None,
        )
        if record is None or record.is_expired(now):
            return None
        return record

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def upsert_dns(
        self,
        host: str,
        resolver_key: str,
        *,
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
        """Insert or update a cached DNS lookup record."""
        checked_at = checked_at.astimezone(timezone.utc)
        expires_at = checked_at + timedelta(days=ttl_days)
        logger.debug(
            "Upserting DNS cache record at %s host=%s resolver=%s ttl_days=%d status_flags=%s",
            self.path,
            host,
            resolver_key,
            ttl_days,
            {
                "exists": a_exists,
                "nodata": a_nodata,
                "nxdomain": a_nxdomain,
                "timeout": a_timeout,
                "servfail": a_servfail,
            },
        )
        self._connection.execute(
            """
            INSERT INTO dns_history (
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
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(host, resolver_key) DO UPDATE SET
                a_exists = excluded.a_exists,
                a_nodata = excluded.a_nodata,
                a_nxdomain = excluded.a_nxdomain,
                a_timeout = excluded.a_timeout,
                a_servfail = excluded.a_servfail,
                canonical_name = excluded.canonical_name,
                ipv4_addresses = excluded.ipv4_addresses,
                ipv6_addresses = excluded.ipv6_addresses,
                checked_at = excluded.checked_at,
                expires_at = excluded.expires_at
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
                json.dumps(ipv4_addresses),
                json.dumps(ipv6_addresses),
                checked_at.isoformat(),
                expires_at.isoformat(),
            ),
        )

    def remove_dns(self, host: str, resolver_key: str) -> bool:
        """Remove a cached DNS lookup record if it exists."""
        cursor = self._connection.execute(
            "DELETE FROM dns_history WHERE host = ? AND resolver_key = ?",
            (host, resolver_key),
        )
        if cursor.rowcount > 0:
            logger.debug(
                "Removed DNS cache record at %s host=%s resolver=%s",
                self.path,
                host,
                resolver_key,
            )
        return cursor.rowcount > 0
