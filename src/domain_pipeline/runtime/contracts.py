"""Explicit async runtime contracts and payload types."""

# pylint: disable=duplicate-code

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from ..checking import DNSResult, GeoPolicyDecision, IPGeoResult, RDAPResult
from ..io.parser import ParsedDomainEntry
from ..shared import SourceJob

CacheTableName = Literal[
    "root_domain_classification_history",
    "dns_history",
    "geo_history",
]
ResultRoute = Literal["normal_output", "review", "drop"]


@dataclass(frozen=True)
class ParsedHostItem:  # pylint: disable=too-many-instance-attributes
    """Normalized parsed host with run-time context and output provenance overrides."""

    job: SourceJob
    entry: ParsedDomainEntry
    sequence: int
    total: int
    manual_filter_pass: bool = False
    manual_add: bool = False
    source_id_override: str | None = None
    source_input_label_override: str | None = None
    source_ids: tuple[str, ...] = ()
    source_input_labels: tuple[str, ...] = ()
    prepared_rdap_status: str | None = None
    prepared_authoritative_base_url: str | None = None


@dataclass(frozen=True)
class DNSWorkItem:
    """Item emitted by RDAP for DNS processing."""

    parsed: ParsedHostItem
    rdap_result: RDAPResult | None


@dataclass(frozen=True)
class GeoWorkItem:
    """Item emitted by DNS for geo processing."""

    parsed: ParsedHostItem
    rdap_result: RDAPResult | None
    dns_result: DNSResult
    classification: str


@dataclass(frozen=True)
class CompletedHostResult:  # pylint: disable=too-many-instance-attributes
    """Terminal result emitted to the writer boundary."""

    job: SourceJob
    entry: ParsedDomainEntry
    classification: str
    route: ResultRoute
    row: dict[str, Any]
    rdap_result: RDAPResult | None
    dns_result: DNSResult
    geo_results: list[IPGeoResult] = field(default_factory=list)
    geo_policy: GeoPolicyDecision | None = None
    geo_attempts: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class CacheReadRequest:
    """Read request routed through the explicit async cache facade."""

    table: CacheTableName
    key: tuple[str, ...]
    now: datetime


@dataclass(frozen=True)
class CacheReadResponse:
    """Response from the async cache facade."""

    table: CacheTableName
    key: tuple[str, ...]
    record: object | None


@dataclass(frozen=True)
class RootCacheWriteRequest:
    """Write request for the root cache table."""

    domain: str
    classification: str
    statuses: list[str]
    statuses_complete: bool
    checked_at: datetime
    ttl_days: int


@dataclass(frozen=True)
class DNSCacheWriteRequest:  # pylint: disable=too-many-instance-attributes
    """Write request for the DNS cache table."""

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
    ttl_days: int


@dataclass(frozen=True)
class GeoCacheWriteRequest:
    """Write request for the geo cache table."""

    provider: str
    ip: str
    country_code: str
    region_code: str
    region_name: str
    checked_at: datetime
    ttl_days: int


@dataclass(frozen=True)
class ValidationFailure:
    """Prior-handoff validation failure."""

    reason: str
    path: Path
