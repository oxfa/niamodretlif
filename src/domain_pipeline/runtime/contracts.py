"""Explicit runtime contracts and payload types."""

# pylint: disable=duplicate-code,too-many-instance-attributes

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from ..checking import (
    DelegationResult,
    GeoPolicyDecision,
    HostResolutionResult,
    IPGeoResult,
)
from ..io.parser import ParsedDomainEntry
from ..shared import SourceJob

CacheTableName = Literal["delegation_history", "dns_history", "geo_history"]
ResultRoute = Literal["filtered", "review", "unactionable"]


@dataclass(frozen=True)
class ParsedHostItem:
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


@dataclass(frozen=True)
class HostResolutionWorkItem:
    """Item emitted by delegation for optional host-resolution processing."""

    parsed: ParsedHostItem
    delegation_result: DelegationResult


@dataclass(frozen=True)
class GeoWorkItem:
    """Item emitted by host resolution for geo processing."""

    parsed: ParsedHostItem
    delegation_result: DelegationResult
    host_resolution_result: HostResolutionResult
    classification: str

    @property
    def dns_result(self) -> HostResolutionResult:
        """Compatibility alias for the host-resolution result."""
        return self.host_resolution_result


@dataclass(frozen=True)
class CompletedHostResult:
    """Terminal result emitted to the writer boundary."""

    job: SourceJob
    entry: ParsedDomainEntry
    classification: str
    route: ResultRoute
    row: dict[str, Any]
    delegation_result: DelegationResult | None = None
    host_resolution_result: HostResolutionResult | None = None
    dns_result: HostResolutionResult | None = None
    geo_results: list[IPGeoResult] = field(default_factory=list)
    geo_policy: GeoPolicyDecision | None = None
    geo_attempts: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Keep legacy dns_result and explicit host_resolution_result synchronized."""
        if self.host_resolution_result is None and self.dns_result is not None:
            object.__setattr__(self, "host_resolution_result", self.dns_result)
        elif self.dns_result is None and self.host_resolution_result is not None:
            object.__setattr__(self, "dns_result", self.host_resolution_result)


@dataclass(frozen=True)
class DelegationCacheWriteRequest:
    """Write request for the delegation cache table."""

    domain: str
    resolver_key: str
    ns_exists: bool
    ns_nodata: bool
    ns_nxdomain: bool
    ns_timeout: bool
    ns_servfail: bool
    no_nameservers: bool
    nameservers: list[str]
    checked_at: datetime
    ttl_days: int


@dataclass(frozen=True)
class DNSCacheWriteRequest:
    """Write request for the physical dns_history host-resolution cache table."""

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


HostResolutionCacheWriteRequest = DNSCacheWriteRequest
"""Explicit name for host-resolution cache writes stored in dns_history."""


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
