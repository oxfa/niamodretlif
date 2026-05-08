"""Worker cache write request payloads."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


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
    soa_exists: bool = False
    soa_nodata: bool = False
    soa_nxdomain: bool = False
    soa_timeout: bool = False
    soa_servfail: bool = False


@dataclass(frozen=True)
class HostResolutionCacheWriteRequest:
    """Write request for the physical host-resolution cache table."""

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
class IpLocationCacheWriteRequest:
    """Write request for the ip location cache table."""

    provider: str
    ip: str
    country_code: str
    region_code: str
    region_name: str
    checked_at: datetime
    ttl_days: int
