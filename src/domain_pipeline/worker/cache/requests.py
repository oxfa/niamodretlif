"""Worker cache write request payloads."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from domain_pipeline.worker.delegation.lookup import (
    DelegationDnsEvidence,
    DelegationSoaEvidence,
)
from domain_pipeline.worker.host_resolution.lookup import (
    HostResolutionAddressEvidence,
    HostResolutionDnsEvidence,
)


@dataclass(frozen=True)
class CacheIdentity:
    """Resolver-scoped DNS cache identity."""

    name: str
    resolver_key: str


@dataclass(frozen=True)
class IpLocationCacheIdentity:
    """Provider-scoped IP-location cache identity."""

    provider: str
    ip: str


@dataclass(frozen=True)
class CacheTimestamps:
    """Cache write timestamp and TTL policy."""

    checked_at: datetime
    ttl_days: int = 0
    expires_at: datetime | None = None

    def effective_expires_at(self) -> datetime:
        """Return the persisted cache expiration timestamp."""
        if self.expires_at is not None:
            return self.expires_at
        return self.checked_at + timedelta(days=self.ttl_days)


@dataclass(frozen=True)
class IpLocationCacheEvidence:
    """IP-location cache payload fields."""

    country_code: str
    region_code: str
    region_name: str


def cache_identity_from_mapping(row: Any, *, name_field: str) -> CacheIdentity:
    """Build a DNS cache identity from a row-like mapping."""
    return CacheIdentity(
        name=str(row[name_field]),
        resolver_key=str(row["resolver_key"]),
    )


def delegation_dns_evidence_from_mapping(row: Any) -> DelegationDnsEvidence:
    """Build delegation NS evidence from a row-like mapping."""
    return DelegationDnsEvidence(
        ns_records_exist=bool(row["ns_records_exist"]),
        ns_nodata=bool(row["ns_nodata"]),
        ns_nxdomain=bool(row["ns_nxdomain"]),
        ns_retry_exhausted=bool(row["ns_retry_exhausted"]),
        ns_lookup_error=bool(row["ns_lookup_error"]),
    )


def delegation_soa_evidence_from_mapping(row: Any) -> DelegationSoaEvidence:
    """Build delegation SOA evidence from a row-like mapping."""
    return DelegationSoaEvidence(
        soa_exists=bool(row["soa_exists"]),
        soa_absent=bool(row["soa_absent"]),
        soa_retry_exhausted=bool(row["soa_retry_exhausted"]),
    )


def host_resolution_dns_evidence_from_mapping(row: Any) -> HostResolutionDnsEvidence:
    """Build host-resolution DNS evidence from a row-like mapping."""
    return HostResolutionDnsEvidence(
        a_exists=bool(row["a_exists"]),
        a_nodata=bool(row["a_nodata"]),
        a_nxdomain=bool(row["a_nxdomain"]),
        a_timeout=bool(row["a_timeout"]),
        a_servfail=bool(row["a_servfail"]),
    )


@dataclass(frozen=True)
class DelegationCacheWriteRequest:
    """Write request for the delegation cache table."""

    identity: CacheIdentity
    dns: DelegationDnsEvidence
    soa: DelegationSoaEvidence
    no_nameservers: bool
    nameservers: list[str]
    timestamps: CacheTimestamps


@dataclass(frozen=True)
class HostResolutionCacheWriteRequest:
    """Write request for the physical host-resolution cache table."""

    identity: CacheIdentity
    dns: HostResolutionDnsEvidence
    addresses: HostResolutionAddressEvidence
    timestamps: CacheTimestamps


@dataclass(frozen=True)
class IpLocationCacheWriteRequest:
    """Write request for the IP-location cache table."""

    identity: IpLocationCacheIdentity
    evidence: IpLocationCacheEvidence
    timestamps: CacheTimestamps
