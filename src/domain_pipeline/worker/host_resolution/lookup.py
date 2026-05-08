"""Host-resolution DNS lookup ownership."""

from __future__ import annotations

import dataclasses
import ipaddress
import logging
import socket
from typing import Any

import dns.exception
import dns.resolver

from domain_pipeline.worker.dns_query.lookup import (
    DNSQueryService,
    RetryableDNSLookupError,
    dns_stage_query_rate_limit,
    dns_stage_resolver_profile,
    dns_stage_retry_backoff_base_seconds,
    dns_stage_timeout,
)
from domain_pipeline.worker.host_resolution.query_coordinator import (
    HostResolutionQueryCoordinator,
)

logger = logging.getLogger(__name__)

DEFAULT_ECS_FALLBACK_NAMESERVERS = ["8.8.8.8", "8.8.4.4"]
QUAD9_ECS_PUBLIC_DNS_NAMESERVERS = ["9.9.9.11", "149.112.112.11"]
VERIFIED_ECS_NAMESERVERS = frozenset(
    [*DEFAULT_ECS_FALLBACK_NAMESERVERS, *QUAD9_ECS_PUBLIC_DNS_NAMESERVERS]
)
CNAME_CHAIN_LIMIT = 8


def effective_host_resolution_resolvers(dns_profile: dict[str, Any]) -> list[str]:
    """Return host-resolution resolvers after applying ECS fallback."""
    resolvers = list(dns_profile.get("resolvers") or [])
    ecs_payload = dict(dns_profile.get("ecs") or {})
    if not ecs_payload.get("enabled"):
        return resolvers
    if not resolvers:
        return list(DEFAULT_ECS_FALLBACK_NAMESERVERS)
    if all(resolver in VERIFIED_ECS_NAMESERVERS for resolver in resolvers):
        return resolvers
    return list(DEFAULT_ECS_FALLBACK_NAMESERVERS)


def effective_host_resolution_nameservers(dns_profile: dict[str, Any]) -> list[str]:
    """Return effective host-resolution recursive nameservers."""
    return effective_host_resolution_resolvers(dns_profile)


def host_resolution_dns_profile(dns_config: dict[str, Any]) -> dict[str, Any]:
    """Return the normalized host-resolution resolver profile."""
    host_config = dict(dns_config.get("host_resolution") or {})
    resolvers, weights = dns_stage_resolver_profile(dns_config, host_config)
    profile = {
        "resolvers": resolvers,
        "resolver_weights": weights,
        "timeout": dns_stage_timeout(dns_config, host_config),
        "retry_backoff_base_seconds": dns_stage_retry_backoff_base_seconds(
            dns_config, host_config
        ),
        "ecs": dict(host_config.get("ecs") or {}),
        "query_rate_limit": dns_stage_query_rate_limit(dns_config, host_config),
    }
    effective_resolvers = effective_host_resolution_resolvers(profile)
    if effective_resolvers != resolvers:
        profile["resolver_weights"] = {}
    profile["resolvers"] = effective_resolvers
    return profile


@dataclasses.dataclass(frozen=True)
class HostResolutionResult:
    """Result of optional host A/AAAA resolution after following CNAME aliases."""

    host: str
    a_exists: bool = False
    a_nodata: bool = False
    a_nxdomain: bool = False
    a_timeout: bool = False
    a_servfail: bool = False
    canonical_name: str | None = None
    ipv4_addresses: list[str] = dataclasses.field(default_factory=list)
    ipv6_addresses: list[str] = dataclasses.field(default_factory=list)
    from_cache: bool = False
    detail: str = ""

    @property
    def resolved_ips(self) -> list[str]:
        """Return all usable IP addresses in deterministic order."""
        return [*self.ipv4_addresses, *self.ipv6_addresses]

    @property
    def status(self) -> str:
        """Return the compact host-resolution status used in rows and logs."""
        if self.a_exists and self.resolved_ips:
            return "resolved"
        if self.a_nxdomain:
            return "nxdomain"
        if self.a_nodata:
            return "nodata"
        if self.a_timeout:
            return "timeout"
        if self.a_servfail:
            return "servfail"
        return "unknown"

    @property
    def reason(self) -> str:
        """Return a readable reason for review rows and raw audit output."""
        canonical_name = (self.canonical_name or "").strip()
        followed_cname = (
            bool(canonical_name) and canonical_name.lower() != self.host.lower()
        )
        if self.status == "resolved":
            return "resolved"
        if self.status == "nxdomain":
            return (
                "canonical target returned NXDOMAIN"
                if followed_cname
                else "host resolution returned NXDOMAIN"
            )
        if self.status == "nodata":
            return (
                "canonical target has no A/AAAA records"
                if followed_cname
                else "host resolution returned NODATA"
            )
        if self.status == "timeout":
            return "host resolution timed out after retries"
        if self.status == "servfail":
            if self.detail == "cname_loop":
                return "CNAME loop detected during host resolution"
            if self.detail == "cname_depth_exceeded":
                return "CNAME chain depth exceeded during host resolution"
            return "host resolution returned SERVFAIL after retries"
        return "host resolution produced inconsistent address data"


@dataclasses.dataclass(frozen=True)
class _HostRecordLookup:
    """Flat DNS flags returned by one host-record query."""

    exists: bool = False
    nodata: bool = False
    nxdomain: bool = False
    timeout: bool = False
    servfail: bool = False
    cname: str | None = None
    addresses: list[str] = dataclasses.field(default_factory=list)


class HostResolutionChecker(DNSQueryService):
    """Checker for exact-host A/AAAA/CNAME resolution lookups."""

    def __init__(
        self,
        *,
        resolvers: list[Any] | tuple[Any, ...] | None = None,
        nameservers: list[str] | tuple[str, ...] | None = None,
        timeout: float = 5.0,
        ecs: dict[str, Any] | None = None,
        query_rate_limit: dict[str, Any] | None = None,
        query_coordinator: Any | None = None,
        host_resolution_dns: dict[str, Any] | None = None,
        retry_attempts: int = 3,
        host_retry_attempts: int | None = None,
    ) -> None:
        host_resolution_payload = dict(host_resolution_dns or {})
        if ecs and "ecs" not in host_resolution_payload:
            host_resolution_payload["ecs"] = ecs
        default_resolvers = (
            list(resolvers)
            if resolvers is not None
            else list(nameservers or self.DEFAULT_NAMESERVERS)
        )
        dns_config = {
            "default_resolvers": default_resolvers,
            "timeout": float(timeout),
            "query_rate_limit": query_rate_limit or {},
            "host_resolution": host_resolution_payload,
        }
        self.host_resolution_dns_profile = host_resolution_dns_profile(dns_config)
        self.resolvers = list(self.host_resolution_dns_profile["resolvers"])
        self.nameservers = list(self.resolvers)
        self.timeout = float(self.host_resolution_dns_profile["timeout"])
        self.ecs = dict(self.host_resolution_dns_profile["ecs"])
        self.query_rate_limit = dict(
            self.host_resolution_dns_profile["query_rate_limit"]
        )
        self.host_retry_attempts = max(
            1,
            int(
                host_retry_attempts
                if host_retry_attempts is not None
                else retry_attempts
            ),
        )
        self.host_resolution_query_coordinator = (
            query_coordinator
            if query_coordinator is not None
            else self._build_query_coordinator(
                coordinator_cls=HostResolutionQueryCoordinator,
                dns_profile=self.host_resolution_dns_profile,
            )
        )
        self.query_coordinator = self.host_resolution_query_coordinator

    @property
    def resolver(self) -> Any:
        """Return the first host-resolution endpoint resolver."""
        return self.host_resolution_query_coordinator.primary_resolver

    @resolver.setter
    def resolver(self, resolver: Any) -> None:
        """Install one resolver for host-resolution DNS queries."""
        self.host_resolution_query_coordinator = self._single_resolver_coordinator(
            coordinator_cls=HostResolutionQueryCoordinator,
            resolver_key=self.host_resolution_resolver_key(),
            resolver=resolver,
        )
        self.query_coordinator = self.host_resolution_query_coordinator

    def resolver_key(self) -> str:
        """Return the host-resolution resolver profile key."""
        return self.host_resolution_resolver_key()

    def host_resolution_resolver_key(self) -> str:
        """Return a deterministic cache key for the host-resolution resolver profile."""
        return self.host_resolution_query_coordinator.resolver_key()

    def _resolve_host_record(
        self, name: str, record_type: str, retry_attempts: int
    ) -> Any:
        """Resolve one host-resolution DNS record with the host profile."""
        return self._resolve_with_coordinator(
            self.host_resolution_query_coordinator,
            name,
            record_type,
            retry_attempts,
        )

    def _query_record(self, host: str, record_type: str) -> _HostRecordLookup:
        """Query one host record type and return flat DNS flags."""
        exists = False
        nodata = False
        nxdomain = False
        timeout = False
        servfail = False
        cname: str | None = None
        addresses: list[str] = []
        try:
            answer = self._resolve_host_record(
                host, record_type, self.host_retry_attempts
            )
            for rr in answer:
                if record_type in {"A", "AAAA"}:
                    address = str(rr)
                    try:
                        ipaddress.ip_address(address)
                    except ValueError:
                        continue
                    addresses.append(address)
                    exists = True
                elif record_type == "CNAME":
                    exists = True
                    cname = str(rr.target).rstrip(".")
                    break
        except dns.resolver.NXDOMAIN:
            nxdomain = True
        except dns.resolver.NoAnswer:
            nodata = True
        except RetryableDNSLookupError as exc:
            if exc.is_timeout:
                timeout = True
            else:
                servfail = True
        except (dns.exception.DNSException, socket.gaierror):
            servfail = True
        return _HostRecordLookup(
            exists=exists,
            nodata=nodata,
            nxdomain=nxdomain,
            timeout=timeout,
            servfail=servfail,
            cname=cname,
            addresses=addresses,
        )

    @staticmethod
    def _normal_name(name: str) -> str:
        """Return a case-insensitive DNS name key without the presentation root."""
        return name.rstrip(".").lower()

    @staticmethod
    def _terminal_host_result(
        *,
        host: str,
        canonical_name: str | None,
        a_record: _HostRecordLookup,
        aaaa_record: _HostRecordLookup,
        cname_record: _HostRecordLookup | None = None,
    ) -> HostResolutionResult:
        """Build a final host-resolution result from one queried DNS name."""
        if a_record.addresses or aaaa_record.addresses:
            return HostResolutionResult(
                host=host,
                a_exists=a_record.exists or aaaa_record.exists,
                canonical_name=canonical_name,
                ipv4_addresses=sorted(a_record.addresses),
                ipv6_addresses=sorted(aaaa_record.addresses),
            )
        cname_timeout = bool(cname_record and cname_record.timeout)
        cname_servfail = bool(cname_record and cname_record.servfail)
        if a_record.timeout or aaaa_record.timeout or cname_timeout:
            return HostResolutionResult(
                host=host, a_timeout=True, canonical_name=canonical_name
            )
        if a_record.servfail or aaaa_record.servfail or cname_servfail:
            return HostResolutionResult(
                host=host, a_servfail=True, canonical_name=canonical_name
            )
        if a_record.nxdomain or aaaa_record.nxdomain:
            return HostResolutionResult(
                host=host, a_nxdomain=True, canonical_name=canonical_name
            )
        if a_record.nodata or aaaa_record.nodata:
            return HostResolutionResult(
                host=host, a_nodata=True, canonical_name=canonical_name
            )
        return HostResolutionResult(host=host, canonical_name=canonical_name)

    def host_resolution_lookup(self, host: str) -> HostResolutionResult:
        """Resolve host A/AAAA, following bounded CNAME chains to final outcome."""
        current_name = host
        canonical_name: str | None = None
        visited: set[str] = set()
        for _depth in range(CNAME_CHAIN_LIMIT):
            name_key = self._normal_name(current_name)
            if name_key in visited:
                result = HostResolutionResult(
                    host=host,
                    a_servfail=True,
                    canonical_name=canonical_name or current_name,
                    detail="cname_loop",
                )
                logger.debug("Host resolution %s -> %s", host, result.status)
                return result
            visited.add(name_key)

            a_record = self._query_record(current_name, "A")
            aaaa_record = self._query_record(current_name, "AAAA")
            if a_record.addresses or aaaa_record.addresses:
                result = self._terminal_host_result(
                    host=host,
                    canonical_name=canonical_name,
                    a_record=a_record,
                    aaaa_record=aaaa_record,
                )
                logger.debug("Host resolution %s -> %s", host, result.status)
                return result

            cname_record = self._query_record(current_name, "CNAME")
            if cname_record.exists and cname_record.cname:
                canonical_name = self._normal_name(cname_record.cname)
                current_name = canonical_name
                continue
            result = self._terminal_host_result(
                host=host,
                canonical_name=canonical_name,
                a_record=a_record,
                aaaa_record=aaaa_record,
                cname_record=cname_record,
            )
            logger.debug("Host resolution %s -> %s", host, result.status)
            return result

        result = HostResolutionResult(
            host=host,
            a_servfail=True,
            canonical_name=canonical_name,
            detail="cname_depth_exceeded",
        )
        logger.debug("Host resolution %s -> %s", host, result.status)
        return result
