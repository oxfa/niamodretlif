"""DNS delegation and host-resolution checks for the domain pipeline."""

# pylint: disable=too-many-instance-attributes

from __future__ import annotations

import dataclasses
import ipaddress
import logging
import socket
import time
from typing import Any

import dns.edns
import dns.exception
import dns.resolver

from domain_pipeline.classifications import (
    CLASSIFICATION_DNS_DELEGATION_EXISTS,
    CLASSIFICATION_DNS_DELEGATION_NODATA,
    CLASSIFICATION_DNS_DELEGATION_NO_NAMESERVERS,
    CLASSIFICATION_DNS_DELEGATION_NXDOMAIN,
    CLASSIFICATION_DNS_DELEGATION_SERVFAIL,
    CLASSIFICATION_DNS_DELEGATION_TIMEOUT,
)

logger = logging.getLogger(__name__)

DEFAULT_ECS_FALLBACK_NAMESERVERS = ["8.8.8.8", "8.8.4.4"]
QUAD9_ECS_NAMESERVERS = ["9.9.9.11", "149.112.112.11"]
VERIFIED_ECS_NAMESERVERS = frozenset(
    [*DEFAULT_ECS_FALLBACK_NAMESERVERS, *QUAD9_ECS_NAMESERVERS]
)


def effective_dns_nameservers(dns_config: dict[str, Any]) -> list[str]:
    """Return resolver nameservers after applying ECS compatibility fallback."""
    nameservers = list(dns_config.get("nameservers") or [])
    ecs_payload = dict(dns_config.get("ecs") or {})
    if not ecs_payload.get("enabled"):
        return nameservers
    if not nameservers:
        return list(DEFAULT_ECS_FALLBACK_NAMESERVERS)
    if all(nameserver in VERIFIED_ECS_NAMESERVERS for nameserver in nameservers):
        return nameservers
    return list(DEFAULT_ECS_FALLBACK_NAMESERVERS)


def dns_resolver_key(dns_config: dict[str, Any]) -> str:
    """Return a deterministic cache key for one DNS resolver profile."""
    nameservers = effective_dns_nameservers(dns_config)
    nameserver_key = ",".join(nameservers) if nameservers else "system"
    ecs_payload = dict(dns_config.get("ecs") or {})
    if not ecs_payload.get("enabled"):
        return f"{nameserver_key}|ecs=off"
    return (
        f"{nameserver_key}|ecs={ecs_payload.get('subnet', '')}"
        f"@{ecs_payload.get('scope_prefix_length', 0)}"
    )


@dataclasses.dataclass(frozen=True)
class DelegationResult:
    """Result of the mandatory NS delegation query for a registrable domain."""

    domain: str
    ns_exists: bool = False
    ns_nodata: bool = False
    ns_nxdomain: bool = False
    ns_timeout: bool = False
    ns_servfail: bool = False
    no_nameservers: bool = False
    nameservers: list[str] = dataclasses.field(default_factory=list)
    from_cache: bool = False

    @property
    def status(self) -> str:
        """Return the compact delegation status used in rows and logs."""
        if self.ns_exists and self.nameservers:
            return "exists"
        if self.ns_nxdomain:
            return "nxdomain"
        if self.ns_nodata:
            return "nodata"
        if self.no_nameservers:
            return "no_nameservers"
        if self.ns_timeout:
            return "timeout"
        if self.ns_servfail:
            return "servfail"
        return "unknown"

    @property
    def actionable(self) -> bool:
        """Return whether the domain is delegated and currently actionable."""
        return self.status == "exists"


@dataclasses.dataclass(frozen=True)
class HostResolutionResult:
    """Result of optional host A/AAAA/CNAME resolution."""

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

    @property
    def resolved_ips(self) -> list[str]:
        """Return all usable IP addresses in deterministic order."""
        return [*self.ipv4_addresses, *self.ipv6_addresses]

    @property
    def status(self) -> str:
        """Return the compact host-resolution status used in rows and logs."""
        if self.a_exists and self.resolved_ips:
            return "resolved"
        if self.a_exists:
            return "no_usable_ips"
        if self.a_nxdomain:
            return "nxdomain"
        if self.a_nodata:
            return "nodata"
        if self.a_timeout:
            return "timeout"
        if self.a_servfail:
            return "servfail"
        return "unknown"


class RetryableDNSLookupError(RuntimeError):
    """Raised for transient DNS failures that should be retried."""


DNSResult = HostResolutionResult
"""Backward-compatible alias for host-resolution results.

New internal code should use ``HostResolutionResult``. The alias is kept for
older tests, imports, and row-building surfaces that still use DNS as the
physical cache/schema term for host-resolution data.
"""


def _delegation_classification(result: DelegationResult) -> str:
    """Return the pipeline classification for one delegation result."""
    if result.status == "exists":
        return CLASSIFICATION_DNS_DELEGATION_EXISTS
    if result.status == "nxdomain":
        return CLASSIFICATION_DNS_DELEGATION_NXDOMAIN
    if result.status == "nodata":
        return CLASSIFICATION_DNS_DELEGATION_NODATA
    if result.status == "no_nameservers":
        return CLASSIFICATION_DNS_DELEGATION_NO_NAMESERVERS
    if result.status == "timeout":
        return CLASSIFICATION_DNS_DELEGATION_TIMEOUT
    return CLASSIFICATION_DNS_DELEGATION_SERVFAIL


class DomainChecker:
    """Checker for mandatory delegation and optional host-resolution stages."""

    DEFAULT_NAMESERVERS: tuple[str, ...] = ()

    def __init__(
        self,
        *,
        nameservers: list[str] | tuple[str, ...] | None = None,
        timeout: float = 5.0,
        ecs: dict[str, Any] | None = None,
        retry_attempts: int = 3,
        delegation_retry_attempts: int | None = None,
        host_retry_attempts: int | None = None,
    ) -> None:
        dns_config = {
            "nameservers": list(nameservers or self.DEFAULT_NAMESERVERS),
            "ecs": ecs or {},
        }
        self.nameservers = effective_dns_nameservers(dns_config)
        self.timeout = timeout
        self.ecs = dict(ecs or {})
        self.retry_attempts = max(1, int(retry_attempts))
        self.delegation_retry_attempts = max(
            1,
            int(
                delegation_retry_attempts
                if delegation_retry_attempts is not None
                else self.retry_attempts
            ),
        )
        self.host_retry_attempts = max(
            1,
            int(
                host_retry_attempts
                if host_retry_attempts is not None
                else self.retry_attempts
            ),
        )
        self.resolver = dns.resolver.Resolver(configure=True)
        if self.nameservers:
            self.resolver.nameservers = list(self.nameservers)
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        if self.ecs.get("enabled"):
            subnet = str(self.ecs.get("subnet", "")).strip()
            if subnet:
                network_address, prefix = subnet.split("/", 1)
                self.resolver.use_edns(
                    edns=0,
                    options=[
                        dns.edns.ECSOption(
                            address=network_address,
                            srclen=int(prefix),
                            scopelen=int(self.ecs.get("scope_prefix_length", 0)),
                        )
                    ],
                )

    def resolver_key(self) -> str:
        """Return a deterministic cache key for the resolver profile."""
        return (
            f"{dns_resolver_key({'nameservers': self.nameservers, 'ecs': self.ecs})}"
            f"|timeout={self.timeout}"
        )

    def _sleep_before_retry(self, attempt_index: int) -> None:
        if attempt_index <= 0:
            return
        time.sleep(min(0.25 * (2 ** (attempt_index - 1)), 2.0))

    def _resolve_with_retries(
        self, name: str, record_type: str, retry_attempts: int
    ) -> Any:
        """Resolve one DNS record type, retrying transient timeout/SERVFAIL errors."""
        last_error: Exception | None = None
        for attempt_index in range(retry_attempts):
            self._sleep_before_retry(attempt_index)
            try:
                return self.resolver.resolve(name, record_type)
            except (dns.resolver.LifetimeTimeout, dns.resolver.NoNameservers) as exc:
                last_error = exc
                continue
            except dns.exception.Timeout as exc:
                last_error = exc
                continue
        if last_error is not None:
            raise RetryableDNSLookupError(str(last_error)) from last_error
        raise RetryableDNSLookupError(f"{record_type} lookup for {name} failed")

    def delegation_lookup(self, domain: str) -> DelegationResult:
        """Query NS records for one registrable domain."""
        try:
            answer = self._resolve_with_retries(
                domain, "NS", self.delegation_retry_attempts
            )
        except dns.resolver.NXDOMAIN:
            return DelegationResult(domain=domain, ns_nxdomain=True)
        except dns.resolver.NoAnswer:
            return DelegationResult(domain=domain, ns_nodata=True)
        except RetryableDNSLookupError as exc:
            text = str(exc).lower()
            if "time" in text:
                return DelegationResult(domain=domain, ns_timeout=True)
            return DelegationResult(domain=domain, ns_servfail=True)
        except (dns.exception.DNSException, socket.gaierror):
            return DelegationResult(domain=domain, ns_servfail=True)

        nameservers = sorted({str(rr.target).rstrip(".").lower() for rr in answer})
        if not nameservers:
            return DelegationResult(domain=domain, no_nameservers=True)
        return DelegationResult(domain=domain, ns_exists=True, nameservers=nameservers)

    def _query_record(
        self, host: str, record_type: str
    ) -> tuple[bool, bool, bool, bool, bool, str | None, list[str]]:
        """Query one host record type and return flat DNS flags."""
        exists = False
        nodata = False
        nxdomain = False
        timeout = False
        servfail = False
        cname: str | None = None
        addresses: list[str] = []
        try:
            answer = self._resolve_with_retries(
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
            if "time" in str(exc).lower():
                timeout = True
            else:
                servfail = True
        except (dns.exception.DNSException, socket.gaierror):
            servfail = True
        return exists, nodata, nxdomain, timeout, servfail, cname, addresses

    def host_resolution_lookup(self, host: str) -> HostResolutionResult:
        """Perform optional host A/AAAA/CNAME resolution."""
        a_exists, a_nodata, a_nxdomain, a_timeout, a_servfail, cname, ipv4 = (
            self._query_record(host, "A")
        )
        (
            aaaa_exists,
            aaaa_nodata,
            aaaa_nxdomain,
            aaaa_timeout,
            aaaa_servfail,
            _,
            ipv6,
        ) = self._query_record(host, "AAAA")
        if not a_exists and not aaaa_exists and not (a_nxdomain or aaaa_nxdomain):
            cname_exists, _, _, cname_timeout, cname_servfail, cname_value, _ = (
                self._query_record(host, "CNAME")
            )
            if cname_exists:
                cname = cname_value
            a_timeout = a_timeout or cname_timeout
            a_servfail = a_servfail or cname_servfail

        exists = a_exists or aaaa_exists or bool(cname)
        nxdomain = (a_nxdomain or aaaa_nxdomain) and not exists
        nodata = (a_nodata or aaaa_nodata) and not exists and not nxdomain
        timeout = (
            (a_timeout or aaaa_timeout) and not exists and not nxdomain and not nodata
        )
        servfail = (a_servfail or aaaa_servfail) and not exists
        result = HostResolutionResult(
            host=host,
            a_exists=exists,
            a_nodata=nodata,
            a_nxdomain=nxdomain,
            a_timeout=timeout,
            a_servfail=servfail,
            canonical_name=cname,
            ipv4_addresses=sorted(ipv4),
            ipv6_addresses=sorted(ipv6),
        )
        logger.debug("Host resolution %s -> %s", host, result.status)
        return result

    def dns_lookup(self, host: str) -> HostResolutionResult:
        """Compatibility wrapper for the optional host-resolution lookup."""
        return self.host_resolution_lookup(host)


def classify(host: str) -> tuple[str, DelegationResult, HostResolutionResult]:
    """Convenience function for ad hoc DNS actionability checks."""
    checker = DomainChecker()
    delegation = checker.delegation_lookup(host)
    host_resolution = (
        checker.host_resolution_lookup(host)
        if delegation.actionable
        else HostResolutionResult(host)
    )
    return _delegation_classification(delegation), delegation, host_resolution
