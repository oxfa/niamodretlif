"""DNS delegation and host-resolution checks for the domain pipeline."""

# pylint: disable=too-many-arguments,too-many-instance-attributes

from __future__ import annotations

import dataclasses
import ipaddress
import logging
import socket
import time
from typing import Any

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
from domain_pipeline.checking.dns_query_coordinator import (
    DNSEndpoint,
    DNSProviderRateLimit,
    DNSQueryCoordinator,
    DNSQueryCoordinatorConfig,
    DNSQueryCoordinatorRegistry,
    PROVIDER_CLOUDFLARE_PUBLIC_DNS,
    PROVIDER_CUSTOM,
    PROVIDER_GOOGLE_PUBLIC_DNS,
    PROVIDER_OPENDNS_PUBLIC_DNS,
    PROVIDER_QUAD9_ECS,
    PROVIDER_SYSTEM_RESOLVER,
    build_dns_endpoint,
)

logger = logging.getLogger(__name__)

DEFAULT_ECS_FALLBACK_NAMESERVERS = ["8.8.8.8", "8.8.4.4"]
QUAD9_ECS_NAMESERVERS = ["9.9.9.11", "149.112.112.11"]
VERIFIED_ECS_NAMESERVERS = frozenset(
    [*DEFAULT_ECS_FALLBACK_NAMESERVERS, *QUAD9_ECS_NAMESERVERS]
)
CNAME_CHAIN_LIMIT = 8
DNS_PROFILE_KEYS = (
    "nameservers",
    "timeout",
    "ecs",
    "query_rate_limit",
    "query_balancer",
)
# Official provider data inspected from primary docs on 2026-05-01:
# - Azure default resolver: 1000 QPS and 200 pending DNS queries per VM.
# - Google Public DNS: rate-limit increase guidance starts above 1500 QPS per
#   client IPv4 address or IPv6 /64.
# - Quad9: contact support above 500 QPS from a single egress IP.
# - Cloudflare 1.1.1.1: no numeric public QPS limit published; docs warn that
#   high-rate single-IP, proxied, and high-SERVFAIL traffic may be rate limited.
# - Cisco Umbrella/OpenDNS: public resolver IPs are documented; DNS Security
#   packages document 5000 DNS queries per Covered User per day as a monthly
#   average, not a public per-client QPS ceiling.
# Project caps below are worker-local and intentionally below published numeric
# thresholds; Cloudflare/OpenDNS use conservative project caps because their
# public docs do not publish per-client QPS ceilings.
DEFAULT_DNS_PROVIDER_LIMITS = {
    PROVIDER_SYSTEM_RESOLVER: DNSProviderRateLimit(
        qps_per_worker=50.0, burst=50, max_pending=100
    ),
    PROVIDER_GOOGLE_PUBLIC_DNS: DNSProviderRateLimit(
        qps_per_worker=50.0, burst=50, max_pending=100
    ),
    PROVIDER_QUAD9_ECS: DNSProviderRateLimit(
        qps_per_worker=25.0, burst=25, max_pending=50
    ),
    PROVIDER_CLOUDFLARE_PUBLIC_DNS: DNSProviderRateLimit(
        qps_per_worker=25.0, burst=25, max_pending=50
    ),
    PROVIDER_OPENDNS_PUBLIC_DNS: DNSProviderRateLimit(
        qps_per_worker=25.0, burst=25, max_pending=50
    ),
    PROVIDER_CUSTOM: DNSProviderRateLimit(
        qps_per_worker=25.0, burst=25, max_pending=50
    ),
}


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
    nameserver_key = ",".join(nameservers) if nameservers else "system_resolver"
    ecs_payload = dict(dns_config.get("ecs") or {})
    if not ecs_payload.get("enabled"):
        return f"{nameserver_key}|ecs=off"
    return (
        f"{nameserver_key}|ecs={ecs_payload.get('subnet', '')}"
        f"@{ecs_payload.get('scope_prefix_length', 0)}"
    )


def _provider_limit_from_config(
    payload: dict[str, Any], fallback: DNSProviderRateLimit
) -> DNSProviderRateLimit:
    qps = float(payload.get("qps_per_worker", fallback.qps_per_worker))
    burst = int(payload.get("burst", fallback.burst))
    max_pending = int(payload.get("max_pending", fallback.max_pending))
    return DNSProviderRateLimit(
        qps_per_worker=max(qps, 0.001),
        burst=max(burst, 1),
        max_pending=max(max_pending, 1),
    )


def dns_query_coordinator_config(
    *,
    query_rate_limit: dict[str, Any] | None,
    query_balancer: dict[str, Any] | None,
) -> DNSQueryCoordinatorConfig:
    """Return normalized DNS query coordination settings."""
    rate_payload = dict(query_rate_limit or {})
    balancer_payload = dict(query_balancer or {})
    provider_payloads = dict(rate_payload.get("providers") or {})
    provider_limits = {
        provider: _provider_limit_from_config(
            dict(provider_payloads.get(provider) or {}), fallback
        )
        for provider, fallback in DEFAULT_DNS_PROVIDER_LIMITS.items()
    }
    return DNSQueryCoordinatorConfig(
        rate_limit_enabled=bool(rate_payload.get("enabled", True)),
        balancer_enabled=bool(balancer_payload.get("enabled", True)),
        balancer_strategy=str(balancer_payload.get("strategy", "round_robin")),
        provider_limits=provider_limits,
    )


def _coordinator_config_key(config: DNSQueryCoordinatorConfig) -> str:
    provider_parts = []
    for provider in sorted(config.provider_limits):
        limit = config.provider_limits[provider]
        provider_parts.append(
            f"{provider}:{limit.qps_per_worker:g}:{limit.burst}:{limit.max_pending}"
        )
    return (
        f"rate={int(config.rate_limit_enabled)}"
        f"|balancer={int(config.balancer_enabled)}:{config.balancer_strategy}"
        f"|providers={';'.join(provider_parts)}"
    )


def dns_query_coordinator_key(
    *,
    nameservers: list[str],
    timeout: float,
    ecs: dict[str, Any],
    query_config: DNSQueryCoordinatorConfig,
) -> str:
    """Return a process-local key for sharing one DNS query coordinator."""
    resolver_key = dns_resolver_key({"nameservers": nameservers, "ecs": ecs})
    return f"{resolver_key}|timeout={timeout}|{_coordinator_config_key(query_config)}"


def stage_dns_profile(
    base_dns_config: dict[str, Any], stage_config: dict[str, Any] | None
) -> dict[str, Any]:
    """Return one DNS resolver profile after applying stage-level overrides."""
    profile = {
        "nameservers": list(base_dns_config.get("nameservers") or []),
        "timeout": float(base_dns_config.get("timeout", 5.0)),
        "ecs": dict(base_dns_config.get("ecs") or {}),
        "query_rate_limit": dict(base_dns_config.get("query_rate_limit") or {}),
        "query_balancer": dict(base_dns_config.get("query_balancer") or {}),
    }
    for key, value in dict(stage_config or {}).items():
        if key in DNS_PROFILE_KEYS and value is not None:
            profile[key] = value
    profile["nameservers"] = effective_dns_nameservers(profile)
    profile["timeout"] = float(profile["timeout"])
    profile["ecs"] = dict(profile.get("ecs") or {})
    profile["query_rate_limit"] = dict(profile.get("query_rate_limit") or {})
    profile["query_balancer"] = dict(profile.get("query_balancer") or {})
    return profile


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
        query_rate_limit: dict[str, Any] | None = None,
        query_balancer: dict[str, Any] | None = None,
        query_coordinator: DNSQueryCoordinator | None = None,
        delegation_dns: dict[str, Any] | None = None,
        host_resolution_dns: dict[str, Any] | None = None,
        retry_attempts: int = 3,
        delegation_retry_attempts: int | None = None,
        host_retry_attempts: int | None = None,
    ) -> None:
        dns_config = {
            "nameservers": list(nameservers or self.DEFAULT_NAMESERVERS),
            "timeout": float(timeout),
            "ecs": ecs or {},
            "query_rate_limit": query_rate_limit or {},
            "query_balancer": query_balancer or {},
        }
        self.delegation_dns_profile = stage_dns_profile(dns_config, delegation_dns)
        self.host_resolution_dns_profile = stage_dns_profile(
            dns_config, host_resolution_dns
        )
        self.delegation_nameservers = list(self.delegation_dns_profile["nameservers"])
        self.nameservers = list(self.host_resolution_dns_profile["nameservers"])
        self.timeout = timeout
        self.ecs = dict(self.host_resolution_dns_profile["ecs"])
        self.query_rate_limit = dict(
            self.host_resolution_dns_profile["query_rate_limit"]
        )
        self.query_balancer = dict(self.host_resolution_dns_profile["query_balancer"])
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
        if query_coordinator is not None:
            self.delegation_query_coordinator = query_coordinator
            self.host_resolution_query_coordinator = query_coordinator
        else:
            self.delegation_query_coordinator = self._build_query_coordinator(
                "delegation", self.delegation_dns_profile
            )
            self.host_resolution_query_coordinator = self._build_query_coordinator(
                "host_resolution", self.host_resolution_dns_profile
            )
        self.query_coordinator = self.host_resolution_query_coordinator

    @property
    def resolver(self) -> Any:
        """Return the first endpoint resolver for compatibility with tests."""
        return self.query_coordinator.primary_resolver

    @resolver.setter
    def resolver(self, resolver: Any) -> None:
        """Install a resolver fake as a coordinator for compatibility tests."""
        query_config = DNSQueryCoordinatorConfig(
            rate_limit_enabled=False,
            balancer_enabled=False,
            balancer_strategy="round_robin",
            provider_limits={},
        )
        coordinator = DNSQueryCoordinator(
            endpoints=[
                DNSEndpoint(
                    provider=PROVIDER_CUSTOM,
                    address=None,
                    resolver=resolver,
                )
            ],
            resolver_key=self.resolver_key(),
            config=query_config,
        )
        self.delegation_query_coordinator = coordinator
        self.host_resolution_query_coordinator = coordinator
        self.query_coordinator = coordinator

    def _build_query_coordinator(
        self, stage: str, dns_profile: dict[str, Any]
    ) -> DNSQueryCoordinator:
        """Build or retrieve the shared DNS query coordinator for this checker."""
        query_config = dns_query_coordinator_config(
            query_rate_limit=dns_profile.get("query_rate_limit", {}),
            query_balancer=dns_profile.get("query_balancer", {}),
        )
        endpoint_nameservers: list[str | None] = list(
            dns_profile.get("nameservers") or []
        ) or [None]
        endpoints = [
            build_dns_endpoint(
                nameserver=nameserver,
                timeout=float(dns_profile.get("timeout", 5.0)),
                ecs=dict(dns_profile.get("ecs") or {}),
            )
            for nameserver in endpoint_nameservers
        ]
        resolver_key = (
            f"{dns_resolver_key(dns_profile)}"
            f"|timeout={float(dns_profile.get('timeout', 5.0))}"
        )
        registry_key = dns_query_coordinator_key(
            nameservers=list(dns_profile.get("nameservers") or []),
            timeout=float(dns_profile.get("timeout", 5.0)),
            ecs=dict(dns_profile.get("ecs") or {}),
            query_config=query_config,
        )
        return DNSQueryCoordinatorRegistry.get_or_create(
            registry_key=f"stage={stage}|{registry_key}",
            endpoints=endpoints,
            resolver_key=resolver_key,
            config=query_config,
        )

    def resolver_key(self) -> str:
        """Return the host-resolution resolver profile key for compatibility."""
        return self.host_resolution_resolver_key()

    def delegation_resolver_key(self) -> str:
        """Return a deterministic cache key for the delegation resolver profile."""
        return self.delegation_query_coordinator.resolver_key()

    def host_resolution_resolver_key(self) -> str:
        """Return a deterministic cache key for the host-resolution resolver profile."""
        return self.host_resolution_query_coordinator.resolver_key()

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
            stage = "delegation" if record_type == "NS" else "host_resolution"
            coordinator = (
                self.delegation_query_coordinator
                if stage == "delegation"
                else self.host_resolution_query_coordinator
            )
            try:
                return coordinator.resolve_with_retries(
                    name,
                    record_type,
                    attempts=1,
                    stage=stage,
                )
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

    @staticmethod
    def _normal_name(name: str) -> str:
        """Return a case-insensitive DNS name key without the presentation root."""
        return name.rstrip(".").lower()

    @staticmethod
    def _terminal_host_result(
        *,
        host: str,
        canonical_name: str | None,
        a_exists: bool,
        a_nodata: bool,
        a_nxdomain: bool,
        a_timeout: bool,
        a_servfail: bool,
        aaaa_exists: bool,
        aaaa_nodata: bool,
        aaaa_nxdomain: bool,
        aaaa_timeout: bool,
        aaaa_servfail: bool,
        ipv4: list[str],
        ipv6: list[str],
    ) -> HostResolutionResult:
        """Build a final host-resolution result from one queried DNS name."""
        if ipv4 or ipv6:
            return HostResolutionResult(
                host=host,
                a_exists=a_exists or aaaa_exists,
                canonical_name=canonical_name,
                ipv4_addresses=sorted(ipv4),
                ipv6_addresses=sorted(ipv6),
            )
        if a_timeout or aaaa_timeout:
            return HostResolutionResult(
                host=host, a_timeout=True, canonical_name=canonical_name
            )
        if a_servfail or aaaa_servfail:
            return HostResolutionResult(
                host=host, a_servfail=True, canonical_name=canonical_name
            )
        if a_nxdomain or aaaa_nxdomain:
            return HostResolutionResult(
                host=host, a_nxdomain=True, canonical_name=canonical_name
            )
        if a_nodata or aaaa_nodata:
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

            a_exists, a_nodata, a_nxdomain, a_timeout, a_servfail, _, ipv4 = (
                self._query_record(current_name, "A")
            )
            (
                aaaa_exists,
                aaaa_nodata,
                aaaa_nxdomain,
                aaaa_timeout,
                aaaa_servfail,
                _,
                ipv6,
            ) = self._query_record(current_name, "AAAA")
            if ipv4 or ipv6:
                result = HostResolutionResult(
                    host=host,
                    a_exists=a_exists or aaaa_exists,
                    canonical_name=canonical_name,
                    ipv4_addresses=sorted(ipv4),
                    ipv6_addresses=sorted(ipv6),
                )
                logger.debug("Host resolution %s -> %s", host, result.status)
                return result

            cname_exists, _, _, cname_timeout, cname_servfail, cname_value, _ = (
                self._query_record(current_name, "CNAME")
            )
            if cname_exists and cname_value:
                canonical_name = self._normal_name(cname_value)
                current_name = canonical_name
                continue
            result = self._terminal_host_result(
                host=host,
                canonical_name=canonical_name,
                a_exists=a_exists,
                a_nodata=a_nodata,
                a_nxdomain=a_nxdomain,
                a_timeout=a_timeout or cname_timeout,
                a_servfail=a_servfail or cname_servfail,
                aaaa_exists=aaaa_exists,
                aaaa_nodata=aaaa_nodata,
                aaaa_nxdomain=aaaa_nxdomain,
                aaaa_timeout=aaaa_timeout,
                aaaa_servfail=aaaa_servfail,
                ipv4=ipv4,
                ipv6=ipv6,
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
