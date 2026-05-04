"""DNS delegation and host-resolution checks for the domain pipeline."""

# pylint: disable=too-many-arguments,too-many-instance-attributes

from __future__ import annotations

import dataclasses
import ipaddress
import logging
import socket
from typing import Any

import dns.exception
import dns.resolver

from domain_pipeline.worker.dns.query_coordinator import (
    DNSEndpoint,
    DNSProviderRateLimit,
    DNSQueryCoordinator,
    DNSQueryCoordinatorConfig,
    DNSQueryExhaustedError,
    DNSQueryCoordinatorRegistry,
    PROVIDER_CLOUDFLARE_PUBLIC_DNS,
    PROVIDER_CONTROLD_UNFILTERED_PUBLIC_DNS,
    PROVIDER_DNS_SB_PUBLIC_DNS,
    PROVIDER_GOOGLE_PUBLIC_DNS,
    PROVIDER_OPENDNS_PUBLIC_DNS,
    PROVIDER_QUAD9_ECS_PUBLIC_DNS,
    PROVIDER_SYSTEM_RESOLVER,
    PROVIDER_UNRECOGNIZED_RESOLVER,
    SYSTEM_NAMESERVER,
    build_dns_endpoint,
)

logger = logging.getLogger(__name__)

DEFAULT_ECS_FALLBACK_NAMESERVERS = ["8.8.8.8", "8.8.4.4"]
QUAD9_ECS_PUBLIC_DNS_NAMESERVERS = ["9.9.9.11", "149.112.112.11"]
VERIFIED_ECS_NAMESERVERS = frozenset(
    [*DEFAULT_ECS_FALLBACK_NAMESERVERS, *QUAD9_ECS_PUBLIC_DNS_NAMESERVERS]
)
CNAME_CHAIN_LIMIT = 8
# Project safety caps, not provider-published guarantees. aggregate_qps_target
# bounds one provider's intended total traffic across effective parallel workers;
# qps_per_worker is the single-worker fallback when no aggregate target is set.
DEFAULT_DNS_PROVIDER_LIMITS = {
    PROVIDER_SYSTEM_RESOLVER: DNSProviderRateLimit(
        qps_per_worker=60.0, burst=10, max_pending=32, aggregate_qps_target=60.0
    ),
    PROVIDER_GOOGLE_PUBLIC_DNS: DNSProviderRateLimit(
        qps_per_worker=30.0, burst=5, max_pending=16, aggregate_qps_target=30.0
    ),
    PROVIDER_QUAD9_ECS_PUBLIC_DNS: DNSProviderRateLimit(
        qps_per_worker=30.0, burst=5, max_pending=16, aggregate_qps_target=30.0
    ),
    PROVIDER_CLOUDFLARE_PUBLIC_DNS: DNSProviderRateLimit(
        qps_per_worker=12.0, burst=2, max_pending=8, aggregate_qps_target=12.0
    ),
    PROVIDER_OPENDNS_PUBLIC_DNS: DNSProviderRateLimit(
        qps_per_worker=12.0, burst=2, max_pending=8, aggregate_qps_target=12.0
    ),
    PROVIDER_CONTROLD_UNFILTERED_PUBLIC_DNS: DNSProviderRateLimit(
        qps_per_worker=12.0, burst=2, max_pending=8, aggregate_qps_target=12.0
    ),
    PROVIDER_DNS_SB_PUBLIC_DNS: DNSProviderRateLimit(
        qps_per_worker=12.0, burst=2, max_pending=8, aggregate_qps_target=12.0
    ),
    PROVIDER_UNRECOGNIZED_RESOLVER: DNSProviderRateLimit(
        qps_per_worker=12.0, burst=2, max_pending=8, aggregate_qps_target=12.0
    ),
}


def effective_host_resolution_resolvers(dns_profile: dict[str, Any]) -> list[str]:
    """Return host-resolution resolvers after applying ECS compatibility fallback."""
    resolvers = list(dns_profile.get("resolvers") or [])
    ecs_payload = dict(dns_profile.get("ecs") or {})
    if not ecs_payload.get("enabled"):
        return resolvers
    if not resolvers:
        return list(DEFAULT_ECS_FALLBACK_NAMESERVERS)
    if all(resolver in VERIFIED_ECS_NAMESERVERS for resolver in resolvers):
        return resolvers
    return list(DEFAULT_ECS_FALLBACK_NAMESERVERS)


def effective_dns_resolvers(dns_config: dict[str, Any]) -> list[str]:
    """Return effective host-resolution resolvers for a DNS config payload."""
    return effective_host_resolution_resolvers(dns_config)


def effective_host_resolution_nameservers(dns_profile: dict[str, Any]) -> list[str]:
    """Return effective host-resolution recursive nameservers."""
    return effective_host_resolution_resolvers(dns_profile)


def effective_dns_nameservers(dns_config: dict[str, Any]) -> list[str]:
    """Return effective DNS recursive nameservers for host resolution."""
    return effective_dns_resolvers(dns_config)


def dns_resolver_key(dns_config: dict[str, Any]) -> str:
    """Return a deterministic cache key for one DNS resolver profile."""
    resolvers = list(dns_config.get("resolvers") or [])
    resolver_key = ",".join(resolvers) if resolvers else "system_resolver"
    ecs_payload = dict(dns_config.get("ecs") or {})
    if not ecs_payload.get("enabled"):
        return f"{resolver_key}|ecs=off"
    return (
        f"{resolver_key}|ecs={ecs_payload.get('subnet', '')}"
        f"@{ecs_payload.get('scope_prefix_length', 0)}"
    )


def _provider_limit_from_config(
    payload: dict[str, Any],
    fallback: DNSProviderRateLimit,
    *,
    effective_parallel_workers: int,
) -> DNSProviderRateLimit:
    if "aggregate_qps_target" in payload:
        aggregate_payload = payload["aggregate_qps_target"]
        aggregate_qps_target = (
            None if aggregate_payload is None else float(aggregate_payload)
        )
    elif "qps_per_worker" in payload:
        aggregate_qps_target = None
    else:
        aggregate_qps_target = fallback.aggregate_qps_target
    qps_payload = payload.get("qps_per_worker")
    configured_qps = (
        fallback.qps_per_worker if qps_payload is None else float(qps_payload)
    )
    if aggregate_qps_target is not None:
        qps = aggregate_qps_target / max(1, int(effective_parallel_workers))
    else:
        qps = configured_qps
    burst = int(payload.get("burst", fallback.burst))
    max_pending = int(payload.get("max_pending", fallback.max_pending))
    return DNSProviderRateLimit(
        qps_per_worker=max(qps, 0.001),
        burst=max(burst, 1),
        max_pending=max(max_pending, 1),
        aggregate_qps_target=(
            max(float(aggregate_qps_target), 0.001)
            if aggregate_qps_target is not None
            else None
        ),
    )


def dns_query_coordinator_config(
    *,
    query_rate_limit: dict[str, Any] | None,
    effective_parallel_workers: int = 1,
) -> DNSQueryCoordinatorConfig:
    """Return normalized DNS query coordination settings."""
    rate_payload = dict(query_rate_limit or {})
    provider_payloads = dict(rate_payload.get("providers") or {})
    if (
        "custom" in provider_payloads
        and "unrecognized_resolver" not in provider_payloads
    ):
        provider_payloads["unrecognized_resolver"] = provider_payloads.pop("custom")
    provider_limits = {
        provider: _provider_limit_from_config(
            dict(provider_payloads.get(provider) or {}),
            fallback,
            effective_parallel_workers=effective_parallel_workers,
        )
        for provider, fallback in DEFAULT_DNS_PROVIDER_LIMITS.items()
    }
    return DNSQueryCoordinatorConfig(
        rate_limit_enabled=bool(rate_payload.get("enabled", True)),
        provider_limits=provider_limits,
    )


def _endpoint_weight_key(resolver: str | None) -> str:
    """Return the weight key for one effective endpoint."""
    return SYSTEM_NAMESERVER if resolver is None else resolver


def _resolver_weights_key(weights: dict[str, int] | None) -> str:
    """Return the process-local key fragment for non-default endpoint weights."""
    normalized = {
        str(resolver): int(weight)
        for resolver, weight in dict(weights or {}).items()
        if int(weight) > 1
    }
    if not normalized:
        return "weights=default"
    parts = [f"{resolver}:{normalized[resolver]}" for resolver in sorted(normalized)]
    return "weights=" + ",".join(parts)


def _coordinator_config_key(config: DNSQueryCoordinatorConfig) -> str:
    provider_parts = []
    for provider in sorted(config.provider_limits):
        limit = config.provider_limits[provider]
        aggregate = (
            "none"
            if limit.aggregate_qps_target is None
            else f"{limit.aggregate_qps_target:g}"
        )
        provider_parts.append(
            f"{provider}:{limit.qps_per_worker:g}:{aggregate}:"
            f"{limit.burst}:{limit.max_pending}"
        )
    return (
        f"rate={int(config.rate_limit_enabled)}"
        f"|providers={';'.join(provider_parts)}"
    )


def dns_query_coordinator_key(
    *,
    resolvers: list[str],
    timeout: float,
    ecs: dict[str, Any],
    query_config: DNSQueryCoordinatorConfig,
    weights: dict[str, int] | None = None,
) -> str:
    """Return a process-local key for sharing one DNS query coordinator."""
    resolver_key = dns_resolver_key({"resolvers": resolvers, "ecs": ecs})
    return (
        f"{resolver_key}|timeout={timeout}|{_coordinator_config_key(query_config)}"
        f"|{_resolver_weights_key(weights)}"
    )


def _resolver_entry_values(entries: list[Any]) -> tuple[list[str], dict[str, int]]:
    """Return resolver endpoints and non-default weights from config entries."""
    resolvers: list[str] = []
    weights: dict[str, int] = {}
    for entry in entries:
        if isinstance(entry, dict):
            resolver = str(entry["resolver"])
            raw_weight = entry.get("weight")
        else:
            resolver = str(entry)
            raw_weight = None
        resolvers.append(resolver)
        if raw_weight is not None and int(raw_weight) > 1:
            weights[resolver] = int(raw_weight)
    return resolvers, weights


def _default_resolver_profile(
    dns_config: dict[str, Any],
) -> tuple[list[str], dict[str, int]]:
    """Return the default recursive resolver profile."""
    entries = list(dns_config.get("default_resolvers") or [])
    return _resolver_entry_values(entries)


def _stage_resolver_profile(
    dns_config: dict[str, Any], stage_config: dict[str, Any]
) -> tuple[list[str], dict[str, int]]:
    """Return stage recursive resolvers and weights after default fallback."""
    if stage_config.get("resolvers") is not None:
        resolvers, weights = _resolver_entry_values(
            list(stage_config.get("resolvers") or [])
        )
        if not weights:
            weights = {
                str(resolver): int(weight)
                for resolver, weight in dict(
                    stage_config.get("resolver_weights") or {}
                ).items()
                if int(weight) > 1
            }
        return resolvers, weights
    return _default_resolver_profile(dns_config)


def _stage_timeout(dns_config: dict[str, Any], stage_config: dict[str, Any]) -> float:
    """Return stage timeout after applying the top-level default."""
    if stage_config.get("timeout") is not None:
        return float(stage_config["timeout"])
    return float(dns_config.get("timeout", 5.0))


def _stage_query_rate_limit(
    dns_config: dict[str, Any], stage_config: dict[str, Any]
) -> dict[str, Any]:
    """Return stage query-rate limits after applying the top-level default."""
    if stage_config.get("query_rate_limit") is not None:
        return dict(stage_config.get("query_rate_limit") or {})
    return dict(dns_config.get("query_rate_limit") or {})


def delegation_dns_profile(dns_config: dict[str, Any]) -> dict[str, Any]:
    """Return the normalized delegation resolver profile without ECS."""
    delegation_config = dict(dns_config.get("delegation") or {})
    resolvers, weights = _stage_resolver_profile(dns_config, delegation_config)
    profile = {
        "resolvers": resolvers,
        "resolver_weights": weights,
        "timeout": _stage_timeout(dns_config, delegation_config),
        "query_rate_limit": _stage_query_rate_limit(dns_config, delegation_config),
    }
    return profile


def host_resolution_dns_profile(dns_config: dict[str, Any]) -> dict[str, Any]:
    """Return the normalized host-resolution resolver profile."""
    host_config = dict(dns_config.get("host_resolution") or {})
    resolvers, weights = _stage_resolver_profile(dns_config, host_config)
    profile = {
        "resolvers": resolvers,
        "resolver_weights": weights,
        "timeout": _stage_timeout(dns_config, host_config),
        "ecs": dict(host_config.get("ecs") or {}),
        "query_rate_limit": _stage_query_rate_limit(dns_config, host_config),
    }
    effective_resolvers = effective_host_resolution_resolvers(profile)
    if effective_resolvers != resolvers:
        profile["resolver_weights"] = {}
    profile["resolvers"] = effective_resolvers
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

    def __init__(self, message: str, *, last_error: Exception | None = None) -> None:
        super().__init__(message)
        self.last_error = last_error

    @property
    def is_timeout(self) -> bool:
        """Return whether the exhausted retry budget ended on a timeout."""
        if isinstance(
            self.last_error,
            (dns.resolver.LifetimeTimeout, dns.exception.Timeout),
        ):
            return True
        return "time" in str(self).lower()


DNSResult = HostResolutionResult
"""Backward-compatible alias for host-resolution results.

New internal code should use ``HostResolutionResult``. The alias is kept for
older tests, imports, and row-building surfaces that still use DNS as the
physical cache/schema term for host-resolution data.
"""


class DomainChecker:
    """Checker for mandatory delegation and optional host-resolution stages."""

    DEFAULT_NAMESERVERS: tuple[str, ...] = ()

    def __init__(
        self,
        *,
        resolvers: list[Any] | tuple[Any, ...] | None = None,
        nameservers: list[str] | tuple[str, ...] | None = None,
        timeout: float = 5.0,
        ecs: dict[str, Any] | None = None,
        query_rate_limit: dict[str, Any] | None = None,
        query_coordinator: DNSQueryCoordinator | None = None,
        delegation_dns: dict[str, Any] | None = None,
        host_resolution_dns: dict[str, Any] | None = None,
        retry_attempts: int = 3,
        delegation_retry_attempts: int | None = None,
        host_retry_attempts: int | None = None,
        effective_parallel_workers: int = 1,
    ) -> None:
        delegation_payload = dict(delegation_dns or {})
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
            "delegation": delegation_payload,
            "host_resolution": host_resolution_payload,
        }
        self.delegation_dns_profile = delegation_dns_profile(dns_config)
        self.host_resolution_dns_profile = host_resolution_dns_profile(dns_config)
        self.delegation_resolvers = list(self.delegation_dns_profile["resolvers"])
        self.resolvers = list(self.host_resolution_dns_profile["resolvers"])
        self.delegation_nameservers = list(self.delegation_resolvers)
        self.nameservers = list(self.resolvers)
        self.timeout = float(self.host_resolution_dns_profile["timeout"])
        self.ecs = dict(self.host_resolution_dns_profile["ecs"])
        self.query_rate_limit = dict(
            self.host_resolution_dns_profile["query_rate_limit"]
        )
        self.retry_attempts = max(1, int(retry_attempts))
        self.effective_parallel_workers = max(1, int(effective_parallel_workers))
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
        """Return the first host-resolution endpoint resolver."""
        return self.query_coordinator.primary_resolver

    @resolver.setter
    def resolver(self, resolver: Any) -> None:
        """Install one resolver for both DNS query coordinators."""
        query_config = DNSQueryCoordinatorConfig(
            rate_limit_enabled=False,
            provider_limits={},
        )
        coordinator = DNSQueryCoordinator(
            endpoints=[
                DNSEndpoint(
                    provider=PROVIDER_UNRECOGNIZED_RESOLVER,
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
            effective_parallel_workers=self.effective_parallel_workers,
        )
        endpoint_resolvers: list[str | None] = list(
            dns_profile.get("resolvers") or []
        ) or [None]
        weights = dict(dns_profile.get("resolver_weights") or {})
        endpoints = [
            build_dns_endpoint(
                nameserver=resolver,
                timeout=float(dns_profile.get("timeout", 5.0)),
                ecs=dict(dns_profile.get("ecs") or {}),
                weight=weights.get(_endpoint_weight_key(resolver), 1),
            )
            for resolver in endpoint_resolvers
        ]
        resolver_key = (
            f"{dns_resolver_key(dns_profile)}"
            f"|timeout={float(dns_profile.get('timeout', 5.0))}"
        )
        registry_key = dns_query_coordinator_key(
            resolvers=list(dns_profile.get("resolvers") or []),
            timeout=float(dns_profile.get("timeout", 5.0)),
            ecs=dict(dns_profile.get("ecs") or {}),
            query_config=query_config,
            weights=weights,
        )
        return DNSQueryCoordinatorRegistry.get_or_create(
            registry_key=f"stage={stage}|{registry_key}",
            endpoints=endpoints,
            resolver_key=resolver_key,
            config=query_config,
        )

    def resolver_key(self) -> str:
        """Return the host-resolution resolver profile key."""
        return self.host_resolution_resolver_key()

    def delegation_resolver_key(self) -> str:
        """Return a deterministic cache key for the delegation resolver profile."""
        return self.delegation_query_coordinator.resolver_key()

    def host_resolution_resolver_key(self) -> str:
        """Return a deterministic cache key for the host-resolution resolver profile."""
        return self.host_resolution_query_coordinator.resolver_key()

    def _resolve_record(self, name: str, record_type: str, retry_attempts: int) -> Any:
        """Resolve one DNS record type through the coordinator-owned retry budget."""
        stage = "delegation" if record_type == "NS" else "host_resolution"
        coordinator = (
            self.delegation_query_coordinator
            if stage == "delegation"
            else self.host_resolution_query_coordinator
        )
        try:
            return coordinator.resolve(
                name,
                record_type,
                attempts=retry_attempts,
                stage=stage,
            )
        except DNSQueryExhaustedError as exc:
            raise RetryableDNSLookupError(
                str(exc.last_error), last_error=exc.last_error
            ) from exc

    def delegation_lookup(self, domain: str) -> DelegationResult:
        """Query NS records for one registrable domain."""
        try:
            answer = self._resolve_record(domain, "NS", self.delegation_retry_attempts)
        except dns.resolver.NXDOMAIN:
            return DelegationResult(domain=domain, ns_nxdomain=True)
        except dns.resolver.NoAnswer:
            return DelegationResult(domain=domain, ns_nodata=True)
        except RetryableDNSLookupError as exc:
            if exc.is_timeout:
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
            answer = self._resolve_record(host, record_type, self.host_retry_attempts)
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
