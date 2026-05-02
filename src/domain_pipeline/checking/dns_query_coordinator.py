"""Shared DNS query coordination, balancing, and provider rate limiting."""

from __future__ import annotations

import dataclasses
import logging
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import dns.edns
import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)

PROVIDER_SYSTEM_RESOLVER = "system_resolver"
PROVIDER_GOOGLE_PUBLIC_DNS = "google_public_dns"
PROVIDER_QUAD9_ECS = "quad9_ecs"
PROVIDER_CLOUDFLARE_PUBLIC_DNS = "cloudflare_public_dns"
PROVIDER_OPENDNS_PUBLIC_DNS = "opendns_public_dns"
PROVIDER_CONTROLD_UNFILTERED_DNS = "controld_unfiltered_dns"
PROVIDER_CUSTOM = "custom"
SYSTEM_NAMESERVER = "system_resolver"

GOOGLE_PUBLIC_DNS_NAMESERVERS = frozenset({"8.8.8.8", "8.8.4.4"})
QUAD9_ECS_NAMESERVERS = frozenset({"9.9.9.11", "149.112.112.11"})
CLOUDFLARE_PUBLIC_DNS_NAMESERVERS = frozenset({"1.1.1.1", "1.0.0.1"})
OPENDNS_NAMESERVERS = frozenset({"208.67.222.222", "208.67.220.220"})
CONTROLD_UNFILTERED_NAMESERVERS = frozenset({"76.76.2.0", "76.76.10.0"})


@dataclasses.dataclass(frozen=True)
class DNSProviderRateLimit:
    """Provider-specific worker-local DNS query limits."""

    qps_per_worker: float
    burst: int
    max_pending: int


@dataclasses.dataclass(frozen=True)
class DNSQueryCoordinatorConfig:
    """Normalized query coordination settings used by the registry key."""

    rate_limit_enabled: bool
    balancer_enabled: bool
    balancer_strategy: str
    provider_limits: dict[str, DNSProviderRateLimit]


@dataclasses.dataclass(frozen=True)
class DNSEndpoint:
    """One concrete resolver endpoint in a DNS resolver pool."""

    provider: str
    address: str | None
    resolver: Any
    weight: int = 1


class TokenBucketRateLimiter:
    """Thread-safe blocking token bucket for one DNS provider."""

    def __init__(self, *, qps: float, burst: int) -> None:
        self.qps = max(float(qps), 0.001)
        self.capacity = max(int(burst), 1)
        self._tokens = float(self.capacity)
        self._updated_at = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> float:
        """Block until one query token is available and return wait seconds."""
        total_wait_seconds = 0.0
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = max(now - self._updated_at, 0.0)
                self._tokens = min(self.capacity, self._tokens + elapsed * self.qps)
                self._updated_at = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return total_wait_seconds
                wait_seconds = (1.0 - self._tokens) / self.qps
                total_wait_seconds += wait_seconds
            time.sleep(wait_seconds)


class PendingQueryLimiter:
    """Thread-safe pending-query guard for one DNS provider."""

    def __init__(self, max_pending: int) -> None:
        self._semaphore = threading.BoundedSemaphore(max(1, int(max_pending)))

    @contextmanager
    def slot(self) -> Iterator[float]:
        """Hold one pending-query slot and yield wait seconds."""
        started_at = time.monotonic()
        with self._semaphore:
            yield max(time.monotonic() - started_at, 0.0)


class DNSQueryBalancer:
    """Thread-safe deterministic weighted round-robin selector for DNS endpoints."""

    def __init__(self, endpoints: list[DNSEndpoint], *, enabled: bool) -> None:
        self._endpoints = list(endpoints)
        self._enabled = enabled
        self._total_weight = sum(max(1, endpoint.weight) for endpoint in endpoints)
        self._positions: dict[tuple[str, str], int] = {}
        self._lock = threading.Lock()

    def _select_weighted_endpoint(self, position: int) -> DNSEndpoint:
        offset = position % self._total_weight
        cumulative_weight = 0
        for endpoint in self._endpoints:
            cumulative_weight += max(1, endpoint.weight)
            if offset < cumulative_weight:
                return endpoint
        return self._endpoints[-1]

    def select(
        self, *, stage: str, record_type: str, attempt_index: int
    ) -> DNSEndpoint:
        """Return the next endpoint for a stage and record type."""
        if not self._endpoints:
            raise RuntimeError("DNS query coordinator requires at least one endpoint")
        if len(self._endpoints) == 1 or not self._enabled:
            return self._endpoints[0]
        key = (stage, record_type)
        with self._lock:
            position = self._positions.get(key, 0)
            endpoint = self._select_weighted_endpoint(position)
            self._positions[key] = position + 1
        if attempt_index <= 0:
            return endpoint
        return endpoint


class DNSQueryCoordinator:
    """Resolve DNS queries through a shared balanced and rate-limited endpoint pool."""

    def __init__(
        self,
        *,
        endpoints: list[DNSEndpoint],
        resolver_key: str,
        config: DNSQueryCoordinatorConfig,
    ) -> None:
        if not endpoints:
            raise ValueError("DNS query coordinator requires at least one endpoint")
        self.endpoints = list(endpoints)
        self._resolver_key = resolver_key
        self._config = config
        self._balancer = DNSQueryBalancer(
            self.endpoints, enabled=config.balancer_enabled
        )
        self._rate_limiters = {
            provider: TokenBucketRateLimiter(
                qps=limit.qps_per_worker,
                burst=limit.burst,
            )
            for provider, limit in config.provider_limits.items()
        }
        self._pending_limiters = {
            provider: PendingQueryLimiter(limit.max_pending)
            for provider, limit in config.provider_limits.items()
        }

    def resolver_key(self) -> str:
        """Return the pool-level resolver cache key."""
        return self._resolver_key

    @property
    def primary_resolver(self) -> Any:
        """Return the first resolver for compatibility-oriented tests."""
        return self.endpoints[0].resolver

    def resolve_with_retries(
        self, name: str, record_type: str, attempts: int, stage: str
    ) -> Any:
        """Resolve one query, rotating endpoints across retryable failures."""
        last_error: Exception | None = None
        for attempt_index in range(max(1, int(attempts))):
            endpoint = self._balancer.select(
                stage=stage,
                record_type=record_type,
                attempt_index=attempt_index,
            )
            logger.debug(
                "DNS query balancer selected endpoint stage=%s record_type=%s "
                "attempt=%d provider=%s nameserver=%s resolver_key=%s",
                stage,
                record_type,
                attempt_index + 1,
                endpoint.provider,
                endpoint.address or SYSTEM_NAMESERVER,
                self._resolver_key,
            )
            try:
                return self._resolve_once(endpoint, name, record_type)
            except (dns.resolver.LifetimeTimeout, dns.resolver.NoNameservers) as exc:
                last_error = exc
                self._log_retryable_failure(
                    endpoint, name, record_type, stage, attempt_index, exc
                )
                continue
            except dns.exception.Timeout as exc:
                last_error = exc
                self._log_retryable_failure(
                    endpoint, name, record_type, stage, attempt_index, exc
                )
                continue
        if last_error is not None:
            logger.debug(
                "DNS query retry exhausted stage=%s record_type=%s name=%s "
                "attempts=%d resolver_key=%s error_type=%s",
                stage,
                record_type,
                name,
                max(1, int(attempts)),
                self._resolver_key,
                type(last_error).__name__,
            )
            raise last_error
        raise dns.exception.Timeout(f"{record_type} lookup for {name} failed")

    def _log_retryable_failure(
        self,
        endpoint: DNSEndpoint,
        name: str,
        record_type: str,
        stage: str,
        attempt_index: int,
        exc: Exception,
    ) -> None:
        """Log one retryable DNS query failure."""
        logger.debug(
            "DNS query retryable failure stage=%s record_type=%s name=%s "
            "attempt=%d provider=%s nameserver=%s error_type=%s",
            stage,
            record_type,
            name,
            attempt_index + 1,
            endpoint.provider,
            endpoint.address or SYSTEM_NAMESERVER,
            type(exc).__name__,
        )

    def _resolve_once(self, endpoint: DNSEndpoint, name: str, record_type: str) -> Any:
        provider = endpoint.provider
        if self._config.rate_limit_enabled:
            rate_limiter = self._rate_limiters.get(provider)
            if rate_limiter is not None:
                wait_seconds = rate_limiter.acquire()
                if wait_seconds > 0:
                    logger.debug(
                        "DNS rate limiter waited provider=%s wait_seconds=%.6f "
                        "qps=%.3f burst=%d record_type=%s name=%s nameserver=%s",
                        provider,
                        wait_seconds,
                        rate_limiter.qps,
                        rate_limiter.capacity,
                        record_type,
                        name,
                        endpoint.address or SYSTEM_NAMESERVER,
                    )
            pending_limiter = self._pending_limiters.get(provider)
            if pending_limiter is not None:
                with pending_limiter.slot() as wait_seconds:
                    if wait_seconds > 0.001:
                        logger.debug(
                            "DNS pending limiter waited provider=%s wait_seconds=%.6f "
                            "record_type=%s name=%s nameserver=%s",
                            provider,
                            wait_seconds,
                            record_type,
                            name,
                            endpoint.address or SYSTEM_NAMESERVER,
                        )
                    return endpoint.resolver.resolve(name, record_type)
        return endpoint.resolver.resolve(name, record_type)


class DNSQueryCoordinatorRegistry:
    """Process-local registry for sharing DNS query coordinators."""

    _lock = threading.Lock()
    _coordinators: dict[str, DNSQueryCoordinator] = {}

    @classmethod
    def get_or_create(
        cls,
        *,
        registry_key: str,
        endpoints: list[DNSEndpoint],
        resolver_key: str,
        config: DNSQueryCoordinatorConfig,
    ) -> DNSQueryCoordinator:
        """Return a shared coordinator for one normalized DNS resolver profile."""
        with cls._lock:
            coordinator = cls._coordinators.get(registry_key)
            if coordinator is None:
                coordinator = DNSQueryCoordinator(
                    endpoints=endpoints,
                    resolver_key=resolver_key,
                    config=config,
                )
                cls._coordinators[registry_key] = coordinator
            return coordinator

    @classmethod
    def clear(cls) -> None:
        """Clear registry state for tests."""
        with cls._lock:
            cls._coordinators.clear()


def provider_for_nameserver(nameserver: str | None) -> str:
    """Return the normalized provider id for one resolver address."""
    if nameserver is None or nameserver == SYSTEM_NAMESERVER:
        return PROVIDER_SYSTEM_RESOLVER
    if nameserver in GOOGLE_PUBLIC_DNS_NAMESERVERS:
        return PROVIDER_GOOGLE_PUBLIC_DNS
    if nameserver in QUAD9_ECS_NAMESERVERS:
        return PROVIDER_QUAD9_ECS
    if nameserver in CLOUDFLARE_PUBLIC_DNS_NAMESERVERS:
        return PROVIDER_CLOUDFLARE_PUBLIC_DNS
    if nameserver in OPENDNS_NAMESERVERS:
        return PROVIDER_OPENDNS_PUBLIC_DNS
    if nameserver in CONTROLD_UNFILTERED_NAMESERVERS:
        return PROVIDER_CONTROLD_UNFILTERED_DNS
    return PROVIDER_CUSTOM


def build_dns_resolver(
    *,
    nameserver: str | None,
    timeout: float,
    ecs: dict[str, Any],
) -> dns.resolver.Resolver:
    """Build a dnspython resolver for one endpoint."""
    resolver = dns.resolver.Resolver(configure=True)
    if nameserver is not None and nameserver != SYSTEM_NAMESERVER:
        resolver.nameservers = [nameserver]
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if ecs.get("enabled"):
        subnet = str(ecs.get("subnet", "")).strip()
        if subnet:
            network_address, prefix = subnet.split("/", 1)
            resolver.use_edns(
                edns=0,
                options=[
                    dns.edns.ECSOption(
                        address=network_address,
                        srclen=int(prefix),
                        scopelen=int(ecs.get("scope_prefix_length", 0)),
                    )
                ],
            )
    return resolver


def build_dns_endpoint(
    *,
    nameserver: str | None,
    timeout: float,
    ecs: dict[str, Any],
    weight: int = 1,
) -> DNSEndpoint:
    """Build one resolver endpoint from normalized DNS settings."""
    endpoint_address = None if nameserver == SYSTEM_NAMESERVER else nameserver
    return DNSEndpoint(
        provider=provider_for_nameserver(nameserver),
        address=endpoint_address,
        resolver=build_dns_resolver(nameserver=nameserver, timeout=timeout, ecs=ecs),
        weight=max(1, int(weight)),
    )
