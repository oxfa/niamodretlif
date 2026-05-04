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
PROVIDER_QUAD9_ECS_PUBLIC_DNS = "quad9_ecs_public_dns"
PROVIDER_CLOUDFLARE_PUBLIC_DNS = "cloudflare_public_dns"
PROVIDER_OPENDNS_PUBLIC_DNS = "opendns_public_dns"
PROVIDER_CONTROLD_UNFILTERED_PUBLIC_DNS = "controld_unfiltered_public_dns"
PROVIDER_DNS_SB_PUBLIC_DNS = "dns_sb_public_dns"
PROVIDER_UNRECOGNIZED_RESOLVER = "unrecognized_resolver"
SYSTEM_NAMESERVER = "system_resolver"

GOOGLE_PUBLIC_DNS_NAMESERVERS = frozenset({"8.8.8.8", "8.8.4.4"})
QUAD9_ECS_PUBLIC_DNS_NAMESERVERS = frozenset({"9.9.9.11", "149.112.112.11"})
CLOUDFLARE_PUBLIC_DNS_NAMESERVERS = frozenset({"1.1.1.1", "1.0.0.1"})
OPENDNS_NAMESERVERS = frozenset({"208.67.222.222", "208.67.220.220"})
CONTROLD_UNFILTERED_PUBLIC_DNS_NAMESERVERS = frozenset({"76.76.2.0", "76.76.10.0"})
DNS_SB_PUBLIC_NAMESERVERS = frozenset({"185.222.222.222", "45.11.45.11"})


@dataclasses.dataclass(frozen=True)
class DNSProviderRateLimit:
    """Provider-specific effective DNS query limits."""

    qps_per_worker: float
    burst: int
    max_pending: int
    aggregate_qps_target: float | None = None


@dataclasses.dataclass(frozen=True)
class DNSQueryCoordinatorConfig:
    """Normalized query coordination settings used by the registry key."""

    rate_limit_enabled: bool
    provider_limits: dict[str, DNSProviderRateLimit]


@dataclasses.dataclass(frozen=True)
class DNSEndpoint:
    """One concrete resolver endpoint in a DNS resolver pool."""

    provider: str
    address: str | None
    resolver: Any
    weight: int = 1


@dataclasses.dataclass(frozen=True)
class DNSQueryAttemptFailure:
    """One retryable failure observed while resolving a single DNS query."""

    attempt: int
    provider: str
    nameserver: str
    error_type: str


class DNSQueryExhaustedError(Exception):
    """Raised after one DNS query exhausts its retry budget."""

    def __init__(
        self,
        *,
        name: str,
        record_type: str,
        attempts: int,
        last_error: Exception,
        failures: list[DNSQueryAttemptFailure],
    ) -> None:
        super().__init__(str(last_error))
        self.name = name
        self.record_type = record_type
        self.attempts = attempts
        self.last_error = last_error
        self.failures = list(failures)


@dataclasses.dataclass
class DNSQuerySelectionState:
    """Mutable selection state shared across queries in one coordinator."""

    weighted_endpoint_indices: list[int]
    positions: dict[tuple[str, str], int]
    position_lock: threading.Lock
    query_counter: int
    query_counter_lock: threading.Lock
    provider_count: int


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
        self._selection = DNSQuerySelectionState(
            weighted_endpoint_indices=self._build_weighted_endpoint_indices(),
            positions={},
            position_lock=threading.Lock(),
            query_counter=0,
            query_counter_lock=threading.Lock(),
            provider_count=len({endpoint.provider for endpoint in self.endpoints}),
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
        """Return the first endpoint resolver in this coordinator."""
        return self.endpoints[0].resolver

    def _build_weighted_endpoint_indices(self) -> list[int]:
        """Return endpoint indexes repeated by their configured first-attempt weight."""
        indices: list[int] = []
        for index, endpoint in enumerate(self.endpoints):
            indices.extend([index] * max(1, int(endpoint.weight)))
        return indices

    def _next_query_id(self) -> str:
        """Return a process-local identifier for one coordinator-owned query."""
        with self._selection.query_counter_lock:
            self._selection.query_counter += 1
            return f"dnsq-{self._selection.query_counter}"

    def _select_first_endpoint_index(self, *, stage: str, record_type: str) -> int:
        """Return the weighted first endpoint index for one query."""
        if not self._selection.weighted_endpoint_indices:
            raise RuntimeError("DNS query coordinator requires at least one endpoint")
        if len(self._selection.weighted_endpoint_indices) == 1:
            return self._selection.weighted_endpoint_indices[0]
        key = (stage, record_type)
        with self._selection.position_lock:
            position = self._selection.positions.get(key, 0)
            endpoint_index = self._selection.weighted_endpoint_indices[
                position % len(self._selection.weighted_endpoint_indices)
            ]
            self._selection.positions[key] = position + 1
            return endpoint_index

    def _endpoint_indices_after(self, previous_index: int) -> Iterator[int]:
        """Yield endpoint indexes after a previous endpoint, wrapping once."""
        endpoint_count = len(self.endpoints)
        for offset in range(1, endpoint_count + 1):
            yield (previous_index + offset) % endpoint_count

    def _select_retry_endpoint_index(
        self, *, previous_index: int, failed_providers: set[str]
    ) -> int:
        """Return a retry endpoint, avoiding already-failed providers when possible."""
        if self._selection.provider_count > len(failed_providers):
            for endpoint_index in self._endpoint_indices_after(previous_index):
                if self.endpoints[endpoint_index].provider not in failed_providers:
                    return endpoint_index
        return next(self._endpoint_indices_after(previous_index))

    def _sleep_before_retry(self, attempt_index: int) -> None:
        """Apply bounded retry backoff after the first failed attempt."""
        if attempt_index <= 0:
            return
        time.sleep(min(0.25 * (2 ** (attempt_index - 1)), 2.0))

    def resolve(self, name: str, record_type: str, attempts: int, stage: str) -> Any:
        """Resolve one query with provider-aware retries and truthful telemetry."""
        query_id = self._next_query_id()
        attempt_budget = max(1, int(attempts))
        last_error: Exception | None = None
        failures: list[DNSQueryAttemptFailure] = []
        failed_providers: set[str] = set()
        endpoint_index = self._select_first_endpoint_index(
            stage=stage, record_type=record_type
        )
        for attempt_index in range(attempt_budget):
            self._sleep_before_retry(attempt_index)
            if attempt_index > 0:
                endpoint_index = self._select_retry_endpoint_index(
                    previous_index=endpoint_index,
                    failed_providers=failed_providers,
                )
            endpoint = self.endpoints[endpoint_index]
            logger.debug(
                "DNS query selected endpoint query_id=%s stage=%s record_type=%s "
                "name=%s attempt=%d attempts=%d provider=%s nameserver=%s "
                "resolver_key=%s",
                query_id,
                stage,
                record_type,
                name,
                attempt_index + 1,
                attempt_budget,
                endpoint.provider,
                endpoint.address or SYSTEM_NAMESERVER,
                self._resolver_key,
            )
            try:
                return self._resolve_once(endpoint, name, record_type)
            except (dns.resolver.LifetimeTimeout, dns.resolver.NoNameservers) as exc:
                last_error = exc
                failed_providers.add(endpoint.provider)
                self._log_retryable_failure(
                    endpoint,
                    name,
                    record_type,
                    stage,
                    attempt_index,
                    query_id,
                    exc,
                )
                failures.append(
                    DNSQueryAttemptFailure(
                        attempt=attempt_index + 1,
                        provider=endpoint.provider,
                        nameserver=endpoint.address or SYSTEM_NAMESERVER,
                        error_type=type(exc).__name__,
                    )
                )
                continue
            except dns.exception.Timeout as exc:
                last_error = exc
                failed_providers.add(endpoint.provider)
                self._log_retryable_failure(
                    endpoint,
                    name,
                    record_type,
                    stage,
                    attempt_index,
                    query_id,
                    exc,
                )
                failures.append(
                    DNSQueryAttemptFailure(
                        attempt=attempt_index + 1,
                        provider=endpoint.provider,
                        nameserver=endpoint.address or SYSTEM_NAMESERVER,
                        error_type=type(exc).__name__,
                    )
                )
                continue
        if last_error is not None:
            logger.debug(
                "DNS query retry exhausted query_id=%s stage=%s record_type=%s "
                "name=%s attempts=%d resolver_key=%s error_type=%s",
                query_id,
                stage,
                record_type,
                name,
                attempt_budget,
                self._resolver_key,
                type(last_error).__name__,
            )
            raise DNSQueryExhaustedError(
                name=name,
                record_type=record_type,
                attempts=attempt_budget,
                last_error=last_error,
                failures=failures,
            ) from last_error
        raise dns.exception.Timeout(f"{record_type} lookup for {name} failed")

    def _log_retryable_failure(
        self,
        endpoint: DNSEndpoint,
        name: str,
        record_type: str,
        stage: str,
        attempt_index: int,
        query_id: str,
        exc: Exception,
    ) -> None:
        """Log one retryable DNS query failure."""
        logger.debug(
            "DNS query retryable failure query_id=%s stage=%s record_type=%s name=%s "
            "attempt=%d provider=%s nameserver=%s error_type=%s",
            query_id,
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
    if nameserver in QUAD9_ECS_PUBLIC_DNS_NAMESERVERS:
        return PROVIDER_QUAD9_ECS_PUBLIC_DNS
    if nameserver in CLOUDFLARE_PUBLIC_DNS_NAMESERVERS:
        return PROVIDER_CLOUDFLARE_PUBLIC_DNS
    if nameserver in OPENDNS_NAMESERVERS:
        return PROVIDER_OPENDNS_PUBLIC_DNS
    if nameserver in CONTROLD_UNFILTERED_PUBLIC_DNS_NAMESERVERS:
        return PROVIDER_CONTROLD_UNFILTERED_PUBLIC_DNS
    if nameserver in DNS_SB_PUBLIC_NAMESERVERS:
        return PROVIDER_DNS_SB_PUBLIC_DNS
    return PROVIDER_UNRECOGNIZED_RESOLVER


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
