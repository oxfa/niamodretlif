"""Shared DNS query coordination, balancing, and provider rate limiting."""

from __future__ import annotations

import dataclasses
import json
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
    """Provider-specific worker-local DNS query limits."""

    qps_per_worker: float
    burst: int
    max_pending: int


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

    endpoint_weights: tuple[int, ...]
    total_weight: int
    current_weights: list[int]
    position_lock: threading.Lock
    query_counter: int
    query_counter_lock: threading.Lock
    provider_count: int


class TokenBucketRateLimiter:
    """Thread-safe token bucket for one DNS provider."""

    def __init__(self, *, qps: float, burst: int) -> None:
        self.qps = max(float(qps), 0.001)
        self.capacity = max(int(burst), 1)
        self._tokens = float(self.capacity)
        self._updated_at = time.monotonic()
        self._lock = threading.Lock()

    def _refill_locked(self, now: float) -> None:
        """Refill tokens using a caller-held lock."""
        elapsed = max(now - self._updated_at, 0.0)
        self._tokens = min(self.capacity, self._tokens + elapsed * self.qps)
        self._updated_at = now

    def try_acquire(self) -> bool:
        """Reserve one token if immediately available."""
        with self._lock:
            self._refill_locked(time.monotonic())
            if self._tokens < 1.0:
                return False
            self._tokens -= 1.0
            return True

    def seconds_until_available(self) -> float:
        """Return the current wait until a token should be available."""
        with self._lock:
            self._refill_locked(time.monotonic())
            if self._tokens >= 1.0:
                return 0.0
            return (1.0 - self._tokens) / self.qps

    def acquire(self) -> float:
        """Block until one query token is available and return wait seconds."""
        total_wait_seconds = 0.0
        while True:
            if self.try_acquire():
                return total_wait_seconds
            wait_seconds = self.seconds_until_available()
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


class DNSQueryCoordinatorBase:
    """Resolve one DNS stage through a balanced worker-local endpoint pool.

    The limiter is intentionally process-local. Observed GitHub matrix runs
    rarely share IPv4 egress, so the scheduler assumes distinct worker IPs and
    avoids cross-worker DNS budget coordination by design.
    """

    stage = ""
    _limiter_lock = threading.Lock()
    _token_limiters: dict[tuple[str, float, int, int], TokenBucketRateLimiter] = {}
    _pending_limiters: dict[tuple[str, float, int, int], PendingQueryLimiter] = {}

    def __init__(
        self,
        *,
        endpoints: list[DNSEndpoint],
        resolver_key: str,
        config: DNSQueryCoordinatorConfig,
        retry_backoff_base_seconds: float = 1.0,
    ) -> None:
        if not endpoints:
            raise ValueError("DNS query coordinator requires at least one endpoint")
        if not self.stage:
            raise ValueError("DNS query coordinator subclass must define a stage")
        self.endpoints = list(endpoints)
        self._resolver_key = resolver_key
        self._config = config
        self._retry_backoff_base_seconds = max(float(retry_backoff_base_seconds), 0.001)
        endpoint_weights = self._endpoint_weights()
        self._selection = DNSQuerySelectionState(
            endpoint_weights=endpoint_weights,
            total_weight=sum(endpoint_weights),
            current_weights=[0] * len(self.endpoints),
            position_lock=threading.Lock(),
            query_counter=0,
            query_counter_lock=threading.Lock(),
            provider_count=len({endpoint.provider for endpoint in self.endpoints}),
        )
        self._rate_limiters, self._provider_pending_limiters = self._build_limiters(
            config=config,
            endpoints=self.endpoints,
        )

    @classmethod
    def _build_limiters(
        cls,
        *,
        config: DNSQueryCoordinatorConfig,
        endpoints: list[DNSEndpoint] | None = None,
    ) -> tuple[dict[str, TokenBucketRateLimiter], dict[str, PendingQueryLimiter]]:
        """Return class-owned worker-local provider limiter state."""
        if not config.rate_limit_enabled:
            return {}, {}
        endpoint_providers = (
            {endpoint.provider for endpoint in endpoints}
            if endpoints is not None
            else set()
        )
        rate_limiters: dict[str, TokenBucketRateLimiter] = {}
        pending_limiters: dict[str, PendingQueryLimiter] = {}
        with cls._limiter_lock:
            for provider in sorted(endpoint_providers):
                limit = config.provider_limits.get(provider)
                if limit is None:
                    continue
                provider_policy_key = cls._provider_policy_key(provider, limit)
                if provider_policy_key not in cls._token_limiters:
                    cls._token_limiters[provider_policy_key] = TokenBucketRateLimiter(
                        qps=limit.qps_per_worker,
                        burst=limit.burst,
                    )
                if provider_policy_key not in cls._pending_limiters:
                    cls._pending_limiters[provider_policy_key] = PendingQueryLimiter(
                        limit.max_pending
                    )
                rate_limiters[provider] = cls._token_limiters[provider_policy_key]
                pending_limiters[provider] = cls._pending_limiters[provider_policy_key]
        return rate_limiters, pending_limiters

    @staticmethod
    def _provider_policy_key(
        provider: str, limit: DNSProviderRateLimit
    ) -> tuple[str, float, int, int]:
        """Return the worker-local static limiter key for one provider policy."""
        return (
            provider,
            float(limit.qps_per_worker),
            int(limit.burst),
            int(limit.max_pending),
        )

    @classmethod
    def clear_shared_limiters(cls) -> None:
        """Clear worker-local static limiter state for tests."""
        with cls._limiter_lock:
            cls._token_limiters.clear()
            cls._pending_limiters.clear()

    @classmethod
    def shared_limiter_counts(cls) -> tuple[int, int]:
        """Return static limiter counts for deterministic tests."""
        with cls._limiter_lock:
            return len(cls._token_limiters), len(cls._pending_limiters)

    def resolver_key(self) -> str:
        """Return the pool-level resolver cache key."""
        return self._resolver_key

    @property
    def primary_resolver(self) -> Any:
        """Return the first endpoint resolver in this coordinator."""
        return self.endpoints[0].resolver

    def _endpoint_weights(self) -> tuple[int, ...]:
        """Return normalized positive first-attempt weights for all endpoints."""
        return tuple(max(1, int(endpoint.weight)) for endpoint in self.endpoints)

    def _next_query_id(self) -> str:
        """Return a process-local identifier for one coordinator-owned query."""
        with self._selection.query_counter_lock:
            self._selection.query_counter += 1
            return f"dnsq-{self._selection.query_counter}"

    def _select_first_endpoint_index(self) -> int:
        """Return the smooth weighted first endpoint index for one query."""
        if not self._selection.endpoint_weights:
            raise RuntimeError("DNS query coordinator requires at least one endpoint")
        if len(self._selection.endpoint_weights) == 1:
            return 0
        with self._selection.position_lock:
            current_weights = self._selection.current_weights
            for index, weight in enumerate(self._selection.endpoint_weights):
                current_weights[index] += weight
            endpoint_index = max(
                range(len(current_weights)),
                key=lambda index: current_weights[index],
            )
            current_weights[endpoint_index] -= self._selection.total_weight
            return endpoint_index

    def _endpoint_indices_after(
        self, previous_index: int, *, include_previous: bool = False
    ) -> Iterator[int]:
        """Yield endpoint indexes after a previous endpoint, wrapping once."""
        endpoint_count = len(self.endpoints)
        offsets = (
            range(0, endpoint_count)
            if include_previous
            else range(1, endpoint_count + 1)
        )
        for offset in offsets:
            yield (previous_index + offset) % endpoint_count

    def _candidate_indices(
        self, *, preferred_index: int, failed_providers: set[str]
    ) -> list[int]:
        """Return rate-limit candidates in preferred-then-wraparound order."""
        candidate_indices = list(
            self._endpoint_indices_after(preferred_index, include_previous=True)
        )
        if self._selection.provider_count > len(failed_providers):
            filtered_indices = [
                endpoint_index
                for endpoint_index in candidate_indices
                if self.endpoints[endpoint_index].provider not in failed_providers
            ]
            if filtered_indices:
                return filtered_indices
        return candidate_indices

    def _select_retry_preferred_index(
        self, *, previous_index: int, failed_providers: set[str]
    ) -> int:
        """Return a retry preference, avoiding failed providers when possible."""
        if self._selection.provider_count > len(failed_providers):
            for endpoint_index in self._endpoint_indices_after(previous_index):
                if self.endpoints[endpoint_index].provider not in failed_providers:
                    return endpoint_index
        return next(self._endpoint_indices_after(previous_index))

    def _select_rate_available_endpoint_index(
        self,
        *,
        preferred_index: int,
        failed_providers: set[str],
        record_type: str,
        name: str,
    ) -> int:
        """Return an endpoint whose provider has an available query token."""
        while True:
            candidate_indices = self._candidate_indices(
                preferred_index=preferred_index,
                failed_providers=failed_providers,
            )
            wait_candidates: list[tuple[float, int, TokenBucketRateLimiter]] = []
            for endpoint_index in candidate_indices:
                endpoint = self.endpoints[endpoint_index]
                rate_limiter = self._rate_limiters.get(endpoint.provider)
                if rate_limiter is None or rate_limiter.try_acquire():
                    return endpoint_index
                wait_candidates.append(
                    (
                        rate_limiter.seconds_until_available(),
                        endpoint_index,
                        rate_limiter,
                    )
                )
            if not wait_candidates:
                return candidate_indices[0]
            wait_seconds, waited_index, rate_limiter = min(
                wait_candidates, key=lambda item: item[0]
            )
            waited_endpoint = self.endpoints[waited_index]
            time.sleep(wait_seconds)
            logger.debug(
                "DNS rate limiter waited provider=%s wait_seconds=%.6f "
                "qps=%.3f burst=%d stage=%s record_type=%s name=%s nameserver=%s",
                waited_endpoint.provider,
                wait_seconds,
                rate_limiter.qps,
                rate_limiter.capacity,
                self.stage,
                record_type,
                name,
                waited_endpoint.address or SYSTEM_NAMESERVER,
            )

    def _sleep_before_retry(self, attempt_index: int) -> None:
        """Apply bounded retry backoff after the first failed attempt."""
        if attempt_index <= 0:
            return
        wait_seconds = self._retry_backoff_base_seconds * (2 ** (attempt_index - 1))
        time.sleep(min(wait_seconds, 2.0))

    def resolve(self, name: str, record_type: str, attempts: int) -> Any:
        """Resolve one query with provider-aware retries and truthful telemetry."""
        query_id = self._next_query_id()
        attempt_budget = max(1, int(attempts))
        last_error: Exception | None = None
        failures: list[DNSQueryAttemptFailure] = []
        failed_providers: set[str] = set()
        preferred_index = self._select_first_endpoint_index()
        endpoint_index = preferred_index
        for attempt_index in range(attempt_budget):
            self._sleep_before_retry(attempt_index)
            if attempt_index > 0:
                preferred_index = self._select_retry_preferred_index(
                    previous_index=endpoint_index,
                    failed_providers=failed_providers,
                )
            endpoint_index = self._select_rate_available_endpoint_index(
                preferred_index=preferred_index,
                failed_providers=failed_providers,
                record_type=record_type,
                name=name,
            )
            endpoint = self.endpoints[endpoint_index]
            logger.debug(
                "DNS query selected endpoint query_id=%s stage=%s record_type=%s "
                "name=%s attempt=%d attempts=%d provider=%s nameserver=%s "
                "resolver_key=%s",
                query_id,
                self.stage,
                record_type,
                name,
                attempt_index + 1,
                attempt_budget,
                endpoint.provider,
                endpoint.address or SYSTEM_NAMESERVER,
                self._resolver_key,
            )
            try:
                answer = self._resolve_once(endpoint, name, record_type)
                self._log_success(
                    endpoint,
                    name,
                    record_type,
                    self.stage,
                    attempt_index,
                    query_id,
                    answer,
                )
                return answer
            except (dns.resolver.LifetimeTimeout, dns.resolver.NoNameservers) as exc:
                last_error = exc
                failed_providers.add(endpoint.provider)
                self._log_retryable_failure(
                    endpoint,
                    name,
                    record_type,
                    self.stage,
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
                    self.stage,
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
                self.stage,
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

    def _log_success(
        self,
        endpoint: DNSEndpoint,
        name: str,
        record_type: str,
        stage: str,
        attempt_index: int,
        query_id: str,
        answer: Any,
    ) -> None:
        """Log one successful DNS query answer."""
        if not logger.isEnabledFor(logging.DEBUG):
            return
        answer_values = _answer_values(answer)
        logger.debug(
            "DNS query success query_id=%s stage=%s record_type=%s name=%s "
            "attempt=%d provider=%s nameserver=%s answer_count=%d "
            "answer_values=%s",
            query_id,
            stage,
            record_type,
            name,
            attempt_index + 1,
            endpoint.provider,
            endpoint.address or SYSTEM_NAMESERVER,
            len(answer_values),
            json.dumps(answer_values, ensure_ascii=True, separators=(",", ":")),
        )

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
            pending_limiter = self._provider_pending_limiters.get(provider)
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


class DNSDelegationQueryCoordinator(DNSQueryCoordinatorBase):
    """Coordinator for the dns.delegation stage."""

    stage = "delegation"


class DNSHostResolutionQueryCoordinator(DNSQueryCoordinatorBase):
    """Coordinator for the dns.host_resolution stage."""

    stage = "host_resolution"


def _answer_values(answer: Any) -> list[str]:
    """Return stable string values for logging a DNS answer."""
    if isinstance(answer, str):
        return [answer.rstrip(".").lower()]
    try:
        values = [str(value).rstrip(".").lower() for value in answer]
    except TypeError:
        return [str(answer).rstrip(".").lower()]
    return sorted(set(values))


class DNSQueryCoordinatorRegistry:
    """Process-local registry for sharing DNS query coordinators."""

    _lock = threading.Lock()
    _coordinators: dict[str, DNSQueryCoordinatorBase] = {}

    @classmethod
    def get_or_create(
        cls,
        *,
        coordinator_cls: type[DNSQueryCoordinatorBase],
        registry_key: str,
        endpoints: list[DNSEndpoint],
        resolver_key: str,
        config: DNSQueryCoordinatorConfig,
        retry_backoff_base_seconds: float = 1.0,
    ) -> DNSQueryCoordinatorBase:
        """Return a shared coordinator for one normalized stage resolver profile."""
        stage_key = f"{coordinator_cls.stage}|{registry_key}"
        with cls._lock:
            coordinator = cls._coordinators.get(stage_key)
            if coordinator is None:
                coordinator = coordinator_cls(
                    endpoints=endpoints,
                    resolver_key=resolver_key,
                    config=config,
                    retry_backoff_base_seconds=retry_backoff_base_seconds,
                )
                cls._coordinators[stage_key] = coordinator
            return coordinator

    @classmethod
    def clear(cls) -> None:
        """Clear registry state for tests."""
        with cls._lock:
            cls._coordinators.clear()
        DNSQueryCoordinatorBase.clear_shared_limiters()


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
