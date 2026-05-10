"""Shared DNS query mechanics for pipeline worker stages."""

from __future__ import annotations

import dataclasses
from typing import Any

import dns.exception
import dns.resolver

from domain_pipeline.worker.dns_query.query_coordinator import (
    DNSEndpoint,
    DNSProviderRateLimit,
    DNSQueryCoordinatorBase,
    DNSQueryCoordinatorConfig,
    DNSQueryCoordinatorOptions,
    DNSQueryCoordinatorState,
    DNSQueryCoordinatorRegistry,
    DNSQueryExhaustedError,
    DNSCoordinatorRegistryRequest,
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

DEFAULT_DNS_PROVIDER_LIMITS = {
    PROVIDER_SYSTEM_RESOLVER: DNSProviderRateLimit(
        qps_per_worker=60.0, burst=10, max_pending=32
    ),
    PROVIDER_GOOGLE_PUBLIC_DNS: DNSProviderRateLimit(
        qps_per_worker=30.0, burst=5, max_pending=16
    ),
    PROVIDER_QUAD9_ECS_PUBLIC_DNS: DNSProviderRateLimit(
        qps_per_worker=30.0, burst=5, max_pending=16
    ),
    PROVIDER_CLOUDFLARE_PUBLIC_DNS: DNSProviderRateLimit(
        qps_per_worker=12.0, burst=2, max_pending=8
    ),
    PROVIDER_OPENDNS_PUBLIC_DNS: DNSProviderRateLimit(
        qps_per_worker=12.0, burst=2, max_pending=8
    ),
    PROVIDER_CONTROLD_UNFILTERED_PUBLIC_DNS: DNSProviderRateLimit(
        qps_per_worker=12.0, burst=2, max_pending=8
    ),
    PROVIDER_DNS_SB_PUBLIC_DNS: DNSProviderRateLimit(
        qps_per_worker=12.0, burst=2, max_pending=8
    ),
    PROVIDER_UNRECOGNIZED_RESOLVER: DNSProviderRateLimit(
        qps_per_worker=12.0, burst=2, max_pending=8
    ),
}
DNS_QUERY_RATE_LIMIT_KEYS = frozenset({"enabled", "providers"})
DNS_PROVIDER_RATE_LIMIT_KEYS = frozenset({"qps_per_worker", "burst", "max_pending"})


@dataclasses.dataclass(frozen=True)
class DNSCheckerBaseRequest:
    """Shared DNS checker construction settings."""

    default_resolvers: list[Any] | tuple[Any, ...] | None = None
    timeout: float = 5.0
    retry_backoff_base_seconds: float = 1.0
    query_rate_limit: dict[str, Any] | None = None
    retry_attempts: int = 3


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
    provider: str,
) -> DNSProviderRateLimit:
    unknown_keys = sorted(set(payload) - DNS_PROVIDER_RATE_LIMIT_KEYS)
    if unknown_keys:
        raise ValueError(
            "unsupported DNS provider rate-limit field "
            f"providers.{provider}.{unknown_keys[0]}; use qps_per_worker"
        )
    qps_payload = payload.get("qps_per_worker")
    qps = fallback.qps_per_worker if qps_payload is None else float(qps_payload)
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
) -> DNSQueryCoordinatorConfig:
    """Return normalized DNS query coordination settings."""
    rate_payload = dict(query_rate_limit or {})
    unknown_rate_keys = sorted(set(rate_payload) - DNS_QUERY_RATE_LIMIT_KEYS)
    if unknown_rate_keys:
        raise ValueError(
            f"unsupported DNS query_rate_limit field query_rate_limit.{unknown_rate_keys[0]}"
        )
    provider_payloads = dict(rate_payload.get("providers") or {})
    unknown_providers = sorted(
        set(provider_payloads) - set(DEFAULT_DNS_PROVIDER_LIMITS)
    )
    if unknown_providers:
        provider_name = unknown_providers[0]
        replacement = "; use unrecognized_resolver" if provider_name == "custom" else ""
        raise ValueError(
            f"unsupported DNS provider rate-limit bucket providers.{provider_name}"
            f"{replacement}"
        )
    provider_limits = {
        provider: _provider_limit_from_config(
            dict(provider_payloads.get(provider) or {}),
            fallback,
            provider=provider,
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
        provider_parts.append(
            f"{provider}:{limit.qps_per_worker:g}:{limit.burst}:{limit.max_pending}"
        )
    return (
        f"rate={int(config.rate_limit_enabled)}"
        f"|providers={';'.join(provider_parts)}"
    )


@dataclasses.dataclass(frozen=True)
class DNSCoordinatorKeyRequest:
    """Inputs that form a process-local DNS query coordinator key."""

    resolvers: list[str]
    timeout: float
    ecs: dict[str, Any]
    query_config: DNSQueryCoordinatorConfig
    weights: dict[str, int] | None = None
    retry_backoff_base_seconds: float = 1.0


def dns_query_coordinator_key(
    request: DNSCoordinatorKeyRequest,
) -> str:
    """Return a process-local key for sharing one DNS query coordinator."""
    resolver_key = dns_resolver_key(
        {"resolvers": request.resolvers, "ecs": request.ecs}
    )
    return (
        f"{resolver_key}|timeout={request.timeout}|"
        f"{_coordinator_config_key(request.query_config)}"
        f"|{_resolver_weights_key(request.weights)}"
        f"|retry_backoff_base_seconds={request.retry_backoff_base_seconds:g}"
    )


def dns_resolver_entry_values(entries: list[Any]) -> tuple[list[str], dict[str, int]]:
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


def default_dns_resolver_profile(
    dns_config: dict[str, Any],
) -> tuple[list[str], dict[str, int]]:
    """Return the default recursive resolver profile."""
    entries = list(dns_config.get("default_resolvers") or [])
    return dns_resolver_entry_values(entries)


def dns_stage_resolver_profile(
    dns_config: dict[str, Any], stage_config: dict[str, Any]
) -> tuple[list[str], dict[str, int]]:
    """Return stage recursive resolvers and weights after default fallback."""
    if stage_config.get("resolvers") is not None:
        resolvers, weights = dns_resolver_entry_values(
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
    return default_dns_resolver_profile(dns_config)


def dns_stage_timeout(
    dns_config: dict[str, Any], stage_config: dict[str, Any]
) -> float:
    """Return stage timeout after applying the shared DNS default."""
    if stage_config.get("timeout") is not None:
        return float(stage_config["timeout"])
    return float(dns_config.get("timeout", 5.0))


def dns_stage_retry_backoff_base_seconds(
    dns_config: dict[str, Any], stage_config: dict[str, Any]
) -> float:
    """Return stage retry backoff after applying the shared DNS default."""
    if stage_config.get("retry_backoff_base_seconds") is not None:
        return float(stage_config["retry_backoff_base_seconds"])
    return float(dns_config.get("retry_backoff_base_seconds", 1.0))


def dns_stage_query_rate_limit(
    dns_config: dict[str, Any], stage_config: dict[str, Any]
) -> dict[str, Any]:
    """Return stage query-rate limits after applying the shared DNS default."""
    if stage_config.get("query_rate_limit") is not None:
        return dict(stage_config.get("query_rate_limit") or {})
    return dict(dns_config.get("query_rate_limit") or {})


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


class DNSQueryService:
    """Shared DNS resolver-pool helper for worker DNS stages."""

    DEFAULT_NAMESERVERS: tuple[str, ...] = ()

    def __init__(
        self, *, coordinator_state: DNSQueryCoordinatorState | None = None
    ) -> None:
        self._coordinator_state = coordinator_state

    def stage_dns_base_config(
        self,
        *,
        default_resolvers: list[Any] | tuple[Any, ...] | None,
        timeout: float,
        retry_backoff_base_seconds: float,
        query_rate_limit: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Return shared DNS config fields for one worker DNS stage."""
        return {
            "default_resolvers": list(default_resolvers or self.DEFAULT_NAMESERVERS),
            "timeout": float(timeout),
            "retry_backoff_base_seconds": float(retry_backoff_base_seconds),
            "query_rate_limit": query_rate_limit or {},
        }

    def build_query_coordinator(
        self,
        *,
        coordinator_cls: type[DNSQueryCoordinatorBase],
        dns_profile: dict[str, Any],
    ) -> DNSQueryCoordinatorBase:
        """Build or retrieve the shared DNS query coordinator for one profile."""
        query_config = dns_query_coordinator_config(
            query_rate_limit=dns_profile.get("query_rate_limit", {}),
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
            f"|retry_backoff_base_seconds="
            f"{float(dns_profile.get('retry_backoff_base_seconds', 1.0)):g}"
        )
        registry_key = dns_query_coordinator_key(
            DNSCoordinatorKeyRequest(
                resolvers=list(dns_profile.get("resolvers") or []),
                timeout=float(dns_profile.get("timeout", 5.0)),
                ecs=dict(dns_profile.get("ecs") or {}),
                query_config=query_config,
                weights=weights,
                retry_backoff_base_seconds=float(
                    dns_profile.get("retry_backoff_base_seconds", 1.0)
                ),
            )
        )
        return DNSQueryCoordinatorRegistry.get_or_create(
            DNSCoordinatorRegistryRequest(
                coordinator_cls=coordinator_cls,
                registry_key=registry_key,
                endpoints=endpoints,
                resolver_key=resolver_key,
                config=query_config,
                retry_backoff_base_seconds=float(
                    dns_profile.get("retry_backoff_base_seconds", 1.0)
                ),
            ),
            coordinator_state=self._coordinator_state,
        )

    def single_resolver_coordinator(
        self,
        *,
        coordinator_cls: type[DNSQueryCoordinatorBase],
        resolver_key: str,
        resolver: Any,
    ) -> DNSQueryCoordinatorBase:
        """Build an unmetered single-resolver coordinator for tests and overrides."""
        query_config = DNSQueryCoordinatorConfig(
            rate_limit_enabled=False,
            provider_limits={},
        )
        return coordinator_cls(
            endpoints=[
                DNSEndpoint(
                    provider=PROVIDER_UNRECOGNIZED_RESOLVER,
                    address=None,
                    resolver=resolver,
                )
            ],
            resolver_key=resolver_key,
            config=query_config,
            options=DNSQueryCoordinatorOptions(
                coordinator_state=self._coordinator_state
            ),
        )

    def resolve_with_coordinator(
        self,
        coordinator: DNSQueryCoordinatorBase,
        name: str,
        record_type: str,
        retry_attempts: int,
    ) -> Any:
        """Resolve one DNS record type through one explicit stage coordinator."""
        try:
            return coordinator.resolve(
                name,
                record_type,
                attempts=retry_attempts,
            )
        except DNSQueryExhaustedError as exc:
            raise RetryableDNSLookupError(
                str(exc.last_error), last_error=exc.last_error
            ) from exc
