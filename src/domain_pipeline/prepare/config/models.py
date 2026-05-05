"""Configuration loading and normalization for the DNS actionability pipeline."""

from __future__ import annotations

import ipaddress
import math
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from domain_pipeline.worker.dns.policy import DNSConfigPolicy
from domain_pipeline.worker.geo.constants import (
    GEO_PROVIDER_IPINFO_LITE,
)

LEGACY_TOP_LEVEL_KEYS = {"rdap", "rdap_global_policy", "whois_fallback"}
LEGACY_CACHE_TTL_KEYS = {
    "rdap_registrable_domain_unregistered",
    "rdap_registrable_domain_registered",
    "rdap_lookup_unavailable",
    "dead",
    "alive",
}


class StrictModel(BaseModel):
    """Base model that rejects unknown fields."""

    model_config = ConfigDict(extra="forbid")


class GeoMatchList(StrictModel):
    """Normalized include/exclude country and region lists."""

    countries: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)

    @field_validator("countries", mode="after")
    @classmethod
    def _normalize_countries(cls, values: list[str]) -> list[str]:
        return [value.strip().upper() for value in values]

    @field_validator("regions", mode="after")
    @classmethod
    def _normalize_regions(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            stripped = value.strip()
            if not stripped:
                raise ValueError("geo policy region entries must be non-empty strings")
            normalized.append(stripped)
        return normalized


class GeoPolicyConfig(StrictModel):
    """Geolocation policy settings."""

    enabled: bool = False
    match_scope: Literal["all_ips", "any_ip"] = "all_ips"
    include: GeoMatchList = Field(default_factory=GeoMatchList)
    exclude: GeoMatchList = Field(default_factory=GeoMatchList)


class GeoConfig(StrictModel):
    """Source or default geo configuration."""

    enabled: bool = False
    provider: Literal["ipwhois", "ip_api", "ipinfo_lite", "geojs", "ip2location_io"] = (
        GEO_PROVIDER_IPINFO_LITE
    )
    timeout: float = 5.0
    cache_ttl_days: int = 7
    token: str = ""
    policy: GeoPolicyConfig = Field(default_factory=GeoPolicyConfig)


class FetchConfig(StrictModel):
    """Fetch timeout settings."""

    request_timeout: float = 30.0


class DNSProviderRateLimitConfig(StrictModel):
    """DNS query limit for one resolver provider."""

    qps_per_worker: float | None = None
    aggregate_qps_target: float | None = None
    burst: int
    max_pending: int

    @model_validator(mode="after")
    def _validate_qps_source(self) -> DNSProviderRateLimitConfig:
        if self.qps_per_worker is None and self.aggregate_qps_target is None:
            raise ValueError(
                "dns provider requires qps_per_worker or aggregate_qps_target"
            )
        return self

    @field_validator("qps_per_worker", "aggregate_qps_target", mode="after")
    @classmethod
    def _validate_qps(cls, value: float | None) -> float | None:
        if value is None:
            return None
        if not math.isfinite(value) or value <= 0:
            raise ValueError(
                "dns provider qps_per_worker and aggregate_qps_target "
                "must be finite and positive"
            )
        return float(value)

    @field_validator("burst", "max_pending", mode="after")
    @classmethod
    def _validate_positive_int(cls, value: int) -> int:
        if value < 1:
            raise ValueError("dns provider burst and max_pending must be >= 1")
        return value


class DNSRateLimitProvidersConfig(StrictModel):
    """Provider-specific project safety defaults for DNS rate limiting."""

    # These are project caps, not provider-published guarantees. aggregate_qps_target
    # is divided by the effective workflow parallelism at runtime.
    system_resolver: DNSProviderRateLimitConfig = Field(
        default_factory=lambda: DNSProviderRateLimitConfig(
            qps_per_worker=60.0,
            aggregate_qps_target=60.0,
            burst=10,
            max_pending=32,
        )
    )
    google_public_dns: DNSProviderRateLimitConfig = Field(
        default_factory=lambda: DNSProviderRateLimitConfig(
            qps_per_worker=30.0,
            aggregate_qps_target=30.0,
            burst=5,
            max_pending=16,
        )
    )
    quad9_ecs_public_dns: DNSProviderRateLimitConfig = Field(
        default_factory=lambda: DNSProviderRateLimitConfig(
            qps_per_worker=30.0,
            aggregate_qps_target=30.0,
            burst=5,
            max_pending=16,
        )
    )
    cloudflare_public_dns: DNSProviderRateLimitConfig = Field(
        default_factory=lambda: DNSProviderRateLimitConfig(
            qps_per_worker=12.0,
            aggregate_qps_target=12.0,
            burst=2,
            max_pending=8,
        )
    )
    opendns_public_dns: DNSProviderRateLimitConfig = Field(
        default_factory=lambda: DNSProviderRateLimitConfig(
            qps_per_worker=12.0,
            aggregate_qps_target=12.0,
            burst=2,
            max_pending=8,
        )
    )
    controld_unfiltered_public_dns: DNSProviderRateLimitConfig = Field(
        default_factory=lambda: DNSProviderRateLimitConfig(
            qps_per_worker=12.0,
            aggregate_qps_target=12.0,
            burst=2,
            max_pending=8,
        )
    )
    dns_sb_public_dns: DNSProviderRateLimitConfig = Field(
        default_factory=lambda: DNSProviderRateLimitConfig(
            qps_per_worker=12.0,
            aggregate_qps_target=12.0,
            burst=2,
            max_pending=8,
        )
    )
    unrecognized_resolver: DNSProviderRateLimitConfig = Field(
        default_factory=lambda: DNSProviderRateLimitConfig(
            qps_per_worker=12.0,
            aggregate_qps_target=12.0,
            burst=2,
            max_pending=8,
        )
    )

    @model_validator(mode="before")
    @classmethod
    def _normalize_legacy_custom_provider(cls, data: Any) -> Any:
        """Accept the legacy custom resolver bucket as unrecognized_resolver."""
        if not isinstance(data, dict) or "custom" not in data:
            return data
        if "unrecognized_resolver" in data:
            raise ValueError(
                "dns.query_rate_limit.providers cannot define both custom "
                "and unrecognized_resolver"
            )
        normalized = dict(data)
        normalized["unrecognized_resolver"] = normalized.pop("custom")
        return normalized


class DNSQueryRateLimitConfig(StrictModel):
    """DNS query rate limiting settings."""

    enabled: bool = True
    providers: DNSRateLimitProvidersConfig = Field(
        default_factory=DNSRateLimitProvidersConfig
    )


class DNSResolverConfig(StrictModel):
    """One recursive DNS resolver endpoint and optional traffic weight."""

    resolver: str
    weight: int | None = None

    @field_validator("resolver", mode="after")
    @classmethod
    def _normalize_resolver(cls, value: str) -> str:
        return DNSConfigPolicy().normalize_resolver_literal(
            value, field_name="dns resolver"
        )

    @field_validator("weight", mode="before")
    @classmethod
    def _validate_weight(cls, value: Any) -> int | None:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("dns resolver weight must be an integer >= 1")
        if value < 1:
            raise ValueError("dns resolver weight must be an integer >= 1")
        return value


class DNSECSConfig(StrictModel):
    """EDNS Client Subnet settings."""

    enabled: bool = False
    subnet: str = ""
    scope_prefix_length: int = 0

    @field_validator("subnet", mode="after")
    @classmethod
    def _normalize_subnet(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            return ""
        try:
            network = ipaddress.ip_network(stripped, strict=False)
        except ValueError as exc:
            raise ValueError(
                "dns.host_resolution.ecs.subnet must be a valid CIDR subnet"
            ) from exc
        return network.with_prefixlen

    @model_validator(mode="after")
    def _validate_ecs(self) -> "DNSECSConfig":
        if not self.enabled:
            return self
        if not self.subnet:
            raise ValueError(
                "dns.host_resolution.ecs.enabled=true requires "
                "dns.host_resolution.ecs.subnet"
            )
        network = ipaddress.ip_network(self.subnet, strict=False)
        if not 0 <= self.scope_prefix_length <= network.max_prefixlen:
            raise ValueError(
                "dns.host_resolution.ecs.scope_prefix_length must be within "
                "the subnet address family range"
            )
        return self


class DNSStageResolverConfig(StrictModel):
    """Optional resolver overrides for one DNS stage."""

    resolvers: list[DNSResolverConfig] | None = None
    timeout: float | None = None
    query_rate_limit: DNSQueryRateLimitConfig | None = None

    @model_validator(mode="before")
    @classmethod
    def _reject_removed_resolver_fields(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        if "nameservers" in value:
            raise ValueError(
                "dns stage nameservers is unsupported; use dns stage resolvers"
            )
        if "query_balancer" in value:
            raise ValueError(
                "dns stage query_balancer is unsupported; put weight on each resolver"
            )
        return value

    @field_validator("timeout", mode="after")
    @classmethod
    def _validate_timeout(cls, value: float | None) -> float | None:
        if value is None:
            return None
        return DNSConfigPolicy().validate_timeout(value)

    @field_validator("resolvers", mode="after")
    @classmethod
    def _validate_resolver_weights(
        cls, values: list[DNSResolverConfig] | None
    ) -> list[DNSResolverConfig] | None:
        if values is None:
            return None
        return DNSConfigPolicy().validate_resolver_weights(
            values, field_name="dns stage resolvers"
        )


class DNSDelegationConfig(DNSStageResolverConfig):
    """Mandatory delegation-stage DNS resolver settings."""

    retry_attempts: int = 3

    @model_validator(mode="before")
    @classmethod
    def _reject_host_resolution_only_fields(cls, value: Any) -> Any:
        if isinstance(value, dict) and "ecs" in value:
            raise ValueError(
                "dns.delegation.ecs is unsupported; ECS only applies to "
                "dns.host_resolution.ecs"
            )
        return value

    @field_validator("retry_attempts", mode="after")
    @classmethod
    def _validate_retry_attempts(cls, value: int) -> int:
        if value < 1:
            raise ValueError("dns.delegation.retry_attempts must be >= 1")
        return value


class DNSHostResolutionConfig(DNSStageResolverConfig):
    """Optional host-resolution stage settings."""

    enabled: bool | None = None
    retry_attempts: int = 3
    ecs: DNSECSConfig = Field(default_factory=DNSECSConfig)

    @field_validator("retry_attempts", mode="after")
    @classmethod
    def _validate_retry_attempts(cls, value: int) -> int:
        if value < 1:
            raise ValueError("dns.host_resolution.retry_attempts must be >= 1")
        return value


class DNSConfig(StrictModel):
    """DNS resolver pool settings and DNS stages."""

    default_resolvers: list[DNSResolverConfig] = Field(default_factory=list)
    timeout: float = 5.0
    retry_backoff_base_seconds: float = 1.0
    query_rate_limit: DNSQueryRateLimitConfig = Field(
        default_factory=DNSQueryRateLimitConfig
    )
    delegation: DNSDelegationConfig = Field(default_factory=DNSDelegationConfig)
    host_resolution: DNSHostResolutionConfig = Field(
        default_factory=DNSHostResolutionConfig
    )

    @model_validator(mode="before")
    @classmethod
    def _reject_legacy_enabled(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        if "enabled" in value:
            raise ValueError("dns.enabled is unsupported; dns.delegation is mandatory")
        if "default_nameservers" in value:
            raise ValueError(
                "dns.default_nameservers is unsupported; use dns.default_resolvers"
            )
        if "nameservers" in value:
            raise ValueError(
                "dns.nameservers is unsupported; use dns.default_resolvers or "
                "stage-specific dns.delegation.resolvers / "
                "dns.host_resolution.resolvers"
            )
        if "ecs" in value:
            raise ValueError("dns.ecs is unsupported; use dns.host_resolution.ecs")
        if "query_balancer" in value:
            raise ValueError(
                "dns.query_balancer is unsupported; put weight on each stage resolver"
            )
        return value

    @field_validator("default_resolvers", mode="after")
    @classmethod
    def _validate_default_resolver_weights(
        cls, values: list[DNSResolverConfig]
    ) -> list[DNSResolverConfig]:
        return DNSConfigPolicy().validate_resolver_weights(
            values, field_name="dns.default_resolvers"
        )

    @field_validator("timeout", mode="after")
    @classmethod
    def _validate_timeout(cls, value: float) -> float:
        return DNSConfigPolicy().validate_timeout(value)

    @field_validator("retry_backoff_base_seconds", mode="after")
    @classmethod
    def _validate_retry_backoff_base_seconds(cls, value: float) -> float:
        return DNSConfigPolicy().validate_retry_backoff_base_seconds(value)


class OutputConfig(StrictModel):
    """Per-source output settings."""

    directory: str = "output"


class InputConfig(StrictModel):
    """Input source settings."""

    type: Literal["file", "url"]
    location: str
    format: str = "auto"
    label: str = ""

    @field_validator("location", mode="after")
    @classmethod
    def _validate_location(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("input.location must be a non-empty string")
        return stripped

    @field_validator("format", mode="after")
    @classmethod
    def _normalize_format(cls, value: str) -> str:
        normalized = value.strip().lower()
        allowed_values = {"auto", "plain", "hosts", "adblock", "dnsmasq"}
        if normalized not in allowed_values:
            raise ValueError(
                "input.format must be one of auto, plain, hosts, adblock, dnsmasq"
            )
        return normalized

    @field_validator("label", mode="after")
    @classmethod
    def _normalize_label(cls, value: str) -> str:
        return value.strip()


class ClassificationTTLConfig(StrictModel):
    """DNS actionability cache TTLs."""

    dns_delegation_actionable: int = 7
    dns_delegation_unactionable: int = 1

    @model_validator(mode="before")
    @classmethod
    def _reject_legacy_keys(cls, value: Any) -> Any:
        if isinstance(value, dict):
            legacy_keys = sorted(set(value) & LEGACY_CACHE_TTL_KEYS)
            if legacy_keys:
                raise ValueError(
                    "RDAP/WHOIS cache TTL keys are unsupported: "
                    + ", ".join(legacy_keys)
                )
        return value


class DNSHostResolutionTTLConfig(StrictModel):
    """Cache TTLs for stable exact-host resolution outcomes."""

    resolved: int | None = None
    nodata: int = 1
    nxdomain: int = 1
    unknown: int = 0

    @field_validator("resolved", "nodata", "nxdomain", "unknown", mode="after")
    @classmethod
    def _validate_ttl_days(cls, value: int | None) -> int | None:
        if value is not None and value < 0:
            raise ValueError("host-resolution cache TTL values must be >= 0")
        return value


class CacheConfig(StrictModel):
    """Global cache configuration."""

    classification_ttl_days: ClassificationTTLConfig = Field(
        default_factory=ClassificationTTLConfig
    )
    dns_ttl_days: int = 1
    dns_host_resolution_ttl_days: DNSHostResolutionTTLConfig = Field(
        default_factory=DNSHostResolutionTTLConfig
    )


class DefaultsConfig(StrictModel):
    """Default settings inherited by each source."""

    fetch: FetchConfig = Field(default_factory=FetchConfig)
    dns: DNSConfig = Field(default_factory=DNSConfig)
    geo: GeoConfig = Field(default_factory=GeoConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)


class SourceOverrideConfig(StrictModel):
    """User-specified source entry before default merging."""

    id: str
    enabled: bool = True
    input: InputConfig
    fetch: FetchConfig | None = None
    dns: DNSConfig | None = None
    geo: GeoConfig | None = None
    output: OutputConfig | None = None

    @field_validator("id", mode="after")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("sources[].id must be a non-empty string")
        return stripped


class EffectiveSourceConfig(StrictModel):
    """Fully merged source configuration."""

    id: str
    enabled: bool = True
    input: InputConfig
    fetch: FetchConfig = Field(default_factory=FetchConfig)
    dns: DNSConfig = Field(default_factory=DNSConfig)
    geo: GeoConfig = Field(default_factory=GeoConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)


class RawPipelineConfig(StrictModel):
    """Top-level raw version 2 configuration."""

    version: Literal[2]
    defaults: DefaultsConfig = Field(default_factory=DefaultsConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    sources: list[SourceOverrideConfig] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _reject_legacy_top_level_keys(cls, value: Any) -> Any:
        if isinstance(value, dict):
            legacy_keys = sorted(set(value) & LEGACY_TOP_LEVEL_KEYS)
            if legacy_keys:
                raise ValueError(
                    "RDAP/WHOIS config keys are unsupported: " + ", ".join(legacy_keys)
                )
        return value

    @model_validator(mode="after")
    def _validate_sources(self) -> "RawPipelineConfig":
        if not self.sources:
            raise ValueError("config must define at least one source in sources")
        return self


class NormalizedPipelineConfig(StrictModel):
    """Final normalized configuration structure used by the runtime."""

    version: Literal[2]
    config_name: str
    config_path: str
    defaults: DefaultsConfig
    cache: CacheConfig
    sources: list[EffectiveSourceConfig]

    @model_validator(mode="after")
    def _validate_enabled_sources(self) -> "NormalizedPipelineConfig":
        if not any(source.enabled for source in self.sources):
            raise ValueError("config must include at least one enabled source")
        return self
