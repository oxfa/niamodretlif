"""Configuration loading and normalization for the DNS actionability pipeline."""

from __future__ import annotations

import copy
import ipaddress
import math
import os
from pathlib import Path
import re
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from .constants import GEO_PROVIDER_GEOJS, GEO_PROVIDER_IPINFO_LITE

try:
    import yaml as YAML_MODULE
except ModuleNotFoundError:  # pragma: no cover
    YAML_MODULE = None

CONFIG_NAMESPACE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
ISO_REGION_RULE_PATTERN = re.compile(r"^[A-Z]{2}-[A-Z0-9]{1,3}$")
LEGACY_TOP_LEVEL_KEYS = {"rdap", "rdap_global_policy", "whois_fallback"}
LEGACY_CACHE_TTL_KEYS = {
    "rdap_registrable_domain_unregistered",
    "rdap_registrable_domain_registered",
    "rdap_lookup_unavailable",
    "dead",
    "alive",
}
SYSTEM_DNS_NAMESERVER = "system_resolver"


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
    """Worker-local DNS query limit for one resolver provider."""

    qps_per_worker: float
    burst: int
    max_pending: int

    @field_validator("qps_per_worker", mode="after")
    @classmethod
    def _validate_qps_per_worker(cls, value: float) -> float:
        if not math.isfinite(value) or value <= 0:
            raise ValueError("dns provider qps_per_worker must be finite and positive")
        return float(value)

    @field_validator("burst", "max_pending", mode="after")
    @classmethod
    def _validate_positive_int(cls, value: int) -> int:
        if value < 1:
            raise ValueError("dns provider burst and max_pending must be >= 1")
        return value


class DNSRateLimitProvidersConfig(StrictModel):
    """Provider-specific worker-local DNS rate limit defaults."""

    # Official provider data inspected from primary docs on 2026-05-01:
    # Azure default resolver: 1000 QPS/200 pending queries per VM.
    # Google Public DNS: rate-limit increase guidance above 1500 QPS per client.
    # Quad9: contact support above 500 QPS from one egress IP.
    # Cloudflare 1.1.1.1: no numeric public QPS limit; high-rate/proxied and
    # high-SERVFAIL traffic may be rate limited.
    # Cisco Umbrella/OpenDNS: documents 5000 DNS queries per Covered User per
    # day as a monthly DNS Security average, not a public per-client QPS cap.
    # Control D Free DNS: unfiltered endpoints are public anycast resolvers; no
    # numeric public per-client QPS cap found in the official free DNS docs.
    # DNS.SB: public resolvers document no logging and DNSSEC; no numeric public
    # per-client QPS cap found in the official DNS.SB docs.
    # Cloudflare/OpenDNS/Control D/DNS.SB defaults are conservative project caps.
    system_resolver: DNSProviderRateLimitConfig = Field(
        default_factory=lambda: DNSProviderRateLimitConfig(
            qps_per_worker=50.0, burst=50, max_pending=100
        )
    )
    google_public_dns: DNSProviderRateLimitConfig = Field(
        default_factory=lambda: DNSProviderRateLimitConfig(
            qps_per_worker=50.0, burst=50, max_pending=100
        )
    )
    quad9_ecs_public_dns: DNSProviderRateLimitConfig = Field(
        default_factory=lambda: DNSProviderRateLimitConfig(
            qps_per_worker=25.0, burst=25, max_pending=50
        )
    )
    cloudflare_public_dns: DNSProviderRateLimitConfig = Field(
        default_factory=lambda: DNSProviderRateLimitConfig(
            qps_per_worker=25.0, burst=25, max_pending=50
        )
    )
    opendns_public_dns: DNSProviderRateLimitConfig = Field(
        default_factory=lambda: DNSProviderRateLimitConfig(
            qps_per_worker=25.0, burst=25, max_pending=50
        )
    )
    controld_unfiltered_public_dns: DNSProviderRateLimitConfig = Field(
        default_factory=lambda: DNSProviderRateLimitConfig(
            qps_per_worker=25.0, burst=25, max_pending=50
        )
    )
    dns_sb_public_dns: DNSProviderRateLimitConfig = Field(
        default_factory=lambda: DNSProviderRateLimitConfig(
            qps_per_worker=25.0, burst=25, max_pending=50
        )
    )
    unrecognized_resolver: DNSProviderRateLimitConfig = Field(
        default_factory=lambda: DNSProviderRateLimitConfig(
            qps_per_worker=25.0, burst=25, max_pending=50
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
    """Worker-local DNS query rate limiting settings."""

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
        return _normalize_dns_resolver_literal(value, field_name="dns resolver")

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
        return _validate_dns_timeout(value)

    @field_validator("resolvers", mode="after")
    @classmethod
    def _validate_resolver_weights(
        cls, values: list[DNSResolverConfig] | None
    ) -> list[DNSResolverConfig] | None:
        if values is None:
            return None
        return _validate_dns_resolver_weights(values, field_name="dns stage resolvers")


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


def _normalize_dns_resolver_literal(value: str, *, field_name: str) -> str:
    """Return one normalized DNS resolver endpoint literal."""
    stripped = value.strip()
    if not stripped:
        raise ValueError(
            f"{field_name} entries must be non-empty IP addresses or "
            "'system_resolver'"
        )
    if stripped == SYSTEM_DNS_NAMESERVER:
        return SYSTEM_DNS_NAMESERVER
    try:
        return str(ipaddress.ip_address(stripped))
    except ValueError as exc:
        raise ValueError(
            f"{field_name} entries must be valid IPv4/IPv6 addresses "
            f"or 'system_resolver' (got {value!r})"
        ) from exc


def _validate_dns_resolver_weights(
    values: list[DNSResolverConfig], *, field_name: str
) -> list[DNSResolverConfig]:
    """Return resolver entries after enforcing all-or-none weight configuration."""
    weighted_count = sum(entry.weight is not None for entry in values)
    if weighted_count not in (0, len(values)):
        raise ValueError(
            f"{field_name} weight must be provided for every resolver "
            "or omitted for every resolver"
        )
    return values


def _validate_dns_timeout(value: float) -> float:
    """Return a normalized positive DNS timeout."""
    if not math.isfinite(value) or value <= 0:
        raise ValueError("dns.timeout must be finite and positive")
    return float(value)


class DNSConfig(StrictModel):
    """DNS resolver pool settings and DNS stages."""

    default_resolvers: list[DNSResolverConfig] = Field(default_factory=list)
    timeout: float = 5.0
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
        return _validate_dns_resolver_weights(
            values, field_name="dns.default_resolvers"
        )

    @field_validator("timeout", mode="after")
    @classmethod
    def _validate_timeout(cls, value: float) -> float:
        return _validate_dns_timeout(value)


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


def _explicit_model_dump(model: BaseModel) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for field_name in model.model_fields_set:
        value = getattr(model, field_name)
        if isinstance(value, BaseModel):
            payload[field_name] = _explicit_model_dump(value)
        elif isinstance(value, list):
            payload[field_name] = [
                (
                    _explicit_model_dump(item)
                    if isinstance(item, BaseModel)
                    else copy.deepcopy(item)
                )
                for item in value
            ]
        elif isinstance(value, dict):
            payload[field_name] = copy.deepcopy(value)
        else:
            payload[field_name] = copy.deepcopy(value)
    return payload


def config_namespace_from_path(path: Path) -> str:
    """Return the strict config-owned namespace derived from a config filename."""
    namespace = path.stem.strip()
    if not namespace:
        raise ValueError(f"config file {path} must have a non-empty filename stem")
    if not CONFIG_NAMESPACE_PATTERN.fullmatch(namespace):
        raise ValueError(
            "config filename stem must match ^[A-Za-z0-9][A-Za-z0-9._-]*$ "
            f"(got {namespace!r})"
        )
    return namespace


def merge_nested(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge nested mappings."""
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_nested(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _normalized_output_directory(directory: str) -> Path:
    return Path(directory).expanduser().resolve()


def _geo_requires_region_lookup(geo_payload: dict[str, Any]) -> bool:
    policy = geo_payload.get("policy", {})
    include = policy.get("include", {})
    exclude = policy.get("exclude", {})
    return bool(include.get("regions", []) or exclude.get("regions", []))


def _effective_geo_provider_name(geo_payload: dict[str, Any]) -> str:
    if _geo_requires_region_lookup(geo_payload):
        return GEO_PROVIDER_GEOJS
    return GEO_PROVIDER_IPINFO_LITE


def _inject_effective_geo_fields(geo_payload: dict[str, Any]) -> None:
    geo_payload["requires_region_lookup"] = _geo_requires_region_lookup(geo_payload)
    geo_payload["effective_provider"] = _effective_geo_provider_name(geo_payload)


def _validate_geo_provider_credentials(
    geo_payload: dict[str, Any], *, source_label: str
) -> None:
    if not bool(geo_payload.get("enabled")):
        return
    if str(geo_payload.get("effective_provider", "")) != GEO_PROVIDER_IPINFO_LITE:
        return
    if os.environ.get("GEO_IPINFO_TOKEN", "").strip():
        return
    if str(geo_payload.get("token", "")).strip():
        return
    raise ValueError(
        f"{source_label} geo requires GEO_IPINFO_TOKEN or geo.token because "
        "effective_provider resolved to ipinfo_lite"
    )


def _validate_geojs_region_rules(
    geo_payload: dict[str, Any], *, source_label: str
) -> None:
    if str(geo_payload.get("effective_provider", "")) != GEO_PROVIDER_GEOJS:
        return
    policy = geo_payload.get("policy", {})
    for bucket_name in ("include", "exclude"):
        bucket = policy.get(bucket_name, {})
        for value in bucket.get("regions", []):
            candidate = str(value).strip()
            if ISO_REGION_RULE_PATTERN.fullmatch(candidate.upper()):
                raise ValueError(
                    f"{source_label} geo.policy.{bucket_name}.regions contains "
                    f"ISO-style code {candidate!r}, but GeoJS-backed region lookup "
                    "supports region names only"
                )


def _finalize_dns_stage_defaults(source_payload: dict[str, Any]) -> None:
    """Apply derived host-resolution defaults after source/default merging."""
    dns_payload = source_payload["dns"]
    host_resolution = dns_payload["host_resolution"]
    if host_resolution.get("enabled") is None:
        host_resolution["enabled"] = bool(source_payload["geo"]["enabled"])


def _finalize_cache_defaults(cache_payload: dict[str, Any]) -> None:
    """Apply legacy host-resolution TTL fallback to the normalized cache payload."""
    host_ttls = cache_payload["dns_host_resolution_ttl_days"]
    if host_ttls.get("resolved") is None:
        host_ttls["resolved"] = int(cache_payload.get("dns_ttl_days", 1))


def _load_yaml_payload(path: Path) -> dict[str, Any]:
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"unable to read config file {path}: {exc}") from exc
    if YAML_MODULE is None:
        raise ValueError("PyYAML is required to load version 2 config files")
    try:
        payload = YAML_MODULE.safe_load(raw_text)
    except Exception as exc:  # pragma: no cover
        raise ValueError(f"config file {path} is not valid YAML: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("config must be a mapping")
    return payload


def _format_validation_error(exc: ValidationError) -> str:
    error = exc.errors()[0]
    location = ".".join(str(part) for part in error.get("loc", ()))
    message = str(error.get("msg", "invalid configuration"))
    return f"{location}: {message}" if location else message


def load_global_policy(path: Path) -> dict[str, Any]:
    """Reject the removed global RDAP policy entrypoint."""
    raise ValueError(f"global RDAP policy files are unsupported: {path}")


def _load_config(path: Path, *, validate_runtime_credentials: bool) -> dict[str, Any]:
    """Load and validate one version 2 YAML configuration file."""
    config_namespace = config_namespace_from_path(path)
    payload = _load_yaml_payload(path)
    if payload.get("version") != 2:
        raise ValueError(
            "config must declare version: 2 and use top-level keys defaults, cache, and sources"
        )
    try:
        raw_config = RawPipelineConfig.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(_format_validation_error(exc)) from exc

    defaults_payload = raw_config.defaults.model_dump()
    normalized_sources: list[dict[str, Any]] = []
    seen_source_ids: set[str] = set()
    for source in raw_config.sources:
        source_payload = _explicit_model_dump(source)
        merged_source = merge_nested(defaults_payload, source_payload)
        merged_source["id"] = source.id
        merged_source["enabled"] = source.enabled
        try:
            normalized_source = EffectiveSourceConfig.model_validate(merged_source)
        except ValidationError as exc:
            raise ValueError(_format_validation_error(exc)) from exc
        if normalized_source.id in seen_source_ids:
            raise ValueError(f"duplicate source id {normalized_source.id!r}")
        seen_source_ids.add(normalized_source.id)
        source_dict = normalized_source.model_dump()
        _finalize_dns_stage_defaults(source_dict)
        normalized_sources.append(source_dict)

    cache_payload = raw_config.cache.model_dump()
    _finalize_cache_defaults(cache_payload)
    try:
        normalized_config = NormalizedPipelineConfig.model_validate(
            {
                "version": raw_config.version,
                "config_name": config_namespace,
                "config_path": str(path),
                "defaults": defaults_payload,
                "cache": cache_payload,
                "sources": normalized_sources,
            }
        )
    except ValidationError as exc:
        raise ValueError(_format_validation_error(exc)) from exc

    enabled_output_directories = {
        str(_normalized_output_directory(source.output.directory))
        for source in normalized_config.sources
        if source.enabled
    }
    if len(enabled_output_directories) > 1:
        raise ValueError(
            "all enabled sources in one config must share the same output.directory "
            "because outputs are namespaced by config filename"
        )

    normalized_payload = normalized_config.model_dump()
    _inject_effective_geo_fields(normalized_payload["defaults"]["geo"])
    for source in normalized_payload["sources"]:
        _inject_effective_geo_fields(source["geo"])
        _validate_geojs_region_rules(
            source["geo"], source_label=f"sources[{source['id']!r}]"
        )
        if source["enabled"] and validate_runtime_credentials:
            _validate_geo_provider_credentials(
                source["geo"], source_label=f"sources[{source['id']!r}]"
            )
    return normalized_payload


def load_config(
    path: Path, *, global_config_path: Path | None = None
) -> dict[str, Any]:
    """Load a runtime-ready version 2 YAML configuration file."""
    if global_config_path is not None:
        raise ValueError("global_config_path is unsupported after RDAP/WHOIS removal")
    return _load_config(path, validate_runtime_credentials=True)


def load_config_without_runtime_credentials(path: Path) -> dict[str, Any]:
    """Load config while skipping runtime credential checks for preparation/tests."""
    return _load_config(path, validate_runtime_credentials=False)
