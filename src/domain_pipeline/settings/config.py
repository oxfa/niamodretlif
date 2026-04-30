"""Configuration loading and normalization for the domain pipeline."""

from __future__ import annotations

import copy
import ipaddress
import math
import os
from pathlib import Path
import re
from typing import Any, Literal, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from domain_pipeline.classifications import (
    RDAP_UNAVAILABLE_DNS_DISABLED_CLASSIFICATION_BY_REASON,
    RDAP_UNAVAILABLE_REASON_UNKNOWN,
    ROOT_CLASSIFICATION_RDAP_LOOKUP_UNAVAILABLE,
    ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_REGISTERED,
    ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED,
)

try:
    import yaml as YAML_MODULE
except ModuleNotFoundError:  # pragma: no cover
    YAML_MODULE = None

from .constants import GEO_PROVIDER_GEOJS, GEO_PROVIDER_IPINFO_LITE

CONFIG_NAMESPACE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
ISO_REGION_RULE_PATTERN = re.compile(r"^[A-Z]{2}-[A-Z0-9]{1,3}$")


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


class DNSConfig(StrictModel):
    """DNS lookup settings."""

    enabled: bool = True

    class ECSConfig(StrictModel):
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
                raise ValueError("dns.ecs.subnet must be a valid CIDR subnet") from exc
            return network.with_prefixlen

        @model_validator(mode="after")
        def _validate_ecs(self) -> "DNSConfig.ECSConfig":
            subnet = self.subnet
            if not self.enabled:
                return self
            if not subnet:
                raise ValueError("dns.ecs.enabled=true requires dns.ecs.subnet")
            network = ipaddress.ip_network(subnet, strict=False)
            if (
                self.scope_prefix_length < 0
                or self.scope_prefix_length > network.max_prefixlen
            ):
                raise ValueError(
                    "dns.ecs.scope_prefix_length must be within the subnet address family range"
                )
            return self

    nameservers: list[str] = Field(default_factory=list)
    timeout: float = 5.0
    ecs: ECSConfig = Field(default_factory=ECSConfig)

    @field_validator("nameservers", mode="after")
    @classmethod
    def _normalize_nameservers(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            stripped = value.strip()
            if not stripped:
                raise ValueError(
                    "dns.nameservers entries must be non-empty IP addresses"
                )
            try:
                normalized.append(str(ipaddress.ip_address(stripped)))
            except ValueError as exc:
                raise ValueError(
                    f"dns.nameservers entries must be valid IPv4 or IPv6 addresses (got {value!r})"
                ) from exc
        return normalized


class WhoisFallbackConfig(StrictModel):
    """WHOIS command fallback settings for selected RDAP-unavailable cases."""

    enabled: bool = True
    command: str = "whois"
    timeout: float = 20.0
    max_concurrency: int = 2

    @field_validator("command", mode="after")
    @classmethod
    def _validate_command(cls, value: str) -> str:
        command = value.strip()
        if not command:
            raise ValueError("rdap.whois_fallback.command must be non-empty")
        if any(character.isspace() for character in command):
            raise ValueError(
                "rdap.whois_fallback.command must be an executable name or path, "
                "not shell text"
            )
        if re.search(r"[;&|<>`$]", command):
            raise ValueError(
                "rdap.whois_fallback.command must not contain shell metacharacters"
            )
        return command

    @field_validator("timeout", mode="after")
    @classmethod
    def _validate_timeout(cls, value: float) -> float:
        if not math.isfinite(value) or value <= 0:
            raise ValueError("rdap.whois_fallback.timeout must be finite and positive")
        return float(value)

    @field_validator("max_concurrency", mode="after")
    @classmethod
    def _validate_max_concurrency(cls, value: int) -> int:
        if value < 1:
            raise ValueError("rdap.whois_fallback.max_concurrency must be >= 1")
        return value


class RDAPConfig(StrictModel):
    """RDAP lookup settings."""

    timeout: float = 10.0
    rate_limit_retry_fallback_seconds: tuple[float, ...] = (
        30.0,
        60.0,
        120.0,
    )
    unavailable_dns_disabled_routes: dict[str, Literal["filtered", "review"]] = Field(
        default_factory=dict
    )
    whois_fallback: WhoisFallbackConfig = Field(default_factory=WhoisFallbackConfig)

    @field_validator("rate_limit_retry_fallback_seconds", mode="after")
    @classmethod
    def _validate_rate_limit_retry_fallback_seconds(
        cls, value: tuple[float, ...]
    ) -> tuple[float, ...]:
        if not value:
            raise ValueError("rdap.rate_limit_retry_fallback_seconds must be non-empty")
        for seconds in value:
            if not math.isfinite(seconds) or seconds < 0:
                raise ValueError(
                    "rdap.rate_limit_retry_fallback_seconds entries must be "
                    "finite non-negative numbers"
                )
        return tuple(float(seconds) for seconds in value)

    @field_validator("unavailable_dns_disabled_routes", mode="after")
    @classmethod
    def _validate_unavailable_dns_disabled_routes(
        cls,
        value: dict[str, Literal["filtered", "review"]],
    ) -> dict[str, Literal["filtered", "review"]]:
        valid_reasons = set(RDAP_UNAVAILABLE_DNS_DISABLED_CLASSIFICATION_BY_REASON)
        valid_reasons.discard(RDAP_UNAVAILABLE_REASON_UNKNOWN)
        invalid_reasons = sorted(set(value) - valid_reasons)
        if invalid_reasons:
            raise ValueError(
                "rdap.unavailable_dns_disabled_routes keys must be known "
                "RDAP-unavailable DNS-disabled reasons, excluding "
                f"{RDAP_UNAVAILABLE_REASON_UNKNOWN!r} "
                f"(invalid: {', '.join(invalid_reasons)})"
            )
        return dict(value)


def _validate_fallback_seconds_sequence(
    value: tuple[float, ...] | list[float],
    *,
    field_name: str,
) -> tuple[float, ...]:
    """Validate one RDAP rate-limit fallback sequence."""
    if not value:
        raise ValueError(f"{field_name} must be non-empty")
    normalized: list[float] = []
    for seconds in value:
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError(
                f"{field_name} entries must be finite non-negative numbers"
            )
        normalized.append(float(seconds))
    return tuple(normalized)


class RDAPAuthoritativeServerPolicyConfig(StrictModel):
    """Per-authoritative-RDAP-server retry fallback policy."""

    rate_limit_retry_fallback_seconds: tuple[float, ...]

    @field_validator("rate_limit_retry_fallback_seconds", mode="after")
    @classmethod
    def _validate_rate_limit_retry_fallback_seconds(
        cls, value: tuple[float, ...]
    ) -> tuple[float, ...]:
        return _validate_fallback_seconds_sequence(
            value,
            field_name=(
                "rdap.authoritative_servers[].rate_limit_retry_fallback_seconds"
            ),
        )


class RDAPGlobalPolicyConfig(StrictModel):
    """RDAP section of the non-runnable global policy config."""

    rate_limit_retry_fallback_seconds: tuple[float, ...]
    authoritative_servers: dict[str, RDAPAuthoritativeServerPolicyConfig] = Field(
        default_factory=dict
    )

    @field_validator("rate_limit_retry_fallback_seconds", mode="after")
    @classmethod
    def _validate_rate_limit_retry_fallback_seconds(
        cls, value: tuple[float, ...]
    ) -> tuple[float, ...]:
        return _validate_fallback_seconds_sequence(
            value,
            field_name="rdap.rate_limit_retry_fallback_seconds",
        )

    @field_validator("authoritative_servers", mode="after")
    @classmethod
    def _validate_authoritative_servers(
        cls,
        value: dict[str, RDAPAuthoritativeServerPolicyConfig],
    ) -> dict[str, RDAPAuthoritativeServerPolicyConfig]:
        for server_url in value:
            if not server_url.strip():
                raise ValueError(
                    "rdap.authoritative_servers keys must be non-empty strings"
                )
            if not server_url.endswith("/"):
                raise ValueError("rdap.authoritative_servers keys must end in '/'")
        return dict(value)


class GlobalPolicyConfig(StrictModel):
    """Non-runnable checked-in policy shared by trusted automation configs."""

    version: Literal[1]
    kind: Literal["rdap_global_policy"]
    rdap: RDAPGlobalPolicyConfig


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
    """Classification cache TTLs."""

    rdap_registrable_domain_unregistered: int = 7
    rdap_registrable_domain_registered: int = 7
    rdap_lookup_unavailable: int = 7

    @model_validator(mode="before")
    @classmethod
    def _upgrade_legacy_keys(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        upgraded = dict(value)
        if "dead" in upgraded and (
            ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED not in upgraded
        ):
            upgraded[ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED] = (
                upgraded["dead"]
            )
        if "alive" in upgraded:
            if ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_REGISTERED not in upgraded:
                upgraded[ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_REGISTERED] = (
                    upgraded["alive"]
                )
            if ROOT_CLASSIFICATION_RDAP_LOOKUP_UNAVAILABLE not in upgraded:
                upgraded[ROOT_CLASSIFICATION_RDAP_LOOKUP_UNAVAILABLE] = upgraded[
                    "alive"
                ]
        return upgraded


class CacheConfig(StrictModel):
    """Global cache configuration."""

    classification_ttl_days: ClassificationTTLConfig = Field(
        default_factory=ClassificationTTLConfig
    )
    dns_ttl_days: int = 1


class DefaultsConfig(StrictModel):
    """Default settings inherited by each source."""

    fetch: FetchConfig = Field(default_factory=FetchConfig)
    dns: DNSConfig = Field(default_factory=DNSConfig)
    rdap: RDAPConfig = Field(default_factory=RDAPConfig)
    geo: GeoConfig = Field(default_factory=GeoConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)


class SourceOverrideConfig(StrictModel):
    """User-specified source entry before default merging."""

    id: str
    enabled: bool = True
    input: InputConfig
    fetch: FetchConfig | None = None
    dns: DNSConfig | None = None
    rdap: RDAPConfig | None = None
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
    rdap: RDAPConfig = Field(default_factory=RDAPConfig)
    geo: GeoConfig = Field(default_factory=GeoConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)


class RawPipelineConfig(StrictModel):
    """Top-level raw version 2 configuration."""

    version: Literal[2]
    defaults: DefaultsConfig = Field(default_factory=DefaultsConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    sources: list[SourceOverrideConfig] = Field(default_factory=list)

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
    """Return only fields that were explicitly set on a Pydantic model."""
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
    """Return a stable comparison key for one configured output directory."""
    return Path(directory).expanduser().resolve()


def _geo_requires_region_lookup(geo_payload: dict[str, Any]) -> bool:
    """Return whether one normalized geo policy needs region-capable lookup."""
    policy = cast(dict[str, Any], geo_payload.get("policy", {}))
    include = cast(dict[str, Any], policy.get("include", {}))
    exclude = cast(dict[str, Any], policy.get("exclude", {}))
    return bool(include.get("regions", []) or exclude.get("regions", []))


def _effective_geo_provider_name(geo_payload: dict[str, Any]) -> str:
    """Return the runtime-selected provider for one normalized geo config."""
    if _geo_requires_region_lookup(geo_payload):
        return GEO_PROVIDER_GEOJS
    return GEO_PROVIDER_IPINFO_LITE


def _inject_effective_geo_fields(geo_payload: dict[str, Any]) -> None:
    """Add runtime-only geo capability fields after config validation succeeds."""
    geo_payload["requires_region_lookup"] = _geo_requires_region_lookup(geo_payload)
    geo_payload["effective_provider"] = _effective_geo_provider_name(geo_payload)


def _validate_geo_provider_credentials(
    geo_payload: dict[str, Any], *, source_label: str
) -> None:
    """Reject enabled sources whose effective geo provider lacks required credentials."""
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
    """Reject ISO-style region rules for the GeoJS-backed region-aware path."""
    if str(geo_payload.get("effective_provider", "")) != GEO_PROVIDER_GEOJS:
        return
    policy = cast(dict[str, Any], geo_payload.get("policy", {}))
    for bucket_name in ("include", "exclude"):
        bucket = cast(dict[str, Any], policy.get(bucket_name, {}))
        for value in cast(list[str], bucket.get("regions", [])):
            candidate = value.strip()
            if ISO_REGION_RULE_PATTERN.fullmatch(candidate.upper()):
                raise ValueError(
                    f"{source_label} geo.policy.{bucket_name}.regions contains "
                    f"ISO-style code {candidate!r}, but GeoJS-backed region lookup "
                    "supports region names only"
                )


def _validate_source_stage_dependencies(source_payload: dict[str, Any]) -> None:
    """Reject invalid stage combinations for one normalized source config."""
    if not bool(source_payload.get("enabled")):
        return
    dns_payload = cast(dict[str, Any], source_payload.get("dns", {}))
    geo_payload = cast(dict[str, Any], source_payload.get("geo", {}))
    if bool(geo_payload.get("enabled")) and not bool(dns_payload.get("enabled", True)):
        raise ValueError(
            f"sources[{source_payload['id']!r}] geo.enabled=true requires dns.enabled=true"
        )


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
    """Load and validate the non-runnable global RDAP policy config."""
    payload = _load_yaml_payload(path)
    try:
        global_config = GlobalPolicyConfig.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(_format_validation_error(exc)) from exc
    return global_config.model_dump()


def _default_has_explicit_rdap_fallback(raw_config: RawPipelineConfig) -> bool:
    """Return whether defaults.rdap explicitly sets the source fallback."""
    if "rdap" not in raw_config.defaults.model_fields_set:
        return False
    return (
        "rate_limit_retry_fallback_seconds" in raw_config.defaults.rdap.model_fields_set
    )


def _source_has_explicit_rdap_fallback(source: SourceOverrideConfig) -> bool:
    """Return whether one source explicitly sets the source fallback."""
    if source.rdap is None:
        return False
    return "rate_limit_retry_fallback_seconds" in source.rdap.model_fields_set


def _rdap_fallback_source_marker(
    *,
    source: SourceOverrideConfig,
    raw_config: RawPipelineConfig,
    global_policy: dict[str, Any] | None,
) -> str:
    """Return the normalized source's RDAP fallback provenance marker."""
    if _source_has_explicit_rdap_fallback(source):
        return "source_override"
    if global_policy is not None and not _default_has_explicit_rdap_fallback(
        raw_config
    ):
        return "global_default"
    if _default_has_explicit_rdap_fallback(raw_config):
        return "source_override"
    return "builtin_default"


def _load_config(
    path: Path,
    *,
    validate_runtime_credentials: bool,
    global_config_path: Path | None = None,
) -> dict[str, Any]:
    """Load and validate one version 2 YAML configuration file."""
    config_namespace = config_namespace_from_path(path)
    global_policy = (
        load_global_policy(global_config_path)
        if global_config_path is not None
        else None
    )
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
    if global_policy is not None and not _default_has_explicit_rdap_fallback(
        raw_config
    ):
        defaults_payload["rdap"]["rate_limit_retry_fallback_seconds"] = list(
            global_policy["rdap"]["rate_limit_retry_fallback_seconds"]
        )
    normalized_sources: list[dict[str, Any]] = []
    seen_source_ids: set[str] = set()
    for source in raw_config.sources:
        # Keep only fields that were explicitly set in the source YAML so
        # omitted nested values continue to inherit from defaults.
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
        normalized_sources.append(normalized_source.model_dump())

    try:
        normalized_config = NormalizedPipelineConfig.model_validate(
            {
                "version": raw_config.version,
                "config_name": config_namespace,
                "config_path": str(path),
                "defaults": defaults_payload,
                "cache": raw_config.cache.model_dump(),
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
    if global_policy is not None:
        normalized_payload["rdap_global_policy"] = global_policy["rdap"]
    source_by_id = {source.id: source for source in raw_config.sources}
    for source_payload in normalized_payload["sources"]:
        source = source_by_id[str(source_payload["id"])]
        source_payload["rdap"]["rate_limit_retry_fallback_seconds_source"] = (
            _rdap_fallback_source_marker(
                source=source,
                raw_config=raw_config,
                global_policy=global_policy,
            )
        )
    _inject_effective_geo_fields(normalized_payload["defaults"]["geo"])
    for source in normalized_payload["sources"]:
        _validate_source_stage_dependencies(source)
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
    path: Path,
    *,
    global_config_path: Path | None = None,
) -> dict[str, Any]:
    """Load a runtime-ready version 2 YAML configuration file."""
    return _load_config(
        path,
        validate_runtime_credentials=True,
        global_config_path=global_config_path,
    )
