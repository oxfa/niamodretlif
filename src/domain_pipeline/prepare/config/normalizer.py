"""Config normalization owner."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from domain_pipeline.prepare.config import models
from domain_pipeline.worker.geo.policy import GeoConfigPolicy


class ConfigNormalizer:
    """Merge defaults, source overrides, cache defaults, and geo effective fields."""

    def __init__(self, *, geo_policy: GeoConfigPolicy | None = None) -> None:
        self.geo_policy = geo_policy or GeoConfigPolicy()

    def explicit_model_dump(self, model: BaseModel) -> dict[str, Any]:
        """Return only fields explicitly provided by the user."""
        payload: dict[str, Any] = {}
        for field_name in model.model_fields_set:
            value = getattr(model, field_name)
            if isinstance(value, BaseModel):
                payload[field_name] = self.explicit_model_dump(value)
            elif isinstance(value, list):
                payload[field_name] = [
                    (
                        self.explicit_model_dump(item)
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

    def merge_nested(
        self, base: dict[str, Any], override: dict[str, Any]
    ) -> dict[str, Any]:
        """Recursively merge nested mappings."""
        merged = copy.deepcopy(base)
        for key, value in override.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = self.merge_nested(merged[key], value)
            else:
                merged[key] = copy.deepcopy(value)
        return merged

    def normalized_output_directory(self, directory: str) -> Path:
        """Return the normalized absolute output directory."""
        return Path(directory).expanduser().resolve()

    def finalize_dns_stage_defaults(self, source_payload: dict[str, Any]) -> None:
        """Apply derived host-resolution defaults after source/default merging."""
        dns_payload = source_payload["dns"]
        host_resolution = dns_payload["host_resolution"]
        if host_resolution.get("enabled") is None:
            host_resolution["enabled"] = bool(source_payload["geo"]["enabled"])

    def finalize_cache_defaults(self, cache_payload: dict[str, Any]) -> None:
        """Apply legacy host-resolution TTL fallback to normalized cache settings."""
        host_ttls = cache_payload["dns_host_resolution_ttl_days"]
        if host_ttls.get("resolved") is None:
            host_ttls["resolved"] = int(cache_payload.get("dns_ttl_days", 1))

    def format_validation_error(self, exc: ValidationError) -> str:
        """Return the first pydantic validation error as an actionable path."""
        error = exc.errors()[0]
        location = ".".join(str(part) for part in error.get("loc", ()))
        message = str(error.get("msg", "invalid configuration"))
        return f"{location}: {message}" if location else message

    def normalize(
        self,
        raw_config: models.RawPipelineConfig,
        *,
        config_namespace: str,
        config_path: Path,
        validate_runtime_credentials: bool,
    ) -> dict[str, Any]:
        """Return the runtime-ready normalized config payload."""
        defaults_payload = raw_config.defaults.model_dump()
        normalized_sources: list[dict[str, Any]] = []
        seen_source_ids: set[str] = set()
        for source in raw_config.sources:
            source_payload = self.explicit_model_dump(source)
            merged_source = self.merge_nested(defaults_payload, source_payload)
            merged_source["id"] = source.id
            merged_source["enabled"] = source.enabled
            try:
                normalized_source = models.EffectiveSourceConfig.model_validate(
                    merged_source
                )
            except ValidationError as exc:
                raise ValueError(self.format_validation_error(exc)) from exc
            if normalized_source.id in seen_source_ids:
                raise ValueError(f"duplicate source id {normalized_source.id!r}")
            seen_source_ids.add(normalized_source.id)
            source_dict = normalized_source.model_dump()
            self.finalize_dns_stage_defaults(source_dict)
            normalized_sources.append(source_dict)

        cache_payload = raw_config.cache.model_dump()
        self.finalize_cache_defaults(cache_payload)
        try:
            normalized_config = models.NormalizedPipelineConfig.model_validate(
                {
                    "version": raw_config.version,
                    "config_name": config_namespace,
                    "config_path": str(config_path),
                    "defaults": defaults_payload,
                    "cache": cache_payload,
                    "sources": normalized_sources,
                }
            )
        except ValidationError as exc:
            raise ValueError(self.format_validation_error(exc)) from exc

        enabled_output_directories = {
            str(self.normalized_output_directory(source.output.directory))
            for source in normalized_config.sources
            if source.enabled
        }
        if len(enabled_output_directories) > 1:
            raise ValueError(
                "all enabled sources in one config must share the same "
                "output.directory because outputs are namespaced by config filename"
            )

        normalized_payload = normalized_config.model_dump()
        self.geo_policy.inject_effective_fields(normalized_payload["defaults"]["geo"])
        for source in normalized_payload["sources"]:
            self.geo_policy.inject_effective_fields(source["geo"])
            self.geo_policy.validate_geojs_region_rules(
                source["geo"], source_label=f"sources[{source['id']!r}]"
            )
            if source["enabled"] and validate_runtime_credentials:
                self.geo_policy.validate_provider_credentials(
                    source["geo"], source_label=f"sources[{source['id']!r}]"
                )
        return normalized_payload


def merge_nested(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Merge nested config mappings through the config normalizer."""
    return ConfigNormalizer().merge_nested(base, override)
