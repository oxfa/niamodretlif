"""Config normalization owner."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from domain_pipeline.prepare.config import models
from domain_pipeline.worker.ip_location.policy import IPLocationConfigPolicy


class ConfigNormalizer:
    """Merge defaults, source overrides, cache defaults, and IP-location effective fields."""

    def __init__(
        self, *, ip_location_policy: IPLocationConfigPolicy | None = None
    ) -> None:
        self.ip_location_policy = ip_location_policy or IPLocationConfigPolicy()

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
        host_resolution = source_payload["host_resolution"]
        if host_resolution.get("enabled") is None:
            host_resolution["enabled"] = bool(source_payload["ip_location"]["enabled"])

    def finalize_cache_defaults(self, cache_payload: dict[str, Any]) -> None:
        """Apply host-resolution cache TTL defaults to normalized settings."""
        host_ttls = cache_payload["host_resolution_ttl_days"]
        if host_ttls.get("resolved") is None:
            host_ttls["resolved"] = 1

    def format_validation_error(self, exc: ValidationError) -> str:
        """Return the first pydantic validation error as an actionable path."""
        error = exc.errors()[0]
        location = ".".join(str(part) for part in error.get("loc", ()))
        message = str(error.get("msg", "invalid configuration"))
        return f"{location}: {message}" if location else message

    def normalize_sources(
        self,
        *,
        raw_config: models.RawPipelineConfig,
        defaults_payload: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Return source configs after applying defaults and derived DNS settings."""
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
        return normalized_sources

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
        normalized_sources = self.normalize_sources(
            raw_config=raw_config,
            defaults_payload=defaults_payload,
        )
        cache_payload = raw_config.cache.model_dump()
        self.finalize_cache_defaults(cache_payload)
        try:
            normalized_config = models.NormalizedPipelineConfig.model_validate(
                {
                    "version": raw_config.version,
                    "config_name": config_namespace,
                    "config_path": str(config_path),
                    "defaults": defaults_payload,
                    "runtime": raw_config.runtime.model_dump(),
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
        self.ip_location_policy.inject_effective_fields(
            normalized_payload["defaults"]["ip_location"]
        )
        for source in normalized_payload["sources"]:
            self.ip_location_policy.inject_effective_fields(source["ip_location"])
            self.ip_location_policy.validate_ip_locationjs_region_rules(
                source["ip_location"], source_label=f"sources[{source['id']!r}]"
            )
            if source["enabled"] and validate_runtime_credentials:
                self.ip_location_policy.validate_provider_credentials(
                    source["ip_location"], source_label=f"sources[{source['id']!r}]"
                )
        return normalized_payload
