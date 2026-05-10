"""Config loading owner."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from domain_pipeline.prepare.config import models
from domain_pipeline.prepare.config.normalizer import ConfigNormalizer

CONFIG_NAMESPACE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

try:
    import yaml as YAML_MODULE
except ModuleNotFoundError:  # pragma: no cover
    YAML_MODULE = None


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


class PipelineConfigLoader:
    """Load YAML config and return normalized runtime payloads."""

    def __init__(self, normalizer: ConfigNormalizer | None = None) -> None:
        self.normalizer = normalizer or ConfigNormalizer()

    def load(
        self, path: Path, *, validate_runtime_credentials: bool = True
    ) -> dict[str, Any]:
        """Load and validate one version 2 YAML configuration file."""
        config_namespace = config_namespace_from_path(path)
        payload = _load_yaml_payload(path)
        return self.load_payload(
            payload,
            config_namespace=config_namespace,
            config_path=path,
            validate_runtime_credentials=validate_runtime_credentials,
        )

    def load_payload(
        self,
        payload: dict[str, Any],
        *,
        config_namespace: str,
        config_path: Path,
        validate_runtime_credentials: bool,
    ) -> dict[str, Any]:
        """Validate and normalize an already-loaded version 2 config payload."""
        if payload.get("version") != 2:
            raise ValueError(
                "config must declare version: 2 and use top-level keys defaults, "
                "cache, and sources"
            )
        try:
            raw_config = models.RawPipelineConfig.model_validate(payload)
        except ValidationError as exc:
            raise ValueError(self.normalizer.format_validation_error(exc)) from exc
        return self.normalizer.normalize(
            raw_config,
            config_namespace=config_namespace,
            config_path=config_path,
            validate_runtime_credentials=validate_runtime_credentials,
        )


def load_config_without_runtime_credentials(path: Path) -> dict[str, Any]:
    """Load config while skipping runtime credential checks for preparation/tests."""
    return PipelineConfigLoader().load(path, validate_runtime_credentials=False)
