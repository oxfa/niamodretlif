"""Tests for pipeline configuration validation."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import BaseModel

from domain_pipeline.prepare.config.models import (
    DelegationTTLConfig,
    DefaultsConfig,
    HostResolutionConfig,
    IPLocationConfig,
    SourceOverrideConfig,
)
from domain_pipeline.prepare.config.loader import PipelineConfigLoader


def test_version_error_lists_all_top_level_config_sections(tmp_path: Path) -> None:
    """Report the full list of required top-level configuration sections."""
    with pytest.raises(
        ValueError,
        match="output, manual_inputs, defaults, runtime, cache, and sources",
    ):
        PipelineConfigLoader().load_payload(
            {"version": 1},
            config_namespace="sample",
            config_path=tmp_path / "sample.yaml",
            validate_runtime_credentials=False,
        )


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (DelegationTTLConfig, {"actionable": -1}),
        (DelegationTTLConfig, {"unactionable": -1}),
        (IPLocationConfig, {"cache_ttl_days": -1}),
    ],
)
def test_cache_ttl_days_must_not_be_negative(
    model: type[BaseModel], payload: dict[str, int]
) -> None:
    """Reject negative cache TTLs across cache configuration models."""
    with pytest.raises(ValueError, match=">= 0"):
        model.model_validate(payload)


@pytest.mark.parametrize(
    "field_name",
    ["fetch", "dns_query", "delegation", "host_resolution", "ip_location"],
)
def test_defaults_reject_explicit_null_mapping_sections(field_name: str) -> None:
    """Defaults sections must be mappings when explicitly supplied."""
    with pytest.raises(ValueError):
        DefaultsConfig.model_validate({field_name: None})


@pytest.mark.parametrize(
    "field_name",
    ["fetch", "dns_query", "delegation", "host_resolution", "ip_location"],
)
def test_source_overrides_reject_explicit_null_mapping_sections(
    field_name: str,
) -> None:
    """Optional source override sections must be omitted or mappings."""
    with pytest.raises(ValueError):
        SourceOverrideConfig.model_validate(
            {
                "id": "source",
                "input": {"type": "file", "location": "source.txt"},
                field_name: None,
            }
        )


def test_ip_location_config_rejects_configured_token() -> None:
    """Runtime credentials are accepted only from the worker environment."""
    with pytest.raises(ValueError, match="ip_location.token"):
        IPLocationConfig.model_validate({"token": "secret"})


def test_host_resolution_uses_one_www_boolean_and_rejects_old_selector() -> None:
    """The host-resolution target selector has one strict replacement field."""
    assert HostResolutionConfig().resolve_www_for_registrable_domain is True
    assert (
        HostResolutionConfig.model_validate(
            {"resolve_www_for_registrable_domain": False}
        ).resolve_www_for_registrable_domain
        is False
    )
    with pytest.raises(ValueError, match="targets"):
        HostResolutionConfig.model_validate({"targets": {"root_domain": True}})
