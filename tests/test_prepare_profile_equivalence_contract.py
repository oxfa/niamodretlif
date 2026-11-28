"""Prepare-time equivalence rules for host and IP profiles."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from domain_pipeline.prepare.config.loader import PipelineConfigLoader
from domain_pipeline.prepare.planner import PreparationPlanner


def _prepare(
    tmp_path: Path,
    sources: list[dict[str, Any]],
) -> Any:
    """Build a small source config and prepare its ordinary input domains."""
    source_payloads: list[dict[str, Any]] = []
    for source in sources:
        source_id = source["id"]
        source_path = tmp_path / f"{source_id}.txt"
        source_path.write_text(source["content"], encoding="utf-8")
        source_payloads.append(
            {
                "id": source_id,
                "input": {
                    "type": "file",
                    "location": str(source_path),
                    "format": "plain",
                },
                **{
                    key: value
                    for key, value in source.items()
                    if key not in {"id", "content"}
                },
            }
        )

    config = PipelineConfigLoader().load_payload(
        {
            "version": 2,
            "output": {
                "filtered": [
                    {"path": "output/filtered/fixture.txt", "format": "plain"}
                ],
                "review": "output/review/fixture.csv",
                "unactionable": "output/unactionable/fixture.txt",
            },
            "sources": source_payloads,
        },
        config_namespace="fixture",
        config_path=tmp_path / "fixture.yaml",
        validate_runtime_credentials=False,
    )
    return PreparationPlanner(source_root=tmp_path).prepare_config(config)


def test_repeated_input_conflicts_on_ip_enablement_when_host_resolution_is_enabled(
    tmp_path: Path,
) -> None:
    """Repeated ordinary inputs must agree on reachable IP-stage enablement."""
    with pytest.raises(ValueError, match="different IP-location enablement"):
        _prepare(
            tmp_path,
            [
                {
                    "id": "one",
                    "content": "ads.example.com\n",
                    "host_resolution": {"enabled": True},
                    "ip_location": {"enabled": True},
                },
                {
                    "id": "two",
                    "content": "ads.example.com\n",
                    "host_resolution": {"enabled": True},
                    "ip_location": {"enabled": False},
                },
            ],
        )


def test_repeated_input_conflicts_on_enabled_ip_location_settings(
    tmp_path: Path,
) -> None:
    """Repeated inputs must agree on effective IP settings when enabled."""
    with pytest.raises(ValueError, match="different effective IP-location profile"):
        _prepare(
            tmp_path,
            [
                {
                    "id": "one",
                    "content": "ads.example.com\n",
                    "host_resolution": {"enabled": True},
                    "ip_location": {"enabled": True, "timeout": 2.0},
                },
                {
                    "id": "two",
                    "content": "ads.example.com\n",
                    "host_resolution": {"enabled": True},
                    "ip_location": {"enabled": True, "timeout": 4.0},
                },
            ],
        )


def test_disabled_ip_location_ignores_unused_profile_differences(
    tmp_path: Path,
) -> None:
    """Disabled IP-location settings do not affect the domain's effective work."""
    prepared = _prepare(
        tmp_path,
        [
            {
                "id": "one",
                "content": "ads.example.com\n",
                "host_resolution": {"enabled": True},
                "ip_location": {"enabled": False, "timeout": 2.0},
            },
            {
                "id": "two",
                "content": "ads.example.com\n",
                "host_resolution": {"enabled": True},
                "ip_location": {"enabled": False, "timeout": 4.0},
            },
        ],
    )

    input_domain = prepared.root_plans["example.com"].input_domains[
        "ads.example.com"
    ]
    assert input_domain.host_resolution_profile is not None
    assert input_domain.ip_location_profile is None


def test_distinct_inputs_under_one_root_may_use_different_host_and_ip_profiles(
    tmp_path: Path,
) -> None:
    """Profile agreement is scoped to an input domain, not the shared root."""
    prepared = _prepare(
        tmp_path,
        [
            {
                "id": "one",
                "content": "ads.example.com\n",
                "host_resolution": {"enabled": True, "timeout": 2.0},
                "ip_location": {"enabled": True, "timeout": 2.0},
            },
            {
                "id": "two",
                "content": "mail.example.com\n",
                "host_resolution": {"enabled": True, "timeout": 4.0},
                "ip_location": {"enabled": True, "timeout": 4.0},
            },
        ],
    )

    root_plan = prepared.root_plans["example.com"]
    ads = root_plan.input_domains["ads.example.com"]
    mail = root_plan.input_domains["mail.example.com"]

    assert ads.host_resolution_profile["timeout"] == 2.0
    assert mail.host_resolution_profile["timeout"] == 4.0
    assert ads.ip_location_profile["timeout"] == 2.0
    assert mail.ip_location_profile["timeout"] == 4.0


def test_repeated_subdomain_ignores_registrable_root_www_selector_difference(
    tmp_path: Path,
) -> None:
    """The www selector affects queries only for the registrable root itself."""
    prepared = _prepare(
        tmp_path,
        [
            {
                "id": "one",
                "content": "ads.example.com\n",
                "host_resolution": {
                    "enabled": True,
                    "resolve_www_for_registrable_domain": True,
                },
            },
            {
                "id": "two",
                "content": "ads.example.com\n",
                "host_resolution": {
                    "enabled": True,
                    "resolve_www_for_registrable_domain": False,
                },
            },
        ],
    )

    input_domain = prepared.root_plans["example.com"].input_domains[
        "ads.example.com"
    ]
    assert input_domain.host_resolution_profile is not None


def test_repeated_registrable_root_conflicts_on_www_selector_difference(
    tmp_path: Path,
) -> None:
    """The www selector is part of an input root's effective query profile."""
    with pytest.raises(ValueError, match="different effective host-resolution profile"):
        _prepare(
            tmp_path,
            [
                {
                    "id": "one",
                    "content": "example.com\n",
                    "host_resolution": {
                        "enabled": True,
                        "resolve_www_for_registrable_domain": True,
                    },
                },
                {
                    "id": "two",
                    "content": "example.com\n",
                    "host_resolution": {
                        "enabled": True,
                        "resolve_www_for_registrable_domain": False,
                    },
                },
            ],
        )
