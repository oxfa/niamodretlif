"""Focused prepare-side domain work and source parsing contracts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from domain_pipeline.prepare.batch_writer import PreparedBatchWriter
from domain_pipeline.prepare.config.loader import PipelineConfigLoader
from domain_pipeline.prepare.planner import PreparationPlanner
from domain_pipeline.prepare.prepare_to_aggregate_manifest import ManuallyAddedDomain
from domain_pipeline.prepare.source_items import SourceItemHandoff
from domain_pipeline.prepare.sources.parser import DomainListParser, InputFileFormat


def _config(
    tmp_path: Path,
    sources: list[dict[str, Any]],
    *,
    manual_inputs: dict[str, str] | None = None,
) -> dict[str, Any]:
    source_payloads = []
    for source in sources:
        source_id = source["id"]
        source_path = tmp_path / f"{source_id}.txt"
        source_path.write_text(source.pop("content"), encoding="utf-8")
        source_payloads.append(
            {
                "id": source_id,
                "input": {
                    "type": "file",
                    "location": str(source_path),
                    "format": source.pop("format", "plain"),
                },
                **source,
            }
        )
    payload: dict[str, Any] = {
        "version": 2,
        "output": {
            "filtered": [{"path": "output/filtered/fixture.txt", "format": "plain"}],
            "review": "output/review/fixture.csv",
            "unactionable": "output/unactionable/fixture.txt",
        },
        "sources": source_payloads,
    }
    if manual_inputs is not None:
        payload["manual_inputs"] = manual_inputs
    return PipelineConfigLoader().load_payload(
        payload,
        config_namespace="fixture",
        config_path=tmp_path / "fixture.yaml",
        validate_runtime_credentials=False,
    )


def test_explicit_adblock_domain_shaped_unanchored_pattern_has_no_target() -> None:
    """Only supported domain-anchored syntax creates a request-host association."""
    parsed = DomainListParser().parse_source_file(
        ["example.com\n", "||ads.example.net^\n"],
        forced_format=InputFileFormat.ADBLOCK,
    )

    assert parsed.file_format is InputFileFormat.ADBLOCK
    assert parsed.lines[0].parsed_item is not None
    assert parsed.lines[0].parsed_item.targets == ()
    assert (
        parsed.lines[0].parsed_item.no_target_reason
        == "network_filter_is_not_host_anchored"
    )
    assert parsed.lines[1].parsed_item is not None
    assert [target.host for target in parsed.lines[1].parsed_item.targets] == [
        "ads.example.net"
    ]


def test_source_item_handoff_keeps_adblock_format_and_metadata_distinct(
    tmp_path: Path,
) -> None:
    """Keep detected format, request targets, no-target rules, and metadata separate."""
    config = _config(
        tmp_path,
        [
            {
                "id": "block",
                "content": (
                    "[Adblock Plus 2.0]\n"
                    "||ads.example.com^\n"
                    "example.net\n"
                ),
                "format": "adblock",
            }
        ],
    )

    prepared = PreparationPlanner(source_root=tmp_path).prepare_config(config)
    handoff = SourceItemHandoff.build(batch_id="batch", prepared_inputs=prepared)
    records_by_id = {record["item_id"]: record for record in handoff.item_records}

    assert handoff.index_payload["sources"][0]["input_format"] == "adblock"
    assert records_by_id["block:1"]["is_metadata"] is True
    assert records_by_id["block:1"]["no_target_reason"] == "format_metadata"
    assert records_by_id["block:2"]["target_associations"][0]["host"] == (
        "ads.example.com"
    )
    assert records_by_id["block:3"]["is_metadata"] is False
    assert records_by_id["block:3"]["no_target_reason"] == (
        "network_filter_is_not_host_anchored"
    )
    assert handoff.index_payload["adblock_metadata"] == [
        {"item_id": "block:1", "association_id": None}
    ]
    assert handoff.index_payload[
        "valid_source_items_without_extractable_registrable_domain"
    ] == [
        {
            "item_id": "block:3",
            "association_id": None,
            "reason": "network_filter_is_not_host_anchored",
        }
    ]


def test_valid_public_suffix_input_has_no_prepare_review_or_worker_route(
    tmp_path: Path,
) -> None:
    """A valid public-suffix target has no prepare review or terminal route."""
    config = _config(
        tmp_path,
        [{"id": "block", "content": "co.uk\n"}],
    )

    prepared = PreparationPlanner(source_root=tmp_path).prepare_config(config)

    assert prepared.root_plans == {}
    assert prepared.entries_by_source == {}
    assert prepared.preparation_review_rows == []
    assert prepared.preparation_terminal_rows == []


def test_unmatched_public_suffix_manual_addition_stays_in_aggregate_inputs(
    tmp_path: Path,
) -> None:
    """An unmatched no-root manual addition remains a separate aggregate record."""
    config = _config(
        tmp_path,
        [{"id": "block", "content": "ads.example.com\n"}],
    )
    manual_path = tmp_path / "manual_inputs" / "manually_added" / "fixture.txt"
    manual_path.parent.mkdir(parents=True)
    manual_path.write_text("co.uk\n", encoding="utf-8")

    prepared = PreparationPlanner(source_root=tmp_path).prepare_config(config)
    _, _, manual_domains = PreparedBatchWriter().prepare_source_archive(prepared)

    assert manual_domains == [ManuallyAddedDomain(host="co.uk", registrable_domain=None)]
    assert prepared.preparation_review_rows == []
    assert prepared.preparation_terminal_rows == []


def test_unmatched_manual_selection_remains_prepare_review(tmp_path: Path) -> None:
    """An unmatched manual selection remains a prepare-owned review row."""
    config = _config(
        tmp_path,
        [{"id": "block", "content": "ads.example.com\n"}],
    )
    manual_path = (
        tmp_path
        / "manual_inputs"
        / "manually_selected_for_filtered"
        / "fixture.txt"
    )
    manual_path.parent.mkdir(parents=True)
    manual_path.write_text("manual.example.net\n", encoding="utf-8")

    prepared = PreparationPlanner(source_root=tmp_path).prepare_config(config)

    assert [row["host"] for row in prepared.preparation_review_rows] == [
        "manual.example.net"
    ]
    assert [row["host"] for row in prepared.preparation_terminal_rows] == [
        "manual.example.net"
    ]


def test_delegation_profile_conflict_is_checked_before_host_dedup(
    tmp_path: Path,
) -> None:
    """Every non-excluded source association contributes to root profile checks."""
    config = _config(
        tmp_path,
        [
            {
                "id": "one",
                "content": "ads.example.com\n",
                "delegation": {"retry_attempts": 2},
            },
            {
                "id": "two",
                "content": "ads.example.com\n",
                "delegation": {"retry_attempts": 3},
            },
        ],
    )

    with pytest.raises(ValueError, match="different delegation DNS behavior"):
        PreparationPlanner(source_root=tmp_path).prepare_config(config)


def test_host_resolution_profile_conflict_is_checked_before_host_dedup(
    tmp_path: Path,
) -> None:
    """Repeated ordinary inputs must agree on effective enabled-stage settings."""
    config = _config(
        tmp_path,
        [
            {
                "id": "one",
                "content": "ads.example.com\n",
                "host_resolution": {"enabled": True, "timeout": 2.0},
            },
            {
                "id": "two",
                "content": "ads.example.com\n",
                "host_resolution": {"enabled": True, "timeout": 4.0},
            },
        ],
    )

    with pytest.raises(ValueError, match="host-resolution profile"):
        PreparationPlanner(source_root=tmp_path).prepare_config(config)


def test_manual_route_ignores_host_and_ip_profile_differences(tmp_path: Path) -> None:
    """Manual input flags bypass downstream host/IP profile conflict checks."""
    config = _config(
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
                "content": "ads.example.com\n",
                "host_resolution": {"enabled": True, "timeout": 4.0},
                "ip_location": {"enabled": True, "timeout": 4.0},
            },
        ],
    )
    manual_path = (
        tmp_path
        / "manual_inputs"
        / "manually_selected_for_filtered"
        / "fixture.txt"
    )
    manual_path.parent.mkdir(parents=True)
    manual_path.write_text("ads.example.com\n", encoding="utf-8")

    prepared = PreparationPlanner(source_root=tmp_path).prepare_config(config)

    assert prepared.root_plans["example.com"].input_domains["ads.example.com"].host_resolution_profile is None
    assert prepared.root_plans["example.com"].input_domains["ads.example.com"].ip_location_profile is None


def test_manual_selection_and_exclusion_conflict_remains_rejected(
    tmp_path: Path,
) -> None:
    """Preserve the manual-input conflict across selection and exclusion files."""
    config = _config(
        tmp_path,
        [{"id": "block", "content": "ads.example.com\n"}],
    )
    selected_path = (
        tmp_path
        / "manual_inputs"
        / "manually_selected_for_filtered"
        / "fixture.txt"
    )
    excluded_path = (
        tmp_path
        / "manual_inputs"
        / "manually_excluded_from_sources"
        / "fixture.txt"
    )
    selected_path.parent.mkdir(parents=True)
    excluded_path.parent.mkdir(parents=True)
    selected_path.write_text("shared.example.net\n", encoding="utf-8")
    excluded_path.write_text("shared.example.net\n", encoding="utf-8")

    with pytest.raises(ValueError, match="conflicts with manually excluded file"):
        PreparationPlanner(source_root=tmp_path).prepare_config(config)
