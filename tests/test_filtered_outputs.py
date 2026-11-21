"""Tests for extra filtered outputs and exact AdBlock parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from domain_pipeline.aggregate.output_merge import AggregateOutputMerger
from domain_pipeline.prepare.assignment import aggregate_output_spec_from_config
from domain_pipeline.prepare.config.loader import (
    load_config_without_runtime_credentials,
)
from domain_pipeline.prepare.config.models import OutputConfig
from domain_pipeline.prepare.sources.parser import DomainEntry, DomainListParser


def test_block_config_uses_easylist_and_adds_filtered_output() -> None:
    """The example block config enables EasyList parsing and one extra output."""
    config = load_config_without_runtime_credentials(Path("config/block.yaml"))
    source = config["sources"][0]

    assert source["input"]["location"] == (
        "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/"
        "refs/heads/master/anti-ad-easylist.txt"
    )
    assert source["input"]["format"] == "adblock"
    assert source["output"]["filtered_files"] == [
        {"name": "block_easylist.txt", "format": "plain"}
    ]


def test_adblock_parser_extracts_only_exact_blocking_domains() -> None:
    """Only exact blocking AdBlock rules become domain entries."""
    parser = DomainListParser()
    entries = list(
        parser.process_entries(
            [
                "||ads.example.com^\n",
                "@@||allowed.example.com^\n",
                "||*.wildcard.example.com^\n",
                "/^tracker\\./\n",
            ],
            forced_format="adblock",
        )
    )

    assert entries == [
        DomainEntry(
            host="ads.example.com",
            registrable_domain="example.com",
        )
    ]


@pytest.mark.parametrize(
    ("output_format", "expected"),
    [
        ("plain", "ads.example.com\n"),
        ("hosts", "0.0.0.0 ads.example.com\n"),
        ("adblock", "||ads.example.com^\n"),
    ],
)
def test_filtered_output_formats(
    tmp_path: Path, output_format: str, expected: str
) -> None:
    """Write all configured line formats while deduplicating domain values."""
    target_path = tmp_path / "filtered" / "domains.txt"

    AggregateOutputMerger().write_filtered_host_values(
        ["ads.example.com", "ads.example.com"],
        target_path,
        output_format=output_format,
    )

    assert target_path.read_text(encoding="utf-8") == expected


def test_aggregate_spec_includes_additional_filtered_files() -> None:
    """Resolve additional configured filtered files into the aggregate spec."""
    spec = aggregate_output_spec_from_config(
        {
            "config_name": "block",
            "sources": [
                {
                    "enabled": True,
                    "output": {
                        "directory": "output",
                        "filtered_files": [
                            {"name": "block_easylist.txt", "format": "plain"}
                        ],
                    },
                }
            ],
        }
    )

    assert spec.filtered == "output/filtered/block.txt"
    assert [(item.path, item.format) for item in spec.filtered_files] == [
        ("output/filtered/block_easylist.txt", "plain")
    ]


def test_filtered_output_names_must_be_unique_and_safe() -> None:
    """Reject duplicate names and names that could escape the output directory."""
    with pytest.raises(ValueError, match="names must be unique"):
        OutputConfig.model_validate(
            {
                "filtered_files": [
                    {"name": "extra.txt"},
                    {"name": "extra.txt", "format": "adblock"},
                ]
            }
        )

    with pytest.raises(ValueError, match="filename"):
        OutputConfig.model_validate({"filtered_files": [{"name": "../outside.txt"}]})
