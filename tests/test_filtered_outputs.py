"""Tests for extra filtered outputs and exact AdBlock parsing."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from domain_pipeline.aggregate.output_merge import AggregateOutputMerger
from domain_pipeline.prepare.assignment import (
    WorkerAssignmentPlanner,
    WorkerManifestBuildRequest,
    aggregate_output_spec_from_config,
)
from domain_pipeline.prepare.config.loader import (
    PipelineConfigLoader,
    load_config_without_runtime_credentials,
)
from domain_pipeline.prepare.config.models import OutputConfig
from domain_pipeline.prepare.models import PreparedRootPlan
from domain_pipeline.prepare.sources.jobs import SourceJob
from domain_pipeline.prepare.sources.parser import DomainEntry, DomainListParser


def test_block_config_explicitly_configures_each_filtered_output() -> None:
    """The block config lists every publish output at config scope."""
    config = load_config_without_runtime_credentials(Path("config/block.yaml"))
    source = config["sources"][0]

    assert source["input"]["location"] == (
        "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/"
        "refs/heads/master/anti-ad-easylist.txt"
    )
    assert source["input"]["format"] == "adblock"
    assert "output" not in source
    assert config["output"] == {
        "filtered": [
            {"path": "output/filtered/block.txt", "format": "plain"},
            {
                "path": "output/filtered/block_easylist.txt",
                "format": "adblock",
            },
        ],
        "review": "output/review/block.csv",
        "unactionable": "output/unactionable/block.txt",
    }


def test_sample_config_inherits_defaults_and_keeps_outputs_at_root() -> None:
    """Resolve default source settings while keeping output config at root."""
    config = load_config_without_runtime_credentials(
        Path("config/domain-pipeline.yaml.sample")
    )
    source = config["sources"][0]

    assert config["output"]["review"] == "output/review/domain-pipeline.csv"
    assert "output" not in source
    assert source["fetch"] == config["defaults"]["fetch"]
    assert source["delegation"] == config["defaults"]["delegation"]
    assert source["host_resolution"]["targets"]["root_domain"] is False
    assert config["defaults"]["host_resolution"]["targets"]["root_domain"] is True


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
    """Render duplicate host values using each supported output format."""
    target_path = tmp_path / "filtered" / "domains.txt"

    AggregateOutputMerger().write_filtered_host_values(
        ["ads.example.com", "ads.example.com"],
        target_path,
        output_format=output_format,
    )

    assert target_path.read_text(encoding="utf-8") == expected


def test_aggregate_spec_uses_only_configured_output_paths() -> None:
    """Resolve configured filtered files without a derived default output."""
    spec = aggregate_output_spec_from_config(
        {
            "config_name": "block",
            "output": {
                "filtered": [
                    {"path": "output/filtered/block.txt", "format": "plain"},
                    {
                        "path": "output/filtered/block_easylist.txt",
                        "format": "adblock",
                    },
                ],
                "review": "output/review/block.csv",
                "unactionable": "output/unactionable/block.txt",
            },
            "sources": [
                {"enabled": True},
                {"enabled": True},
            ],
        }
    )

    assert [(item.path, item.format) for item in spec.filtered] == [
        ("output/filtered/block.txt", "plain"),
        ("output/filtered/block_easylist.txt", "adblock"),
    ]
    assert spec.review == "output/review/block.csv"
    assert spec.unactionable == "output/unactionable/block.txt"


def test_config_requires_at_least_one_filtered_output() -> None:
    """Require each config to define at least one filtered output."""
    config_path = Path("config/block.yaml")
    payload = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    payload["output"]["filtered"] = []

    with pytest.raises(ValueError, match="output.filtered"):
        PipelineConfigLoader().load_payload(
            payload,
            config_namespace="block",
            config_path=config_path,
            validate_runtime_credentials=False,
        )


@pytest.mark.parametrize(
    ("config_path", "source_id"),
    [("config/block.yaml", "block"), ("config/direct.yaml", "direct")],
)
def test_additional_filtered_outputs_are_not_sent_to_worker_runtime(
    config_path: str, source_id: str
) -> None:
    """Keep aggregate-only filtered output settings out of worker manifests."""
    config = load_config_without_runtime_credentials(Path(config_path))
    source = next(item for item in config["sources"] if item["id"] == source_id)
    entry = DomainEntry(host="ads.example.com", registrable_domain="example.com")
    source_job = SourceJob(
        source_id=source_id,
        input_label="fixture",
        output_stem=str(config["config_name"]),
        lines=[],
        config=source,
    )
    manifests = WorkerAssignmentPlanner().build_worker_manifests(
        WorkerManifestBuildRequest(
            config=config,
            batch_id="batch",
            worker_ids=["worker-1"],
            worker_source_entries={"worker-1": {source_id: [entry]}},
            worker_root_plans={
                "worker-1": {
                    "example.com": PreparedRootPlan(
                        registrable_domain="example.com",
                        entry_count=1,
                        delegation_config_source_id=source_id,
                        delegation_behavior_fingerprint="fixture",
                    )
                }
            },
            source_jobs_by_id={source_id: source_job},
            manual_routing_by_host={},
        )
    )
    runtime_spec = manifests[0].manifest.runtime_spec

    assert runtime_spec.sources[0].output.directory.endswith("publish_snapshot/output")
    assert runtime_spec.sources[0].output.model_dump() == {
        "directory": runtime_spec.sources[0].output.directory
    }


def test_output_paths_must_be_unique_and_safe() -> None:
    """Reject duplicate paths and paths that could escape the publish worktree."""
    with pytest.raises(ValueError, match="output paths must be unique"):
        OutputConfig.model_validate(
            {
                "filtered": [
                    {"path": "output/extra.txt"},
                    {"path": "output/extra.txt", "format": "adblock"},
                ],
                "review": "output/review.csv",
                "unactionable": "output/unactionable.txt",
            }
        )

    with pytest.raises(ValueError, match="safe relative path"):
        OutputConfig.model_validate(
            {
                "filtered": [
                    {"path": "../outside.txt"},
                ],
                "review": "output/review.csv",
                "unactionable": "output/unactionable.txt",
            }
        )
