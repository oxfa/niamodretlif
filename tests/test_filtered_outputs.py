"""Tests for configured outputs and source-preserving filtering."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from domain_pipeline.aggregate.output_merge import AggregateOutputMerger
from domain_pipeline.aggregate.runner import AggregateBatchRunner
from domain_pipeline.prepare.assignment import (
    PreparedBatchPlanningInputs,
    WorkerAssignmentPlanner,
    WorkerManifestBuildRequest,
    aggregate_output_spec_from_config,
)
from domain_pipeline.prepare.batch_writer import PreparedBatchWriter
from domain_pipeline.prepare.config.loader import (
    PipelineConfigLoader,
    load_config_without_runtime_credentials,
)
from domain_pipeline.prepare.config.models import OutputConfig
from domain_pipeline.prepare.models import (
    PreparedInputSet,
    PreparedManualRouting,
    PreparedOutputRows,
    PreparedRootPlan,
)
from domain_pipeline.prepare.prepare_to_aggregate_manifest import (
    ManuallyAddedDomain,
    load_prepare_aggregate_manifest_for_batch,
)
from domain_pipeline.prepare.source_line_index import (
    SourceLineIndex,
    SourceLineReference,
)
from domain_pipeline.prepare.sources.jobs import SourceJob
from domain_pipeline.prepare.sources.parser import (
    DomainEntry,
    DomainListParser,
)
from domain_pipeline.routing.route_codes import RouteCode
from domain_pipeline.worker.output.writer import ResultOutputWriter
from domain_pipeline.worker.runtime.contracts import (
    CompletedHostResult,
    WorkerSourceContext,
)


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


def test_adblock_parser_extracts_concrete_blocking_domain_targets() -> None:
    """Extract concrete AdBlock targets while ignoring exceptions and regex rules."""
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
        ),
        DomainEntry(
            host="wildcard.example.com",
            registrable_domain="example.com",
        ),
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
    """Render retained source-domain lines using each configured output format."""
    target_path = tmp_path / "filtered" / "domains.txt"

    AggregateOutputMerger().write_filtered_source_content(
        ["ads.example.com\n"],
        SourceLineIndex(
            source_formats=("plain",),
            registrable_domain_lines={
                "example.com": (SourceLineReference(0, 1),),
            },
        ),
        [],
        [],
        target_path,
        output_format=output_format,
    )

    assert target_path.read_text(encoding="utf-8") == expected


def test_adblock_output_preserves_valid_non_domain_rules_and_filters_bad_targets(
    tmp_path: Path,
) -> None:
    """Keep meaningful AdBlock rules while removing only unactionable domains."""
    target_path = tmp_path / "filtered" / "rules.txt"
    source_content = (
        "[Adblock Plus 2.0]\n"
        "||bad.example.com^\n"
        "@@||allowed.example.net^\n"
        "good.example.org##.sponsored\n"
        "/^tracker\\./\n"
        "##.global-ad\n"
        "||good.example.org^\n"
    )

    AggregateOutputMerger().write_filtered_source_content(
        [source_content],
        SourceLineIndex(
            source_formats=("adblock",),
            registrable_domain_lines={
                "example.com": (SourceLineReference(0, 2),),
                "example.org": (SourceLineReference(0, 7),),
            },
        ),
        ["example.com"],
        [],
        target_path,
        output_format="adblock",
    )

    assert target_path.read_text(encoding="utf-8") == (
        "[Adblock Plus 2.0]\n"
        "@@||allowed.example.net^\n"
        "good.example.org##.sponsored\n"
        "/^tracker\\./\n"
        "##.global-ad\n"
        "||good.example.org^\n"
    )


def test_hosts_line_filters_only_unactionable_aliases(tmp_path: Path) -> None:
    """Preserve actionable hosts aliases when a line spans multiple roots."""
    target_path = tmp_path / "filtered" / "hosts.txt"

    AggregateOutputMerger().write_filtered_source_content(
        ["0.0.0.0 bad.example.com good.example.org\n"],
        SourceLineIndex(
            source_formats=("hosts",),
            registrable_domain_lines={
                "example.com": (SourceLineReference(0, 1),),
                "example.org": (SourceLineReference(0, 1),),
            },
        ),
        ["example.com"],
        [],
        target_path,
        output_format="hosts",
    )

    assert target_path.read_text(encoding="utf-8") == "0.0.0.0 good.example.org\n"


def test_source_archive_keeps_valid_non_domain_lines_and_indexes_targets() -> None:
    """Clean comments and invalid lines without dropping valid AdBlock rules."""
    source_job = SourceJob(
        source_id="block",
        input_label="fixture",
        output_stem="block",
        lines=[
            "! comment\n",
            "||blocked.example.com^\n",
            "@@||allowed.example.net^\n",
            "||*.wildcard.example.com^\n",
            "##.global-ad\n",
            "/^tracker\\./\n",
            "not a valid rule\n",
        ],
        config={"input": {"format": "adblock"}},
    )
    prepared_inputs = PreparedInputSet(
        config={},
        source_jobs_by_id={"block": source_job},
        parsed_source_entry_count=0,
        entries_by_source={},
        manual_routing_by_host={},
        root_plans={},
        preparation_outputs=PreparedOutputRows(review_rows=[], terminal_rows=[]),
    )

    contents, index, manually_added_domains = (
        PreparedBatchWriter()._prepare_source_archive(prepared_inputs)
    )

    assert contents == [
        "||blocked.example.com^\n"
        "@@||allowed.example.net^\n"
        "||*.wildcard.example.com^\n"
        "##.global-ad\n"
        "/^tracker\\./\n"
    ]
    assert index.source_formats == ("adblock",)
    assert index.registrable_domain_lines == {
        "example.com": (
            SourceLineReference(0, 1),
            SourceLineReference(0, 3),
        )
    }
    assert manually_added_domains == []


def test_source_archive_keeps_manual_additions_separate() -> None:
    """Keep unmatched manual additions out of the configured-source archive."""
    source_job = SourceJob(
        source_id="block",
        input_label="fixture",
        output_stem="block",
        lines=["||source.example.com^\n"],
        config={"input": {"format": "adblock"}},
    )
    manual_entry = DomainEntry(
        host="manual.example.net",
        registrable_domain="example.net",
    )
    prepared_inputs = PreparedInputSet(
        config={},
        source_jobs_by_id={"block": source_job},
        parsed_source_entry_count=1,
        entries_by_source={"block": [manual_entry]},
        manual_routing_by_host={
            manual_entry.host: PreparedManualRouting(manually_added=True)
        },
        root_plans={},
        preparation_outputs=PreparedOutputRows(review_rows=[], terminal_rows=[]),
    )

    contents, index, manually_added_domains = (
        PreparedBatchWriter()._prepare_source_archive(prepared_inputs)
    )

    assert contents == ["||source.example.com^\n"]
    assert index.source_formats == ("adblock",)
    assert index.registrable_domain_lines == {
        "example.com": (SourceLineReference(0, 1),)
    }
    assert manually_added_domains == [
        ManuallyAddedDomain(
            host="manual.example.net",
            registrable_domain="example.net",
        )
    ]


@pytest.mark.parametrize(
    ("output_format", "expected"),
    [
        ("plain", "manual.example.net\n"),
        ("hosts", "0.0.0.0 manual.example.net\n"),
        ("adblock", "||manual.example.net^\n"),
    ],
)
def test_aggregate_renders_actionable_manual_additions(
    tmp_path: Path, output_format: str, expected: str
) -> None:
    """Render unmatched manual additions in each configured output format."""
    target_path = tmp_path / "filtered" / "manual.txt"

    AggregateOutputMerger().write_filtered_source_content(
        [],
        SourceLineIndex(source_formats=(), registrable_domain_lines={}),
        [],
        [
            ManuallyAddedDomain(
                host="manual.example.net",
                registrable_domain="example.net",
            )
        ],
        target_path,
        output_format=output_format,
    )

    assert target_path.read_text(encoding="utf-8") == expected


def test_aggregate_omits_unactionable_manual_additions(tmp_path: Path) -> None:
    """Filter separately handed-off manual hosts by their registrable domain."""
    target_path = tmp_path / "filtered" / "manual.txt"

    AggregateOutputMerger().write_filtered_source_content(
        [],
        SourceLineIndex(source_formats=(), registrable_domain_lines={}),
        ["example.net"],
        [
            ManuallyAddedDomain(
                host="manual.example.net",
                registrable_domain="example.net",
            )
        ],
        target_path,
        output_format="plain",
    )

    assert target_path.read_text(encoding="utf-8") == ""


def test_worker_writer_does_not_create_filtered_output(tmp_path: Path) -> None:
    """Keep actionable host results for audit without writing a worker filtered file."""
    output_directory = tmp_path / "worker-output"
    audit_path = tmp_path / "worker-audit.jsonl"
    writer = ResultOutputWriter()
    writer.add(
        CompletedHostResult(
            source_context=WorkerSourceContext(
                source_id="block",
                input_label="fixture",
                output_stem="block",
                config={
                    "output": {
                        "directory": str(output_directory),
                        "terminal_rows_file": str(audit_path),
                    }
                },
            ),
            entry=DomainEntry(
                host="ads.example.com",
                registrable_domain="example.com",
            ),
            route="filtered",
            route_code=RouteCode.HOST_RESOLUTION_TO_FILTERED_SKIPPED,
            row={"host": "ads.example.com"},
        )
    )

    writer.write()

    assert not (output_directory / "filtered").exists()
    assert audit_path.read_text(encoding="utf-8") == (
        '{"host": "ads.example.com", "route": "filtered"}\n'
    )


def test_unmatched_manual_additions_are_in_prepare_aggregate_manifest(
    tmp_path: Path,
) -> None:
    """Persist manual additions on the prepare-to-aggregate handoff."""
    source_job = SourceJob(
        source_id="block",
        input_label="fixture",
        output_stem="block",
        lines=["||source.example.com^\n"],
        config={"input": {"format": "adblock"}},
    )
    manual_entry = DomainEntry(
        host="manual.example.net",
        registrable_domain="example.net",
    )
    prepared_inputs = PreparedInputSet(
        config={
            "config_name": "block",
            "sources": [{"id": "block", "enabled": True}],
            "output": {
                "filtered": [{"path": "output/filtered/block.txt", "format": "plain"}],
                "review": "output/review/block.csv",
                "unactionable": "output/unactionable/block.txt",
            },
        },
        source_jobs_by_id={"block": source_job},
        parsed_source_entry_count=1,
        entries_by_source={"block": [manual_entry]},
        manual_routing_by_host={
            manual_entry.host: PreparedManualRouting(manually_added=True)
        },
        root_plans={},
        preparation_outputs=PreparedOutputRows(review_rows=[], terminal_rows=[]),
    )

    batch_writer = PreparedBatchWriter()
    batch = batch_writer.from_prepared_inputs(
        prepared_inputs=prepared_inputs,
        worker_ids=[],
        batch_id="batch",
    )
    batch_writer.write(batch, state_root=tmp_path)
    persisted_manifest = load_prepare_aggregate_manifest_for_batch(
        batch_id="batch",
        state_root=tmp_path,
    )

    assert batch.source_input_contents == ["||source.example.com^\n"]
    assert persisted_manifest.manually_added_domains == [
        ManuallyAddedDomain(
            host="manual.example.net",
            registrable_domain="example.net",
        )
    ]


def test_batch_emits_empty_manifests_for_every_configured_worker(
    tmp_path: Path,
) -> None:
    """Keep worker artifacts present even when no root is assigned."""
    config = load_config_without_runtime_credentials(Path("config/block.yaml"))
    source_config = config["sources"][0]
    source_job = SourceJob(
        source_id=source_config["id"],
        input_label="fixture",
        output_stem="block",
        lines=["||blocked.example.com^\n"],
        config=source_config,
    )
    prepared_inputs = PreparedInputSet(
        config=config,
        source_jobs_by_id={source_job.source_id: source_job},
        parsed_source_entry_count=1,
        entries_by_source={},
        manual_routing_by_host={},
        root_plans={},
        preparation_outputs=PreparedOutputRows(review_rows=[], terminal_rows=[]),
    )

    batch_writer = PreparedBatchWriter()
    batch = batch_writer.from_prepared_inputs(
        prepared_inputs=prepared_inputs,
        worker_ids=["worker-1", "worker-2", "worker-3"],
        batch_id="batch",
    )
    committed_paths = batch_writer.write(batch, state_root=tmp_path)

    assert [manifest.worker_id for manifest in batch.worker_manifests] == [
        "worker-1",
        "worker-2",
        "worker-3",
    ]
    assert all(
        not manifest.manifest.prepared_metadata.delegation_roots
        for manifest in batch.worker_manifests
    )
    assert len(batch.prepare_aggregate_manifest.worker_ids) == 3
    assert any("source-line-index.json" in path for path in committed_paths)
    source_contents, source_line_index = AggregateBatchRunner()._load_source_archive(
        batch_id="batch",
        state_root=tmp_path,
    )
    assert source_contents == ["||blocked.example.com^\n"]
    assert source_line_index.registrable_domain_lines == {
        "example.com": (SourceLineReference(0, 1),)
    }


def test_worker_assignment_balances_registrable_domains_not_host_counts() -> None:
    """Treat each registrable domain as one unit of worker work."""
    roots = [
        "a.example.com",
        "b.example.com",
        "c.example.com",
        "d.example.com",
    ]
    entries_by_root = {
        root: [
            ("block", DomainEntry(host=f"host-{index}.{root}", registrable_domain=root))
            for index in range(3 if root == roots[0] else 1)
        ]
        for root in roots
    }
    planning_inputs = PreparedBatchPlanningInputs(
        source_jobs_by_id={"block": None},
        eligible_root_entries=entries_by_root,
        public_suffix_entries=[],
        root_plans={
            root: PreparedRootPlan(
                registrable_domain=root,
                entry_count=len(entries),
                delegation_config_source_id="block",
                delegation_behavior_fingerprint="fixture",
            )
            for root, entries in entries_by_root.items()
        },
    )

    source_entries, root_plans, root_counts = WorkerAssignmentPlanner().assign(
        planning_inputs=planning_inputs,
        worker_ids=["worker-1", "worker-2"],
    )

    assert {worker_id: len(roots) for worker_id, roots in root_plans.items()} == {
        "worker-1": 2,
        "worker-2": 2,
    }
    assert {worker_id: count for worker_id, count in root_counts.items()} == {
        "worker-1": 2,
        "worker-2": 2,
    }
    assert all(source_entries[worker_id] for worker_id in root_plans)


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
        )
    )
    runtime_spec = manifests[0].manifest.runtime_spec

    assert runtime_spec.sources[0].output.directory.endswith("publish_snapshot/output")
    assert runtime_spec.sources[0].output.model_dump() == {
        "directory": runtime_spec.sources[0].output.directory
    }
    assert "filtered" not in runtime_spec.output_spec.model_dump()


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
