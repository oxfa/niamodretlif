"""Tests for configured outputs and source-preserving filtering."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from domain_pipeline.aggregate.output_merge import AggregateOutputMerger
from domain_pipeline.paths.layout import PathLayout
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
    load_source_line_index,
)
from domain_pipeline.prepare.source_items import SourceItemHandoff
from domain_pipeline.prepare.sources.jobs import SourceJob
from domain_pipeline.prepare.sources import parser as parser_module
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


def _source_item_handoff(
    lines: list[str],
    *,
    file_format: str,
    excluded_hosts: set[str] | None = None,
    supply_parsed_source_file: bool = True,
) -> SourceItemHandoff:
    """Build the same prepared item contract the aggregate runner consumes."""
    source_job = SourceJob(
        source_id="source",
        input_label="fixture",
        output_stem="source",
        lines=lines,
        config={"input": {"format": file_format}},
    )
    parsed_source_files = {}
    if supply_parsed_source_file:
        parser = DomainListParser()
        parsed_source_files[source_job.source_id] = parser.parse_source_file(
            lines,
            source_name=source_job.input_label,
            forced_format=None if file_format == "auto" else file_format,
        )
    prepared_inputs = PreparedInputSet(
        config={},
        source_jobs_by_id={source_job.source_id: source_job},
        parsed_source_entry_count=0,
        entries_by_source={},
        manual_routing_by_host={},
        root_plans={},
        preparation_outputs=PreparedOutputRows(review_rows=[], terminal_rows=[]),
        excluded_source_hosts=set(excluded_hosts or ()),
        parsed_source_files=parsed_source_files,
    )
    return SourceItemHandoff.build(
        batch_id="batch", prepared_inputs=prepared_inputs
    )


def test_source_item_handoff_requires_prepare_parse_results() -> None:
    """Do not rebuild source associations by reparsing original lines."""
    with pytest.raises(
        ValueError,
        match="prepare parse results are missing for configured source 'source'",
    ):
        _source_item_handoff(
            ["ads.example.com\n"],
            file_format="plain",
            supply_parsed_source_file=False,
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
    """Extract blocking and exception targets without inventing wildcard hosts."""
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
        DomainEntry(host="ads.example.com", registrable_domain="example.com"),
        DomainEntry(host="allowed.example.com", registrable_domain="example.com"),
    ]


def test_configured_adblock_standalone_domain_is_a_request_host_target() -> None:
    """Interpret a standalone literal domain as a target in explicit AdBlock input."""
    parser = DomainListParser()

    entries = list(
        parser.process_entries(
            ["standalone.example.net\n"],
            forced_format="adblock",
        )
    )

    assert entries == [
        DomainEntry(host="standalone.example.net", registrable_domain="example.net")
    ]


def test_adblock_host_modifiers_preserve_literal_target_and_rule_text(
    tmp_path: Path,
) -> None:
    """Keep supported AdGuard modifiers attached to their request-host rules."""
    lines = [
        "||ads.example.com^$dnstype=script\n",
        "||cdn.example.com^$denyallow=example.org\n",
    ]
    source_items = _source_item_handoff(lines, file_format="adblock")
    target_path = tmp_path / "filtered" / "modifier-rules.txt"

    AggregateOutputMerger().write_filtered_source_items(
        source_items,
        [],
        [],
        (target_path, "adblock"),
    )

    assert source_items.index_payload[
        "valid_source_items_by_registrable_domain"
    ] == {
        "example.com": [
            {"item_id": "source:1", "association_id": "source:1:target:1"},
            {"item_id": "source:2", "association_id": "source:2:target:1"},
        ]
    }
    assert target_path.read_text(encoding="utf-8") == "".join(lines)


@pytest.mark.parametrize(
    "output_format",
    ["plain", "hosts"],
)
def test_adblock_exceptions_are_not_rendered_as_plain_or_hosts(
    tmp_path: Path, output_format: str
) -> None:
    """Do not turn allow rules into blocking lines in non-AdBlock formats."""
    source_items = _source_item_handoff(
        ["@@||allowed.example.net^\n"], file_format="adblock"
    )
    target_path = tmp_path / f"exceptions-{output_format}.txt"

    AggregateOutputMerger().write_filtered_source_items(
        source_items,
        [],
        [],
        (target_path, output_format),
    )

    assert source_items.index_payload["valid_source_items_by_registrable_domain"].keys() == {
        "example.net"
    }
    assert target_path.read_text(encoding="utf-8") == ""


def test_adblock_host_path_rule_maps_and_renders_request_host(
    tmp_path: Path,
) -> None:
    """Use the literal request host from a supported host/path rule."""
    source_items = _source_item_handoff(
        ["||ads.example.com/ads/*\n"], file_format="adblock"
    )
    target_path = tmp_path / "host-path.txt"

    AggregateOutputMerger().write_filtered_source_items(
        source_items,
        [],
        [],
        (target_path, "plain"),
    )

    assert source_items.index_payload["valid_source_items_by_registrable_domain"].keys() == {
        "example.com"
    }
    assert target_path.read_text(encoding="utf-8") == "ads.example.com\n"


@pytest.mark.parametrize(
    ("host", "registrable_domain"),
    [
        ("news.example.co.uk", "example.co.uk"),
        ("tenant.blogspot.com", "tenant.blogspot.com"),
    ],
)
def test_full_psl_maps_icann_and_private_suffixes(
    host: str, registrable_domain: str
) -> None:
    """Map registrable domains under both ICANN and PRIVATE PSL rules."""
    source_items = _source_item_handoff([f"{host}\n"], file_format="plain")

    assert source_items.index_payload["valid_source_items_by_registrable_domain"].keys() == {
        registrable_domain
    }
    assert source_items.item_records[0]["target_associations"][0][
        "registrable_domain"
    ] == registrable_domain


def test_adblock_regex_validation_uses_ecmascript_syntax() -> None:
    """Accept JavaScript named groups and diagnose Python-only group syntax."""
    source_items = _source_item_handoff(
        ["/(?<label>ads?)/\n", "/(?P<label>ads?)/\n"],
        file_format="adblock",
    )

    assert [item["original_text"] for item in source_items.item_records] == [
        "/(?<label>ads?)/"
    ]
    assert source_items.diagnostic_records == (
        {
            "batch_id": "batch",
            "source_ordinal": 0,
            "source_id": "source",
            "source_label": "fixture",
            "source_line_number": 2,
            "input_format": "adblock",
            "original_text": "/(?P<label>ads?)/",
            "reason": "invalid_regular_expression_filter",
            "target_ordinal": None,
        },
    )


@pytest.mark.parametrize(("validator_output", "expected"), [("valid", True), ("invalid", False)])
def test_adblock_regex_validation_caches_repeated_results(
    monkeypatch: pytest.MonkeyPatch,
    validator_output: str,
    expected: bool,
) -> None:
    """Reuse both accepted and rejected checks for repeated pattern bodies."""
    validator = parser_module._is_valid_ecmascript_regex
    validator.cache_clear()
    calls: list[tuple[object, dict[str, object]]] = []

    def fake_run(
        args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, validator_output, "")

    monkeypatch.setattr(parser_module.subprocess, "run", fake_run)
    try:
        assert validator("repeated-regex-body") is expected
        assert validator("repeated-regex-body") is expected
        assert len(calls) == 1
        assert calls[0][1]["timeout"] == 10
    finally:
        validator.cache_clear()


def test_adblock_regex_validation_timeout_is_operational_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail explicitly and retry after a timed-out Node validation."""
    validator = parser_module._is_valid_ecmascript_regex
    validator.cache_clear()
    calls = 0

    def time_out(args: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        raise subprocess.TimeoutExpired(args, kwargs["timeout"])

    monkeypatch.setattr(parser_module.subprocess, "run", time_out)
    try:
        for _ in range(2):
            with pytest.raises(RuntimeError, match="validator timed out"):
                validator("timed-out-regex-body")
        assert calls == 2
    finally:
        validator.cache_clear()


def test_adblock_regex_validator_unavailability_fails_preparation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Treat a missing Node validator as an operational preparation failure."""
    validator = parser_module._is_valid_ecmascript_regex
    validator.cache_clear()

    def fail_to_launch(*_args: object, **_kwargs: object) -> None:
        raise FileNotFoundError("node")

    monkeypatch.setattr(
        "domain_pipeline.prepare.sources.parser.subprocess.run", fail_to_launch
    )

    try:
        with pytest.raises(RuntimeError, match="unable to run Node.js ECMAScript"):
            _source_item_handoff(["/example.*/\n"], file_format="adblock")
    finally:
        validator.cache_clear()


@pytest.mark.parametrize(
    ("lines", "expected_format"),
    [
        (["#@?#.extended-exception\n"], "unknown"),
        (
            [
                "||blocked.example.com^\n",
                "plain.example.net\n",
                "#@?#.extended-exception\n",
            ],
            "mixed",
        ),
    ],
)
def test_auto_format_diagnoses_leading_unsupported_cosmetic_items(
    lines: list[str], expected_format: str
) -> None:
    """Keep leading unsupported cosmetic operators in whole-source diagnostics."""
    source_items = _source_item_handoff(lines, file_format="auto")

    assert source_items.index_payload["sources"][0]["input_format"] == expected_format
    assert {
        "original_text": "#@?#.extended-exception",
        "reason": f"source_file_format_{expected_format}",
    } in [
        {
            "original_text": diagnostic["original_text"],
            "reason": diagnostic["reason"],
        }
        for diagnostic in source_items.diagnostic_records
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
    """Render prepared source-item associations in each configured output format."""
    target_path = tmp_path / "filtered" / "domains.txt"

    AggregateOutputMerger().write_filtered_source_items(
        _source_item_handoff(["ads.example.com\n"], file_format="plain"),
        [],
        [],
        (target_path, output_format),
    )

    assert target_path.read_text(encoding="utf-8") == expected


@pytest.mark.parametrize(
    ("output_format", "expected"),
    [
        ("plain", ""),
        ("hosts", ""),
        (
            "adblock",
            "/example.*/\n"
            r"/\/(ads?|advert|advertising|adserver)([\/._?-]|$)/$third-party"
            "\n"
            "||*.wildcard.example.com^\n"
            "||adserver.*^\n"
            "##.global-ad\n"
            "#@#.global-ad\n"
            "example.com##.sponsored\n",
        ),
    ],
)
def test_valid_adblock_no_target_items_render_only_as_adblock(
    tmp_path: Path, output_format: str, expected: str
) -> None:
    """Preserve valid rules without worker hosts only in AdBlock output."""
    lines = [
        "/example.*/\n",
        r"/\/(ads?|advert|advertising|adserver)([\/._?-]|$)/$third-party" + "\n",
        "||*.wildcard.example.com^\n",
        "||adserver.*^\n",
        "##.global-ad\n",
        "#@#.global-ad\n",
        "example.com##.sponsored\n",
    ]
    target_path = tmp_path / "filtered" / f"no-target-{output_format}.txt"

    AggregateOutputMerger().write_filtered_source_items(
        _source_item_handoff(lines, file_format="adblock"),
        [],
        [],
        (target_path, output_format),
    )

    assert target_path.read_text(encoding="utf-8") == expected


def test_invalid_adblock_lines_are_diagnosed_and_not_rendered(
    tmp_path: Path,
) -> None:
    """Keep malformed short patterns and out-of-profile cosmetics out of output."""
    lines = [
        "||\n",
        "||^\n",
        "||bad_host^\n",
        "example.com#@?#.extended-exception\n",
    ]
    source_items = _source_item_handoff(lines, file_format="adblock")
    target_path = tmp_path / "filtered" / "invalid-rules.txt"

    AggregateOutputMerger().write_filtered_source_items(
        source_items,
        [],
        [],
        (target_path, "adblock"),
    )

    assert source_items.item_records == ()
    assert [diagnostic["original_text"] for diagnostic in source_items.diagnostic_records] == [
        line.rstrip("\n") for line in lines
    ]
    assert target_path.read_text(encoding="utf-8") == ""


def test_adblock_source_exclusions_do_not_reappear_in_filtered_outputs(
    tmp_path: Path,
) -> None:
    """Apply prepare exclusions before either worker mapping or rendering."""
    source_items = _source_item_handoff(
        ["||blocked.example.com^\n"],
        file_format="adblock",
        excluded_hosts={"blocked.example.com"},
    )
    target_path = tmp_path / "filtered" / "excluded.txt"

    AggregateOutputMerger().write_filtered_source_items(
        source_items,
        [],
        [],
        (target_path, "adblock"),
    )

    assert source_items.index_payload["valid_source_items_by_registrable_domain"] == {}
    assert target_path.read_text(encoding="utf-8") == ""


def test_source_item_semantics_reject_a_reintroduced_excluded_target(
    tmp_path: Path,
) -> None:
    """Reject a changed item/index pair when prepare marked its host excluded."""
    excluded_host = "blocked.example.com"
    source_items = _source_item_handoff(
        [f"{excluded_host}\n"],
        file_format="plain",
        excluded_hosts={excluded_host},
    )
    record = source_items.item_records[0]
    association = record["target_associations"][0]
    association["excluded_from_sources"] = False
    source_items.index_payload["valid_source_items_by_registrable_domain"] = {
        "example.com": [
            {
                "item_id": record["item_id"],
                "association_id": association["association_id"],
            }
        ]
    }
    items_path = tmp_path / "source-items.jsonl"
    index_path = tmp_path / "source-item-index.json"
    diagnostics_path = tmp_path / "source-item-diagnostics.jsonl"
    source_items.write(
        items_path=items_path,
        index_path=index_path,
        diagnostics_path=diagnostics_path,
    )

    with pytest.raises(ValueError, match="exclusion decision does not match"):
        SourceItemHandoff.load(
            batch_id="batch",
            items_path=items_path,
            index_path=index_path,
            diagnostics_path=diagnostics_path,
            validate_semantics=True,
            excluded_source_hosts={excluded_host},
        )


def test_filtered_output_deduplicates_rendered_hosts_not_provenance(
    tmp_path: Path,
) -> None:
    """Collapse duplicate lines while retaining distinct prepared source items."""
    source_items = _source_item_handoff(
        ["ads.example.com\n", "ads.example.com\n", "cdn.example.com\n"],
        file_format="plain",
    )
    target_path = tmp_path / "filtered" / "deduplicated.txt"

    AggregateOutputMerger().write_filtered_source_items(
        source_items,
        [],
        [],
        (target_path, "plain"),
    )

    assert len(source_items.item_records) == 3
    assert target_path.read_text(encoding="utf-8") == (
        "ads.example.com\ncdn.example.com\n"
    )


def test_multi_target_line_preserves_physical_and_occurrence_provenance(
    tmp_path: Path,
) -> None:
    """Keep source line and repeated target identities when rendered lines dedupe."""
    original_text = "0.0.0.0 repeated.example.com repeated.example.com"
    source_items = _source_item_handoff(
        ["\n", f"{original_text}\n"], file_format="hosts"
    )
    target_path = tmp_path / "filtered" / "repeated-hosts.txt"

    AggregateOutputMerger().write_filtered_source_items(
        source_items,
        [],
        [],
        (target_path, "hosts"),
    )

    assert len(source_items.item_records) == 1
    item = source_items.item_records[0]
    assert item["item_id"] == "source:2"
    assert item["source_line_number"] == 2
    assert item["original_text"] == original_text
    assert [
        (association["association_id"], association["target_ordinal"])
        for association in item["target_associations"]
    ] == [
        ("source:2:target:1", 1),
        ("source:2:target:2", 2),
    ]
    assert [
        reference["association_id"]
        for reference in source_items.index_payload[
            "valid_source_items_by_registrable_domain"
        ]["example.com"]
    ] == ["source:2:target:1", "source:2:target:2"]
    assert target_path.read_text(encoding="utf-8") == (
        "0.0.0.0 repeated.example.com\n"
    )


@pytest.mark.parametrize(
    ("output_format", "expected"),
    [
        ("plain", "co.uk\n"),
        ("hosts", "0.0.0.0 co.uk\n"),
        ("adblock", "||co.uk^\n"),
    ],
)
def test_public_suffix_target_without_registrable_domain_is_kept(
    tmp_path: Path, output_format: str, expected: str
) -> None:
    """Render a valid suffix-only item according to the selected output format."""
    source_items = _source_item_handoff(["co.uk\n"], file_format="plain")
    target_path = tmp_path / "filtered" / f"suffix-{output_format}.txt"

    AggregateOutputMerger().write_filtered_source_items(
        source_items,
        [],
        [],
        (target_path, output_format),
    )

    assert source_items.index_payload[
        "valid_source_items_without_extractable_registrable_domain"
    ][0]["reason"] == "public_suffix_only"
    assert source_items.index_payload["valid_source_items_by_registrable_domain"] == {}
    assert target_path.read_text(encoding="utf-8") == expected


def test_excluded_public_suffix_is_not_indexed_or_rendered(tmp_path: Path) -> None:
    """An exclusion removes a suffix-only item from its separate no-domain index."""
    source_items = _source_item_handoff(
        ["co.uk\n"], file_format="plain", excluded_hosts={"co.uk"}
    )
    target_path = tmp_path / "filtered" / "excluded-public-suffix.txt"

    AggregateOutputMerger().write_filtered_source_items(
        source_items,
        [],
        [],
        (target_path, "adblock"),
    )

    assert source_items.index_payload[
        "valid_source_items_by_registrable_domain"
    ] == {}
    assert source_items.index_payload[
        "valid_source_items_without_extractable_registrable_domain"
    ] == []
    assert source_items.item_records[0]["target_associations"][0][
        "excluded_from_sources"
    ] is True
    assert target_path.read_text(encoding="utf-8") == ""


def test_strict_psl_miss_is_invalid_and_never_rendered(tmp_path: Path) -> None:
    """Exclude a validly parsed host when it has no strict PSL match."""
    source_items = _source_item_handoff(["example.invalid\n"], file_format="plain")
    target_path = tmp_path / "filtered" / "invalid-psl-target.txt"

    assert source_items.index_payload[
        "valid_source_items_by_registrable_domain"
    ] == {}
    assert source_items.index_payload[
        "valid_source_items_without_extractable_registrable_domain"
    ] == []
    assert source_items.item_records[0]["target_associations"][0][
        "error_reason"
    ] == "no_strict_public_suffix_match"
    assert source_items.diagnostic_records[0]["reason"] == (
        "no_strict_public_suffix_match"
    )

    AggregateOutputMerger().write_filtered_source_items(
        source_items,
        [],
        [],
        (target_path, "plain"),
    )

    assert target_path.read_text(encoding="utf-8") == ""


def test_strict_psl_miss_adblock_rule_is_not_reemitted(tmp_path: Path) -> None:
    """Do not preserve an AdBlock rule whose concrete host misses the PSL."""
    source_items = _source_item_handoff(
        ["||example.invalid^\n"], file_format="adblock"
    )
    target_path = tmp_path / "filtered" / "invalid-adblock-target.txt"

    AggregateOutputMerger().write_filtered_source_items(
        source_items,
        [],
        [],
        (target_path, "adblock"),
    )

    assert source_items.index_payload["valid_source_items_by_registrable_domain"] == {}
    assert source_items.index_payload[
        "valid_source_items_without_extractable_registrable_domain"
    ] == []
    association = source_items.item_records[0]["target_associations"][0]
    assert association["error_reason"] == "no_strict_public_suffix_match"
    assert source_items.diagnostic_records[0]["reason"] == (
        "no_strict_public_suffix_match"
    )
    assert target_path.read_text(encoding="utf-8") == ""


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

    AggregateOutputMerger().write_filtered_source_items(
        _source_item_handoff(
            source_content.splitlines(keepends=True), file_format="adblock"
        ),
        ["example.com"],
        [],
        (target_path, "adblock"),
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

    AggregateOutputMerger().write_filtered_source_items(
        _source_item_handoff(
            ["0.0.0.0 bad.example.com good.example.org\n"],
            file_format="hosts",
        ),
        ["example.com"],
        [],
        (target_path, "hosts"),
    )

    assert target_path.read_text(encoding="utf-8") == "0.0.0.0 good.example.org\n"


def test_hosts_line_exclusion_removes_only_excluded_target_association(
    tmp_path: Path,
) -> None:
    """Keep eligible aliases from a hosts line with one excluded target."""
    source_items = _source_item_handoff(
        ["0.0.0.0 blocked.example.com good.example.org\n"],
        file_format="hosts",
        excluded_hosts={"blocked.example.com"},
    )
    target_path = tmp_path / "partially-excluded-hosts.txt"

    AggregateOutputMerger().write_filtered_source_items(
        source_items,
        [],
        [],
        (target_path, "hosts"),
    )

    associations = source_items.item_records[0]["target_associations"]
    assert [(item["host"], item["excluded_from_sources"]) for item in associations] == [
        ("blocked.example.com", True),
        ("good.example.org", False),
    ]
    assert source_items.index_payload["valid_source_items_by_registrable_domain"] == {
        "example.org": [
            {
                "item_id": source_items.item_records[0]["item_id"],
                "association_id": associations[1]["association_id"],
            }
        ]
    }
    assert target_path.read_text(encoding="utf-8") == (
        "0.0.0.0 good.example.org\n"
    )


def test_hosts_line_separates_excluded_invalid_and_eligible_targets(
    tmp_path: Path,
) -> None:
    """Filter each multi-target association using its own exclusion and PSL result."""
    source_items = _source_item_handoff(
        ["0.0.0.0 blocked.example.com bad.invalid good.example.org\n"],
        file_format="hosts",
        excluded_hosts={"blocked.example.com"},
    )
    target_path = tmp_path / "partially-valid-hosts.txt"

    AggregateOutputMerger().write_filtered_source_items(
        source_items,
        [],
        [],
        (target_path, "hosts"),
    )

    associations = source_items.item_records[0]["target_associations"]
    assert [
        (
            association["host"],
            association["excluded_from_sources"],
            association["error_reason"],
        )
        for association in associations
    ] == [
        ("blocked.example.com", True, None),
        ("bad.invalid", False, "no_strict_public_suffix_match"),
        ("good.example.org", False, None),
    ]
    assert source_items.index_payload[
        "valid_source_items_by_registrable_domain"
    ] == {
        "example.org": [
            {
                "item_id": source_items.item_records[0]["item_id"],
                "association_id": associations[2]["association_id"],
            }
        ]
    }
    assert source_items.index_payload[
        "valid_source_items_without_extractable_registrable_domain"
    ] == []
    assert target_path.read_text(encoding="utf-8") == (
        "0.0.0.0 good.example.org\n"
    )


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
        excluded_source_hosts={"source.example.com"},
    )

    contents, index, manually_added_domains = (
        PreparedBatchWriter().prepare_source_archive(prepared_inputs)
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
        "example.com": (SourceLineReference(0, 1),),
        "example.net": (SourceLineReference(0, 2),),
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
    parsed_source_file = DomainListParser().parse_source_file(
        source_job.lines,
        source_name=source_job.input_label,
        forced_format="adblock",
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
        PreparedBatchWriter().prepare_source_archive(prepared_inputs)
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

    AggregateOutputMerger().write_filtered_source_items(
        _source_item_handoff([], file_format="plain"),
        [],
        [
            ManuallyAddedDomain(
                host="manual.example.net",
                registrable_domain="example.net",
            )
        ],
        (target_path, output_format),
    )

    assert target_path.read_text(encoding="utf-8") == expected


def test_aggregate_omits_unactionable_manual_additions(tmp_path: Path) -> None:
    """Filter separately handed-off manual hosts by their registrable domain."""
    target_path = tmp_path / "filtered" / "manual.txt"

    AggregateOutputMerger().write_filtered_source_items(
        _source_item_handoff([], file_format="plain"),
        ["example.net"],
        [
            ManuallyAddedDomain(
                host="manual.example.net",
                registrable_domain="example.net",
            )
        ],
        (target_path, "plain"),
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


def test_worker_writer_writes_unactionable_registrable_domain(tmp_path: Path) -> None:
    """Write the rendered registrable domain to its configured worker TXT path."""
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
            route="unactionable",
            route_code=RouteCode.DELEGATION_TO_UNACTIONABLE_NS_NXDOMAIN_SOA_ABSENT,
            row={
                "host": "ads.example.com",
                "registrable_domain": "example.com",
            },
        )
    )

    writer.write()

    unactionable_path = (
        output_directory
        / "unactionable-registrable-domains"
        / "block.txt"
    )
    assert unactionable_path.read_text(encoding="utf-8") == "example.com\n"


def test_prepare_aggregate_manifest_persists_manual_additions_and_exclusions(
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
    parsed_source_file = DomainListParser().parse_source_file(
        source_job.lines,
        source_name=source_job.input_label,
        forced_format="adblock",
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
        excluded_source_hosts={"source.example.com"},
        parsed_source_files={source_job.source_id: parsed_source_file},
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
    assert persisted_manifest.excluded_source_hosts == ["source.example.com"]


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
    parsed_source_file = DomainListParser().parse_source_file(
        source_job.lines,
        source_name=source_job.input_label,
        forced_format=source_config["input"]["format"],
    )
    prepared_inputs = PreparedInputSet(
        config=config,
        source_jobs_by_id={source_job.source_id: source_job},
        parsed_source_entry_count=1,
        entries_by_source={},
        manual_routing_by_host={},
        root_plans={},
        preparation_outputs=PreparedOutputRows(review_rows=[], terminal_rows=[]),
        parsed_source_files={source_job.source_id: parsed_source_file},
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
    assert any("source-line-index.csv" in path for path in committed_paths)
    assert any("source-formats.csv" in path for path in committed_paths)
    workflow_paths = PathLayout(tmp_path).workflow_state
    source_contents = [
        workflow_paths.batch_source_input_path(
            batch_id="batch", source_ordinal=source_ordinal
        ).read_text(encoding="utf-8")
        for source_ordinal in range(len(batch.source_line_index.source_formats))
    ]
    source_line_index = load_source_line_index(
        workflow_paths.batch_source_line_index_path(batch_id="batch"),
        workflow_paths.batch_source_formats_path(batch_id="batch"),
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
    assert dict(root_counts.items()) == {
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
