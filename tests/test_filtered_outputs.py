"""Tests for configured outputs and source-preserving filtering."""

from __future__ import annotations

import csv
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from domain_pipeline.aggregate.output_merge import AggregateOutputMerger
from domain_pipeline.aggregate.readiness import validate_standalone_manual_additions
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
    PreparedInputDomainPlan,
    PreparedInputSet,
    PreparedManualRouting,
    PreparedRootPlan,
)
from domain_pipeline.prepare.prepare_to_aggregate_manifest import (
    ManuallyAddedDomain,
    load_prepare_aggregate_manifest_for_batch,
)
from domain_pipeline.prepare.delegation import (
    effective_delegation_profile,
    effective_host_resolution_profile,
    effective_ip_location_profile,
)
from domain_pipeline.prepare.source_items import SourceItemHandoff
from domain_pipeline.prepare.sources.jobs import SourceJob
from domain_pipeline.prepare.sources import parser as parser_module
from domain_pipeline.prepare.sources.parser import (
    DomainEntry,
    DomainListParser,
)
from domain_pipeline.routing.policies import (
    ROUTE_REASON_TEXT,
    DelegationRoutingPolicy,
    HostResolutionRoutingPolicy,
)
from domain_pipeline.routing.route_codes import RouteCode, TerminalRouteTransition
from domain_pipeline.worker.delegation.lookup import (
    DelegationDnsEvidence,
    DelegationResult,
    DelegationSoaEvidence,
)
from domain_pipeline.worker.output.invariants import DuplicateOutputInvariantError
from domain_pipeline.worker.output.writer import ResultOutputWriter
from domain_pipeline.worker.runtime.contracts import (
    CompletedResultEvidence,
    RegistrableDomainResult,
)
from domain_pipeline.worker.runtime.results import (
    CompletedResultRequest,
    build_completed_result,
)
from domain_pipeline.worker.worker_to_aggregate_manifest import (
    InputDomainResultRow,
    RegistrableDomainResultRow,
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
        preparation_terminal_rows=[],
        excluded_source_hosts=set(excluded_hosts or ()),
        parsed_source_files=parsed_source_files,
    )
    return SourceItemHandoff.build(
        batch_id="batch", prepared_inputs=prepared_inputs
    )


def _render_filtered_output(
    source_items: SourceItemHandoff,
    unactionable_registrable_domains: list[str],
    manually_added_domains: list[ManuallyAddedDomain],
    filtered_output: tuple[Path, str],
    *,
    input_domain_routes: dict[str, str] | None = None,
) -> None:
    """Render with explicit per-input routes, defaulting test fixtures to filtered."""
    if input_domain_routes is None:
        routes = {
            association["host"]: "filtered"
            for item in source_items.item_records
            for association in item["target_associations"]
            if association["registrable_domain"] not in unactionable_registrable_domains
        }
        routes.update(
            {item.host: "filtered" for item in manually_added_domains
             if item.registrable_domain not in unactionable_registrable_domains}
        )
    else:
        routes = input_domain_routes
    merger = AggregateOutputMerger()
    merger.write_filtered_source_items(
        merger.eligible_source_items(source_items, routes),
        merger.eligible_manual_hosts(manually_added_domains, routes),
        filtered_output,
    )


def _root_result(registrable_domain: str, disposition: str) -> dict[str, object]:
    return {
        "registrable_domain": registrable_domain,
        "disposition": disposition,
        "delegation_result": {},
    }


def _input_result(
    input_domain: str, registrable_domain: str, route: str
) -> dict[str, object]:
    return {
        "input_domain": input_domain,
        "registrable_domain": registrable_domain,
        "route": route,
        "route_code": "test_route",
        "route_reason": "test reason",
        "host_resolution_results": [],
        "ip_location_results": [],
        "ip_location_policy": None,
    }


def _worker_results(
    roots: list[dict[str, object]], inputs: list[dict[str, object]]
) -> SimpleNamespace:
    return SimpleNamespace(
        worker_id="worker-1",
        handoff_finalized=True,
        registrable_domain_results=roots,
        input_domain_results=inputs,
    )


def _typed_audit_rows() -> tuple[RegistrableDomainResultRow, InputDomainResultRow]:
    route_code = RouteCode.HOST_RESOLUTION_TO_FILTERED_SKIPPED
    root_row = RegistrableDomainResultRow.model_validate(
        {
            "registrable_domain": "example.com",
            "disposition": "actionable",
            "delegation_result": {
                "domain": "example.com",
                "dns": {
                    "ns_records_exist": True,
                    "ns_nodata": False,
                    "ns_nxdomain": False,
                    "ns_retry_exhausted": False,
                    "ns_lookup_error": False,
                },
                "soa": {
                    "soa_exists": False,
                    "soa_absent": False,
                    "soa_retry_exhausted": False,
                    "soa_source": "",
                },
                "no_nameservers": False,
                "nameservers": ["ns1.example.com"],
                "from_cache": False,
            },
        }
    )
    input_row = InputDomainResultRow.model_validate(
        {
            "input_domain": "example.com",
            "registrable_domain": "example.com",
            "route": "filtered",
            "route_code": route_code,
            "route_reason": ROUTE_REASON_TEXT[route_code],
            "host_resolution_results": [],
            "ip_location_results": [],
            "ip_location_policy": None,
        }
    )
    return root_row, input_row


def test_audit_merger_serializes_typed_worker_result_rows(tmp_path: Path) -> None:
    root_row, input_row = _typed_audit_rows()
    output_path = tmp_path / "audit" / "results.jsonl"

    AggregateOutputMerger().merge_audit_payloads(
        [("worker-1", [root_row, input_row])], output_path
    )

    actual_rows = [
        json.loads(line)
        for line in output_path.read_text(encoding="utf-8").splitlines()
    ]
    expected_rows = [
        root_row.model_dump(mode="json"),
        input_row.model_dump(mode="json"),
    ]
    assert actual_rows == sorted(
        expected_rows,
        key=lambda row: json.dumps(row, sort_keys=True, separators=(",", ":")),
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
    assert source["host_resolution"]["resolve_www_for_registrable_domain"] is True
    assert (
        config["defaults"]["host_resolution"]["resolve_www_for_registrable_domain"]
        is True
    )


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


def test_configured_adblock_unanchored_domain_is_retained_without_host_target(
    tmp_path: Path,
) -> None:
    """Keep an unanchored AdBlock pattern without inventing a request host."""
    parser = DomainListParser()
    line = "standalone.example.net\n"

    entries = list(parser.process_entries([line], forced_format="adblock"))
    source_items = _source_item_handoff([line], file_format="adblock")
    no_target_items = source_items.index_payload[
        "valid_source_items_without_extractable_registrable_domain"
    ]
    plain_path = tmp_path / "filtered" / "plain.txt"
    adblock_path = tmp_path / "filtered" / "adblock.txt"

    _render_filtered_output(source_items, [], [], (plain_path, "plain"))
    _render_filtered_output(source_items, [], [], (adblock_path, "adblock"))

    assert entries == []
    assert source_items.index_payload[
        "valid_source_items_by_input_domain"
    ] == {}
    assert no_target_items == [
        {
            "item_id": "source:1",
            "association_id": None,
            "reason": "network_filter_is_not_host_anchored",
        }
    ]
    assert plain_path.read_text(encoding="utf-8") == ""
    assert adblock_path.read_text(encoding="utf-8") == line


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

    _render_filtered_output(
        source_items,
        [],
        [],
        (target_path, "adblock"),
    )

    assert source_items.index_payload[
        "valid_source_items_by_input_domain"
    ] == {
        "ads.example.com": [
            {"item_id": "source:1", "association_id": "source:1:target:1"},
        ],
        "cdn.example.com": [
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

    _render_filtered_output(
        source_items,
        [],
        [],
        (target_path, output_format),
    )

    assert source_items.index_payload["valid_source_items_by_input_domain"].keys() == {"allowed.example.net"}
    assert target_path.read_text(encoding="utf-8") == ""


@pytest.mark.parametrize(
    ("output_format", "expected"),
    [("plain", ""), ("hosts", ""), ("adblock", "||ads.example.com/ads/*\n")],
)
def test_adblock_host_path_rule_has_worker_target_and_native_output(
    tmp_path: Path, output_format: str, expected: str
) -> None:
    source_items = _source_item_handoff(
        ["||ads.example.com/ads/*\n"], file_format="adblock"
    )
    assert source_items.item_records[0]["target_associations"][0]["host"] == "ads.example.com"
    target_path = tmp_path / "host-path.txt"
    _render_filtered_output(source_items, [], [], (target_path, output_format))
    assert target_path.read_text(encoding="utf-8") == expected


def test_standalone_addition_cannot_duplicate_source_hostname() -> None:
    items = _source_item_handoff(["||ads.example.com/path"], file_format="adblock")
    with pytest.raises(ValueError, match="already occurs in source"):
        validate_standalone_manual_additions(
            items,
            [ManuallyAddedDomain(host="ads.example.com", registrable_domain="example.com")],
            (),
        )


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

    assert source_items.index_payload["valid_source_items_by_input_domain"].keys() == {host}
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
                "0.0.0.0 plain.example.net\n",
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

    _render_filtered_output(
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

    _render_filtered_output(
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

    _render_filtered_output(
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

    _render_filtered_output(
        source_items,
        [],
        [],
        (target_path, "adblock"),
    )

    assert source_items.index_payload["valid_source_items_by_input_domain"] == {}
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
    source_items.index_payload["valid_source_items_by_input_domain"] = {
        excluded_host: [
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

    _render_filtered_output(
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

    _render_filtered_output(
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
            "valid_source_items_by_input_domain"
        ]["repeated.example.com"]
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

    _render_filtered_output(
        source_items,
        [],
        [],
        (target_path, output_format),
    )

    assert source_items.index_payload[
        "valid_source_items_without_extractable_registrable_domain"
    ][0]["reason"] == "public_suffix_only"
    assert source_items.index_payload["valid_source_items_by_input_domain"] == {}
    assert target_path.read_text(encoding="utf-8") == expected


def test_excluded_public_suffix_is_not_indexed_or_rendered(tmp_path: Path) -> None:
    """An exclusion removes a suffix-only item from its separate no-domain index."""
    source_items = _source_item_handoff(
        ["co.uk\n"], file_format="plain", excluded_hosts={"co.uk"}
    )
    target_path = tmp_path / "filtered" / "excluded-public-suffix.txt"

    _render_filtered_output(
        source_items,
        [],
        [],
        (target_path, "adblock"),
    )

    assert source_items.index_payload[
        "valid_source_items_by_input_domain"
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
        "valid_source_items_by_input_domain"
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

    _render_filtered_output(
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

    _render_filtered_output(
        source_items,
        [],
        [],
        (target_path, "adblock"),
    )

    assert source_items.index_payload["valid_source_items_by_input_domain"] == {}
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

    _render_filtered_output(
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

    _render_filtered_output(
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

    _render_filtered_output(
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
    assert source_items.index_payload["valid_source_items_by_input_domain"] == {
        "good.example.org": [
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

    _render_filtered_output(
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
        "valid_source_items_by_input_domain"
    ] == {
        "good.example.org": [
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


def test_source_corpus_counts_valid_lines_and_preserves_positions() -> None:
    items = _source_item_handoff(
        ["! comment", "||ads.example.com^", "##.banner", "not a valid rule"],
        file_format="adblock",
    )
    assert items.retained_line_count == 2
    assert [record["source_line_number"] for record in items.item_records] == [2, 3]
    assert items.valid_source_hosts == {"ads.example.com"}
    assert items.diagnostic_records[0]["source_line_number"] == 4


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

    _render_filtered_output(
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

    _render_filtered_output(
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


def test_filtered_renderer_joins_each_target_to_its_input_domain_route(
    tmp_path: Path,
) -> None:
    """Render only filtered associations while retaining route-free valid inputs."""
    source_items = _source_item_handoff(
        [
            "0.0.0.0 review.example.com filtered.example.com\n",
            "0.0.0.0 co.uk\n",
        ],
        file_format="hosts",
    )
    manual = [
        ManuallyAddedDomain(
            host="manual.example.net", registrable_domain="example.net"
        ),
        ManuallyAddedDomain(host="com", registrable_domain=None),
    ]
    target_path = tmp_path / "filtered" / "route-joined.txt"

    _render_filtered_output(
        source_items,
        [],
        manual,
        (target_path, "plain"),
        input_domain_routes={
            "review.example.com": "review",
            "filtered.example.com": "filtered",
            "manual.example.net": "filtered",
        },
    )

    assert target_path.read_text(encoding="utf-8") == (
        "filtered.example.com\nco.uk\ncom\nmanual.example.net\n"
    )


def test_aggregate_validates_global_root_and_input_domain_coverage() -> None:
    """Require one outcome per mapped root and registrable manual input."""
    merger = AggregateOutputMerger()
    source_items = _source_item_handoff(
        ["ads.example.com\n", "cdn.example.com\n", "co.uk\n"],
        file_format="plain",
    )
    manual = [
        ManuallyAddedDomain(
            host="manual.example.net", registrable_domain="example.net"
        ),
        ManuallyAddedDomain(host="com", registrable_domain=None),
    ]
    results = _worker_results(
        [
            _root_result("example.com", "actionable"),
            _root_result("example.net", "actionable"),
        ],
        [
            _input_result("ads.example.com", "example.com", "review"),
            _input_result("cdn.example.com", "example.com", "filtered"),
            _input_result("manual.example.net", "example.net", "unactionable"),
        ],
    )

    routes = merger.validate_worker_results(source_items, manual, [results])

    assert routes == {
        "ads.example.com": "review",
        "cdn.example.com": "filtered",
        "manual.example.net": "unactionable",
    }
    assert merger.unactionable_input_domains(routes) == ["manual.example.net"]


def test_aggregate_rejects_missing_input_domain_outcome() -> None:
    """Do not treat an omitted final route as a filtered association."""
    merger = AggregateOutputMerger()
    source_items = _source_item_handoff(
        ["ads.example.com\n", "cdn.example.com\n"],
        file_format="plain",
    )
    results = _worker_results(
        [_root_result("example.com", "actionable")],
        [_input_result("ads.example.com", "example.com", "filtered")],
    )

    with pytest.raises(ValueError, match="missing input-domain outcomes"):
        merger.validate_worker_results(source_items, [], [results])


@pytest.mark.parametrize(
    ("root_results", "input_results", "error"),
    [
        (
            [],
            [_input_result("ads.example.com", "example.com", "filtered")],
            "missing registrable-domain outcomes",
        ),
        (
            [_root_result("example.com", "actionable")],
            [_input_result("other.example.com", "example.com", "filtered")],
            "unexpected input-domain result",
        ),
    ],
)
def test_aggregate_rejects_incomplete_or_unexpected_global_results(
    root_results: list[dict[str, object]],
    input_results: list[dict[str, object]],
    error: str,
) -> None:
    """Reject missing root outcomes and unexpected input-domain routes."""
    merger = AggregateOutputMerger()
    source_items = _source_item_handoff(["ads.example.com\n"], file_format="plain")

    with pytest.raises(ValueError, match=error):
        merger.validate_worker_results(
            source_items,
            [],
            [_worker_results(root_results, input_results)],
        )


@pytest.mark.parametrize("duplicate_kind", ["root", "input"])
def test_aggregate_rejects_duplicate_results_across_workers(
    duplicate_kind: str,
) -> None:
    """Reject duplicated global outcomes even when each worker is finalized."""
    merger = AggregateOutputMerger()
    source_items = _source_item_handoff(["ads.example.com\n"], file_format="plain")
    root = _root_result("example.com", "actionable")
    input_row = _input_result("ads.example.com", "example.com", "filtered")
    first = _worker_results([root], [input_row])
    second = _worker_results(
        [root] if duplicate_kind == "root" else [],
        [] if duplicate_kind == "root" else [input_row],
    )

    expected_error = (
        "duplicate registrable-domain result"
        if duplicate_kind == "root"
        else "duplicate input-domain result"
    )
    with pytest.raises(ValueError, match=expected_error):
        merger.validate_worker_results(source_items, [], [first, second])


def test_aggregate_requires_terminal_root_route_fanout() -> None:
    """A review root cannot have a filtered child input-domain route."""
    merger = AggregateOutputMerger()
    source_items = _source_item_handoff(
        ["ads.example.com\n", "cdn.example.com\n"],
        file_format="plain",
    )
    results = _worker_results(
        [_root_result("example.com", "review")],
        [
            _input_result("ads.example.com", "example.com", "review"),
            _input_result("cdn.example.com", "example.com", "filtered"),
        ],
    )

    with pytest.raises(ValueError, match="terminal root outcome"):
        merger.validate_worker_results(source_items, [], [results])


def test_unactionable_output_uses_input_domains_under_terminal_root() -> None:
    """Publish each routed child domain instead of replacing them with the root."""
    merger = AggregateOutputMerger()
    source_items = _source_item_handoff(
        ["ads.example.com\n", "cdn.example.com\n"],
        file_format="plain",
    )
    results = _worker_results(
        [_root_result("example.com", "unactionable")],
        [
            _input_result("ads.example.com", "example.com", "unactionable"),
            _input_result("cdn.example.com", "example.com", "unactionable"),
        ],
    )

    routes = merger.validate_worker_results(source_items, [], [results])

    assert merger.unactionable_input_domains(routes) == [
        "ads.example.com",
        "cdn.example.com",
    ]


def test_aggregate_review_projection_drops_prepare_source_details(
    tmp_path: Path,
) -> None:
    """Keep the published review rows source-blind after prepare merging."""
    target_path = tmp_path / "review.csv"
    AggregateOutputMerger().merge_review_payloads(
        [
            (
                "prepare",
                [
                    {
                        "host": "manual.example.net",
                        "registrable_domain": "example.net",
                        "route_code": "manual_input_review",
                        "review_reason": "manual input needs review",
                        "source_id": "source-secret",
                        "source_input_label": "private-feed.txt",
                        "source_url": "https://example.invalid/private-feed",
                        "original_text": "private source line",
                        "source_line_number": "3",
                    }
                ],
            )
        ],
        target_path,
    )

    with target_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames is not None
        assert not {
            "source_id",
            "source_input_label",
            "source_url",
            "original_text",
            "source_line_number",
        } & set(reader.fieldnames)
        rows = list(reader)
    assert rows[0]["host"] == "manual.example.net"


def test_duplicate_review_rows_across_worker_and_prepare_are_rejected(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "review.csv"
    destination.write_bytes(b"previous review\n")
    review = {"host": "ads.example.com", "registrable_domain": "example.com"}
    prepare_review = {**review, "source_id": "private-source"}
    with pytest.raises(DuplicateOutputInvariantError) as raised:
        AggregateOutputMerger().merge_review_payloads(
            [("worker-1", [review]), ("prepare", [prepare_review])], destination
        )
    assert raised.value.output_kind == "aggregate_review_row"
    assert raised.value.duplicate_key == review["host"]
    assert destination.read_bytes() == b"previous review\n"


def test_worker_writer_does_not_create_filtered_output(tmp_path: Path) -> None:
    """Keep input-domain results source-blind without a worker filtered file."""
    output_directory = tmp_path / "worker-output"
    domain_results_path = tmp_path / "worker-domain-results.jsonl"
    writer = ResultOutputWriter(
        output_spec={
            "domain_results": str(domain_results_path),
            "review": str(output_directory / "review-results-by-input-domain" / "worker.csv"),
            "unactionable": str(output_directory / "unactionable-input-domains" / "worker.txt"),
        },
        expected_input_domains_by_root={"example.com": {"ads.example.com"}},
    )
    delegation = DelegationResult(
        domain="example.com",
        dns=DelegationDnsEvidence(ns_records_exist=True),
        soa=DelegationSoaEvidence(),
        nameservers=["ns1.example.com"],
    )
    writer.add_root_result(
        RegistrableDomainResult(
            registrable_domain="example.com",
            disposition="actionable",
            delegation_result=delegation,
        )
    )
    writer.add(
        build_completed_result(
            CompletedResultRequest(
                entry=DomainEntry(
                    host="ads.example.com",
                    registrable_domain="example.com",
                ),
                route_transition=HostResolutionRoutingPolicy().skipped(),
                evidence=CompletedResultEvidence(delegation_result=delegation),
            )
        )
    )

    writer.write()

    assert not (output_directory / "filtered").exists()
    envelope = json.loads(domain_results_path.read_text(encoding="utf-8"))
    assert set(envelope) == {"registrable_domain_results", "input_domain_results"}
    assert envelope["input_domain_results"][0]["input_domain"] == "ads.example.com"
    assert "source_id" not in envelope["input_domain_results"][0]


def test_worker_writer_writes_unactionable_input_domain(tmp_path: Path) -> None:
    """Write the input-domain value for an unactionable route."""
    output_directory = tmp_path / "worker-output"
    domain_results_path = tmp_path / "worker-domain-results.jsonl"
    writer = ResultOutputWriter(
        output_spec={
            "domain_results": str(domain_results_path),
            "review": str(output_directory / "review-results-by-input-domain" / "worker.csv"),
            "unactionable": str(output_directory / "unactionable-input-domains" / "worker.txt"),
        },
        expected_input_domains_by_root={"example.com": {"ads.example.com"}},
    )
    delegation = DelegationResult(
        domain="example.com",
        dns=DelegationDnsEvidence(),
        soa=DelegationSoaEvidence(),
        no_nameservers=True,
    )
    transition = DelegationRoutingPolicy().for_result(delegation)
    assert isinstance(transition, TerminalRouteTransition)
    writer.add_root_result(
        RegistrableDomainResult(
            registrable_domain="example.com",
            disposition="unactionable",
            delegation_result=delegation,
        )
    )
    writer.add(
        build_completed_result(
            CompletedResultRequest(
                entry=DomainEntry(
                    host="ads.example.com",
                    registrable_domain="example.com",
                ),
                route_transition=transition,
                evidence=CompletedResultEvidence(delegation_result=delegation),
            )
        )
    )

    writer.write()

    unactionable_path = output_directory / "unactionable-input-domains" / "worker.txt"
    assert unactionable_path.read_text(encoding="utf-8") == "ads.example.com\n"


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
    manual_entry = DomainEntry(host="co.uk", registrable_domain=None)
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
        entries_by_source={"block": []},
        manual_routing_by_host={},
        root_plans={},
        preparation_terminal_rows=[],
        manually_added_entries={manual_entry.host: manual_entry},
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

    assert batch.source_item_handoff.item_records[0]["original_text"] == "||source.example.com^"
    assert persisted_manifest.manually_added_domains == [
        ManuallyAddedDomain(
            host="co.uk",
            registrable_domain=None,
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
        preparation_terminal_rows=[],
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
    names = {Path(path).name for path in committed_paths}
    assert {"source-items.jsonl", "source-item-index.json", "source-item-diagnostics.jsonl"} <= names
    assert not {"source-line-index.csv", "source-formats.csv", "preparation-review.csv"} & names
    assert all("source_inputs" not in Path(path).parts for path in committed_paths)


def test_worker_assignment_balances_unique_input_domain_counts() -> None:
    """Assign large roots first, weighting each root by its unique input domains."""
    input_counts = {
        "example.com": 5,
        "example.net": 4,
        "example.org": 3,
        "example.co.uk": 1,
    }
    root_plans = {
        root: PreparedRootPlan(
            registrable_domain=root,
            delegation_profile={"query": "shared"},
            input_domains={
                f"host-{index}.{root}": PreparedInputDomainPlan(
                    host=f"host-{index}.{root}",
                    manual_routing=PreparedManualRouting(),
                )
                for index in range(count)
            },
        )
        for root, count in input_counts.items()
    }
    planning_inputs = PreparedBatchPlanningInputs(
        root_plans=root_plans,
    )

    worker_root_plans, domain_counts = WorkerAssignmentPlanner().assign(
        planning_inputs=planning_inputs,
        worker_ids=["worker-1", "worker-2"],
    )

    assert {
        worker_id: set(plans) for worker_id, plans in worker_root_plans.items()
    } == {
        "worker-1": {"example.com", "example.co.uk"},
        "worker-2": {"example.net", "example.org"},
    }
    assert dict(domain_counts.items()) == {
        "worker-1": 6,
        "worker-2": 7,
    }
    assert sum(
        len(plan.input_domains)
        for plans in worker_root_plans.values()
        for plan in plans.values()
    ) == sum(input_counts.values())


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
    "config_path",
    ["config/block.yaml", "config/direct.yaml"],
)
def test_additional_filtered_outputs_are_not_sent_to_worker_runtime(
    config_path: str,
) -> None:
    """Keep aggregate-only filtered output settings out of worker manifests."""
    config = load_config_without_runtime_credentials(Path(config_path))
    source_config = config["sources"][0]
    entry = DomainEntry(host="ads.example.com", registrable_domain="example.com")
    manifests = WorkerAssignmentPlanner().build_worker_manifests(
        WorkerManifestBuildRequest(
            config=config,
            batch_id="batch",
            worker_ids=["worker-1"],
            worker_root_plans={
                "worker-1": {
                    "example.com": PreparedRootPlan(
                        registrable_domain="example.com",
                        delegation_profile=effective_delegation_profile(source_config),
                        input_domains={
                            entry.host: PreparedInputDomainPlan(
                                host=entry.host,
                                manual_routing=PreparedManualRouting(),
                                host_resolution_profile=(
                                    effective_host_resolution_profile(source_config)
                                    if source_config["host_resolution"]["enabled"]
                                    else None
                                ),
                                ip_location_profile=(
                                    effective_ip_location_profile(source_config)
                                    if source_config["host_resolution"]["enabled"]
                                    and source_config["ip_location"]["enabled"]
                                    else None
                                ),
                            )
                        },
                    )
                }
            },
        )
    )
    runtime_spec = manifests[0].manifest.runtime_spec
    runtime_payload = runtime_spec.model_dump(mode="json")

    assert set(runtime_payload) == {
        "config_name",
        "cache",
        "runtime",
        "output_spec",
        "debug_log_path",
    }
    assert set(runtime_spec.output_spec.model_dump()) == {
        "result_root",
        "unactionable",
        "review",
        "domain_results",
        "cache",
    }
    assert "filtered" not in runtime_payload
    assert "sources" not in runtime_payload


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


@pytest.mark.parametrize(
    ("lines", "file_format", "excluded", "expected_hosts"),
    [
        (["0.0.0.0 One.Example.com Two.Example.net # comment"], "hosts",
         {"two.example.net"}, ["one.example.com"]),
        (["server=/one.example.com/.two.example.net/bad.invalid/#"], "dnsmasq",
         {"one.example.com"}, ["two.example.net"]),
        (["DOMAIN,One.Example.com", "DOMAIN-SUFFIX,Two.Example.net"], "auto",
         set(), ["one.example.com", "two.example.net"]),
        (["One.Example.com", ".Two.Example.net"], "auto",
         set(), ["one.example.com", "two.example.net"]),
    ],
)
@pytest.mark.parametrize(
    ("output_format", "template"),
    [("plain", "{}"), ("hosts", "0.0.0.0 {}"), ("adblock", "||{}^")],
)
def test_non_adblock_projection_matrix(
    tmp_path: Path, lines: list[str], file_format: str, excluded: set[str],
    expected_hosts: list[str], output_format: str, template: str,
) -> None:
    items = _source_item_handoff(lines, file_format=file_format, excluded_hosts=excluded)
    path = tmp_path / "filtered.txt"
    _render_filtered_output(items, [], [], (path, output_format))
    assert path.read_text(encoding="utf-8").splitlines() == [
        template.format(host) for host in expected_hosts
    ]


@pytest.mark.parametrize(
    ("output_format", "expected"),
    [
        ("plain", "ads.example.com\n"),
        ("hosts", "0.0.0.0 ads.example.com\n"),
        ("adblock", "||ads.example.com/path\n  ||ADS.Example.COM^  \n"),
    ],
)
def test_simple_adblock_occurrence_projects_normalized_host_and_replays_raw_text(
    tmp_path: Path, output_format: str, expected: str,
) -> None:
    items = _source_item_handoff(
        ["||ads.example.com/path", "  ||ADS.Example.COM^  "], file_format="adblock"
    )
    path = tmp_path / "filtered.txt"
    _render_filtered_output(items, [], [], (path, output_format))
    assert path.read_text(encoding="utf-8") == expected
