"""Focused coverage for source-blind worker assignment and result collections."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from domain_pipeline.prepare.sources.parser import DomainEntry
from domain_pipeline.routing.policies import HostResolutionRoutingPolicy
from domain_pipeline.worker.delegation.lookup import (
    DelegationDnsEvidence,
    DelegationResult,
    DelegationSoaEvidence,
)
from domain_pipeline.worker.runtime.contracts import (
    CompletedResultEvidence,
    RegistrableDomainResult,
)
from domain_pipeline.worker.runtime.loading import RuntimeItemLoader
from domain_pipeline.worker.runtime.results import (
    CompletedResultRequest,
    build_completed_result,
)
from domain_pipeline.worker.worker_to_aggregate_manifest import (
    WorkerDomainResultsEnvelope,
    parse_worker_domain_results_jsonl_text,
    validate_worker_domain_results,
)
from domain_pipeline.worker.output.writer import ResultOutputWriter


def _delegation_profile() -> dict[str, object]:
    return {
        "dns_query": {
            "default_resolvers": [],
            "timeout": 5.0,
            "retry_backoff_base_seconds": 1.0,
            "query_rate_limit": {},
        },
        "delegation": {
            "resolvers": None,
            "timeout": None,
            "query_rate_limit": None,
            "retry_attempts": 3,
        },
    }


def _root_row() -> dict[str, object]:
    return {
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


def _input_row(input_domain: str = "example.com") -> dict[str, object]:
    return {
        "input_domain": input_domain,
        "registrable_domain": "example.com",
        "route": "filtered",
        "route_code": "host_resolution_to_filtered_skipped",
        "route_reason": "host resolution was skipped",
        "host_resolution_results": [],
        "ip_location_results": [],
        "ip_location_policy": None,
    }


def _envelope(input_domain: str = "example.com") -> dict[str, object]:
    return {
        "registrable_domain_results": [_root_row()],
        "input_domain_results": [_input_row(input_domain)],
    }


def test_runtime_loader_builds_source_blind_root_and_domain_work() -> None:
    metadata = {
        "delegation_roots": {
            "example.com": {
                "delegation_profile": _delegation_profile(),
                "input_domains": {
                    "ads.example.com": {
                        "manual_routing": {
                            "manually_selected_for_filtered": False,
                            "manually_added": False,
                        },
                        "host_resolution_profile": {
                            "resolvers": [],
                            "timeout": 5.0,
                            "retry_backoff_base_seconds": 1.0,
                            "query_rate_limit": {},
                            "retry_attempts": 3,
                            "ecs": {},
                            "resolve_www_for_registrable_domain": True,
                        },
                    }
                },
            }
        }
    }

    work_items = RuntimeItemLoader(
        config={}, prepared_metadata=metadata
    ).delegation_work_items()

    assert len(work_items) == 1
    assert work_items[0].registrable_domain == "example.com"
    assert [item.entry.host for item in work_items[0].items] == ["ads.example.com"]
    assert not hasattr(work_items[0].items[0], "source_context")
    assert work_items[0].items[0].host_resolution_profile["resolve_www_for_registrable_domain"]


def test_result_envelope_rejects_source_attribution_fields() -> None:
    payload = _envelope()
    payload["input_domain_results"][0]["source_id"] = "source-a"  # type: ignore[index]

    with pytest.raises(ValidationError, match="extra_forbidden"):
        parse_worker_domain_results_jsonl_text(json.dumps(payload))


def test_result_validation_requires_exact_coverage_and_psl_root() -> None:
    envelope = WorkerDomainResultsEnvelope.model_validate(_envelope("ads.example.com"))

    validate_worker_domain_results(
        expected_input_domains_by_root={
            "example.com": {"ads.example.com"}
        },
        envelope=envelope,
    )

    with pytest.raises(ValueError, match="registrable root does not match"):
        validate_worker_domain_results(
            expected_input_domains_by_root={"example.com": {"example.org"}},
            envelope=WorkerDomainResultsEnvelope.model_validate(
                {
                    "registrable_domain_results": [_root_row()],
                    "input_domain_results": [_input_row("example.org")],
                }
            ),
        )


def test_result_envelope_rejects_public_suffix_validation_route() -> None:
    payload = {
        "registrable_domain_results": [_root_row()],
        "input_domain_results": [
            {
                **_input_row(),
                "route": "review",
                "route_code": "input_validation_to_review_public_suffix",
                "route_reason": "input is a public suffix rather than a registrable host",
            }
        ],
    }

    with pytest.raises(
        ValidationError,
        match="input-domain route does not match its terminal route code",
    ):
        WorkerDomainResultsEnvelope.model_validate(payload)


def test_writer_emits_only_the_two_closed_result_collections(
    tmp_path: Path,
) -> None:
    writer = ResultOutputWriter(
        output_spec={
            "unactionable": str(tmp_path / "unactionable-input-domains" / "worker.txt"),
            "review": str(tmp_path / "review-results-by-input-domain" / "worker.csv"),
            "domain_results": str(tmp_path / "domain-results.jsonl"),
        },
        expected_input_domains_by_root={"example.com": {"example.com"}},
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
                entry=DomainEntry("example.com", "example.com"),
                route_transition=HostResolutionRoutingPolicy().skipped(),
                evidence=CompletedResultEvidence(delegation_result=delegation),
            )
        )
    )

    writer.write()
    payload = parse_worker_domain_results_jsonl_text(
        (tmp_path / "domain-results.jsonl").read_text(encoding="utf-8")
    )

    assert set(payload.model_dump(mode="json")) == {
        "registrable_domain_results",
        "input_domain_results",
    }
    assert payload.input_domain_results[0].input_domain == "example.com"
