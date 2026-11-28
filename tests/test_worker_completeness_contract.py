"""Worker-local exact-coverage checks for root and input-domain results."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from domain_pipeline.handoff_io import write_csv
from domain_pipeline.paths import PathLayout
from domain_pipeline.routing.policies import ROUTE_REASON_TEXT
from domain_pipeline.routing.route_codes import RouteCode
from domain_pipeline.worker.delegation.lookup import (
    DelegationDnsEvidence,
    DelegationResult,
)
from domain_pipeline.worker.host_resolution.lookup import (
    HostResolutionAddressEvidence,
    HostResolutionDnsEvidence,
    HostResolutionResult,
)
from domain_pipeline.worker.ip_location.providers import (
    IPLocationResult,
    LocationPolicyDecision,
)
from domain_pipeline.worker.output.manager import write_projected_review_rows
from domain_pipeline.worker.output.rows import REVIEW_OUTPUT_COLUMNS
from domain_pipeline.worker.worker_to_aggregate_manifest import (
    WorkerAggregateManifest,
    WorkerDomainResultsEnvelope,
    load_worker_aggregate_manifest_for_worker,
    project_worker_review_rows,
    validate_worker_domain_results,
    write_worker_aggregate_manifest,
)


def _root_row(registrable_domain: str = "example.com") -> dict[str, object]:
    return {
        "registrable_domain": registrable_domain,
        "disposition": "actionable",
        "delegation_result": {
            "domain": registrable_domain,
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


def _input_row(
    input_domain: str = "example.com",
    registrable_domain: str = "example.com",
) -> dict[str, object]:
    return {
        "input_domain": input_domain,
        "registrable_domain": registrable_domain,
        "route": "filtered",
        "route_code": "host_resolution_to_filtered_skipped",
        "route_reason": "host resolution was skipped",
        "host_resolution_results": [],
        "ip_location_results": [],
        "ip_location_policy": None,
    }


def _envelope(
    *,
    roots: list[dict[str, object]] | None = None,
    inputs: list[dict[str, object]] | None = None,
) -> WorkerDomainResultsEnvelope:
    return WorkerDomainResultsEnvelope.model_validate(
        {
            "registrable_domain_results": roots
            if roots is not None
            else [_root_row()],
            "input_domain_results": inputs
            if inputs is not None
            else [_input_row()],
        }
    )


def test_rejects_missing_root_result() -> None:
    with pytest.raises(
        ValueError,
        match="worker registrable-domain results do not match assigned roots",
    ):
        validate_worker_domain_results(
            expected_input_domains_by_root={
                "example.com": {"example.com"},
                "example.org": {"example.org"},
            },
            envelope=_envelope(),
        )


def test_rejects_duplicate_root_result() -> None:
    with pytest.raises(
        ValueError, match="worker registrable-domain results contain duplicates"
    ):
        validate_worker_domain_results(
            expected_input_domains_by_root={"example.com": {"example.com"}},
            envelope=_envelope(roots=[_root_row(), _root_row()]),
        )


def test_rejects_unexpected_root_result() -> None:
    with pytest.raises(
        ValueError,
        match="worker registrable-domain results do not match assigned roots",
    ):
        validate_worker_domain_results(
            expected_input_domains_by_root={"example.com": {"example.com"}},
            envelope=_envelope(roots=[_root_row(), _root_row("example.org")]),
        )


def test_rejects_missing_input_domain_result() -> None:
    with pytest.raises(
        ValueError, match="worker input-domain results do not match assigned domains"
    ):
        validate_worker_domain_results(
            expected_input_domains_by_root={
                "example.com": {"example.com", "ads.example.com"}
            },
            envelope=_envelope(),
        )


def test_rejects_duplicate_input_domain_result() -> None:
    with pytest.raises(
        ValueError, match="worker input-domain results contain duplicates"
    ):
        validate_worker_domain_results(
            expected_input_domains_by_root={"example.com": {"example.com"}},
            envelope=_envelope(inputs=[_input_row(), _input_row()]),
        )


def test_rejects_unexpected_input_domain_result() -> None:
    with pytest.raises(
        ValueError, match="worker input-domain results do not match assigned domains"
    ):
        validate_worker_domain_results(
            expected_input_domains_by_root={"example.com": {"example.com"}},
            envelope=_envelope(
                inputs=[_input_row(), _input_row("ads.example.com")]
            ),
        )


def _write_finalized_results(
    state_root: Path,
    *,
    roots: list[dict[str, object]],
    inputs: list[dict[str, object]],
    review_rows: list[dict[str, str]] | None = None,
) -> None:
    identity = {"batch_id": "batch-123-attempt-1", "worker_id": "worker-1"}
    write_worker_aggregate_manifest(
        WorkerAggregateManifest.empty(**identity, finalized=True),
        state_root=state_root,
    )
    paths = PathLayout(state_root).workflow_state
    result_path = paths.worker_handoff_domain_results_path(**identity)
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(
        json.dumps(
            {"registrable_domain_results": roots, "input_domain_results": inputs}
        )
        + "\n",
        encoding="utf-8",
    )
    paths.worker_handoff_unactionable_path(**identity).write_text("", encoding="utf-8")
    write_csv(
        paths.worker_handoff_review_path(**identity),
        tuple(REVIEW_OUTPUT_COLUMNS),
        review_rows or [],
    )


def _load_finalized_results(state_root: Path) -> WorkerAggregateManifest | None:
    return load_worker_aggregate_manifest_for_worker(
        batch_id="batch-123-attempt-1", worker_id="worker-1", state_root=state_root
    )


@pytest.mark.parametrize(
    ("roots", "inputs", "message"),
    [
        ([], [_input_row()], "has no delegation result in its worker bundle"),
        ([_root_row()], [], "has no input-domain results in its worker bundle"),
    ],
    ids=["input-without-root", "root-without-input"],
)
def test_finalized_worker_rejects_split_root_and_input_results(
    tmp_path: Path,
    roots: list[dict[str, object]],
    inputs: list[dict[str, object]],
    message: str,
) -> None:
    _write_finalized_results(tmp_path, roots=roots, inputs=inputs)
    with pytest.raises(ValueError, match=message):
        _load_finalized_results(tmp_path)


_TERMINAL_ROUTE_CODE = RouteCode.DELEGATION_TO_REVIEW_NS_LOOKUP_ERROR


def _review_root(domain: str) -> dict[str, object]:
    return {
        "registrable_domain": domain,
        "disposition": "review",
        "delegation_result": asdict(
            DelegationResult(
                domain=domain, dns=DelegationDnsEvidence(ns_lookup_error=True)
            )
        ),
    }


def _review_input_row(
    host: str, root: str, route_code: RouteCode, **evidence: object
) -> dict[str, object]:
    return {
        **_input_row(host, root),
        "route": "review",
        "route_code": route_code.value,
        "route_reason": ROUTE_REASON_TEXT[route_code],
        **evidence,
    }


def _review_sidecar(host: str, root: str, route_code: RouteCode) -> dict[str, str]:
    return {
        "host": host,
        "registrable_domain": root,
        "route_code": route_code.value,
        "review_reason": "fixture reason",
    }


@pytest.mark.parametrize(
    ("route_code", "downstream_evidence", "message"),
    [
        (
            RouteCode.DELEGATION_TO_REVIEW_NS_RETRY_EXHAUSTED_SOA_ABSENT,
            {},
            "does not follow its terminal root outcome",
        ),
        (
            _TERMINAL_ROUTE_CODE,
            {
                "host_resolution_results": [
                    asdict(HostResolutionResult(host="example.com"))
                ]
            },
            "has downstream evidence after terminal delegation",
        ),
        (
            _TERMINAL_ROUTE_CODE,
            {
                "ip_location_results": [
                    asdict(IPLocationResult("192.0.2.1", "fixture", "", "", "", "ok"))
                ]
            },
            "has downstream evidence after terminal delegation",
        ),
        (
            _TERMINAL_ROUTE_CODE,
            {
                "ip_location_policy": asdict(
                    LocationPolicyDecision("rejected", "", [], [])
                )
            },
            "has downstream evidence after terminal delegation",
        ),
    ],
    ids=["wrong-review-code", "host-evidence", "ip-evidence", "ip-policy"],
)
def test_finalized_worker_requires_exact_terminal_delegation_fanout(
    tmp_path: Path,
    route_code: RouteCode,
    downstream_evidence: dict[str, object],
    message: str,
) -> None:
    host = "example.com"
    _write_finalized_results(
        tmp_path,
        roots=[_review_root(host)],
        inputs=[_review_input_row(host, host, route_code, **downstream_evidence)],
        review_rows=[_review_sidecar(host, host, route_code)],
    )
    with pytest.raises(ValueError, match=message):
        _load_finalized_results(tmp_path)


def test_finalized_worker_checks_review_sidecar_root(tmp_path: Path) -> None:
    _write_finalized_results(
        tmp_path,
        roots=[_review_root("example.com")],
        inputs=[_review_input_row("example.com", "example.com", _TERMINAL_ROUTE_CODE)],
        review_rows=[_review_sidecar("example.com", "example.net", _TERMINAL_ROUTE_CODE)],
    )
    with pytest.raises(ValueError, match="worker review row does not match"):
        _load_finalized_results(tmp_path)


def test_final_review_bytes_use_ordered_worker_evidence(tmp_path: Path) -> None:
    host_code = RouteCode.HOST_RESOLUTION_TO_REVIEW_SERVFAIL
    ip_code = RouteCode.IP_LOCATION_TO_REVIEW_LOOKUP_FAILED
    ip_host = "ip.example.com"
    host_queries = [
        HostResolutionResult(
            host="example.com",
            dns=HostResolutionDnsEvidence(a_servfail=True),
            detail="cname_loop",
        ),
        HostResolutionResult(
            host="www.example.com",
            dns=HostResolutionDnsEvidence(a_servfail=True),
            detail="cname_depth_exceeded",
        ),
    ]
    ip_query = HostResolutionResult(
        host=ip_host,
        dns=HostResolutionDnsEvidence(a_exists=True),
        addresses=HostResolutionAddressEvidence(
            ipv4_addresses=["192.0.2.1", "192.0.2.2"]
        ),
    )
    location_results = [
        IPLocationResult(
            "192.0.2.1", "first-provider", "", "", "", "request_failed", "request_failed"
        ),
        IPLocationResult(
            "192.0.2.2", "rate-limited-provider", "", "", "", "rate_limited", "rate_limited"
        ),
    ]
    _write_finalized_results(
        tmp_path,
        roots=[_root_row(), _review_root("example.net")],
        inputs=[
            _review_input_row("example.net", "example.net", _TERMINAL_ROUTE_CODE),
            _review_input_row(
                ip_host,
                "example.com",
                ip_code,
                host_resolution_results=[asdict(ip_query)],
                ip_location_results=[asdict(result) for result in location_results],
            ),
            _review_input_row(
                "example.com",
                "example.com",
                host_code,
                host_resolution_results=[asdict(result) for result in host_queries],
            ),
        ],
        review_rows=[
            _review_sidecar("example.com", "example.com", host_code),
            _review_sidecar("example.net", "example.net", _TERMINAL_ROUTE_CODE),
            _review_sidecar(ip_host, "example.com", ip_code),
        ],
    )
    manifest = _load_finalized_results(tmp_path)
    assert manifest is not None
    review_path = tmp_path / "final-review.csv"
    write_projected_review_rows(review_path, project_worker_review_rows(manifest))
    expected = (
        ",".join(f'"{column}"' for column in REVIEW_OUTPUT_COLUMNS) + "\r\n"
        '"example.com","example.com","host_resolution_to_review_servfail",'
        '"CNAME loop detected during host resolution","ns_records_exist",'
        '"ns_records_exist","servfail","CNAME loop detected during host resolution",'
        '"skipped","skipped","skipped","skipped",""\r\n'
        '"example.net","example.net","delegation_to_review_ns_lookup_error",'
        '"delegation NS lookup failed before a definitive delegation result",'
        '"ns_lookup_error","ns_lookup_error","skipped","skipped","skipped","skipped",'
        '"skipped","skipped",""\r\n'
        '"ip.example.com","example.com","ip_location_to_review_lookup_failed",'
        '"ip_location lookup failed because the ip_location provider rate limited the request",'
        '"ns_records_exist","ns_records_exist","resolved","resolved","rate_limited",'
        '"rate_limited","skipped","skipped","rate-limited-provider"\r\n'
    )
    assert review_path.read_bytes() == expected.encode("utf-8")
