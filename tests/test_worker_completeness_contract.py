"""Worker-local exact-coverage checks for root and input-domain results."""

from __future__ import annotations

import pytest

from domain_pipeline.worker.worker_to_aggregate_manifest import (
    WorkerDomainResultsEnvelope,
    validate_worker_domain_results,
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
