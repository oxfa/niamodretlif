"""Pure classification, routing, and row-shaping helpers."""

from __future__ import annotations

import json
from typing import Any, TypedDict

from domain_pipeline.classifications import (
    CLASSIFICATION_DNS_DELEGATION_EXISTS,
    CLASSIFICATION_DNS_DELEGATION_NODATA,
    CLASSIFICATION_DNS_DELEGATION_NO_NAMESERVERS,
    CLASSIFICATION_DNS_DELEGATION_NXDOMAIN,
    CLASSIFICATION_DNS_DELEGATION_SERVFAIL,
    CLASSIFICATION_DNS_DELEGATION_TIMEOUT,
    CLASSIFICATION_DNS_HOST_NODATA,
    CLASSIFICATION_DNS_HOST_NXDOMAIN,
    CLASSIFICATION_DNS_LOOKUP_SERVFAIL,
    CLASSIFICATION_DNS_LOOKUP_TIMEOUT,
    CLASSIFICATION_DNS_RESOLVED_WITHOUT_IP_ADDRESSES,
    CLASSIFICATION_DNS_RESOLVES,
    CLASSIFICATION_GEO_LOOKUP_FAILED,
    CLASSIFICATION_GEO_POLICY_ACCEPTED,
    CLASSIFICATION_GEO_POLICY_REJECTED,
    CLASSIFICATION_GEO_REGION_NAME_UNAVAILABLE,
    CLASSIFICATION_HOST_RESOLUTION_SKIPPED,
    CLASSIFICATION_INPUT_PUBLIC_SUFFIX,
    CLASSIFICATION_MANUAL_FILTER_OUT,
    CLASSIFICATION_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
    CLASSIFICATION_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
    DELEGATION_REVIEW_CLASSIFICATIONS,
    DNS_REVIEW_CLASSIFICATIONS,
    GEO_REVIEW_CLASSIFICATIONS,
    HOST_RESOLUTION_REVIEW_CLASSIFICATIONS,
    REVIEW_CLASSIFICATION_DNS_DELEGATION_FILTERED_OUT,
    REVIEW_CLASSIFICATION_DNS_HOST_RESOLUTION_FILTERED_OUT,
    REVIEW_CLASSIFICATION_GEO_FILTERED_OUT,
    REVIEW_CLASSIFICATION_INPUT_PUBLIC_SUFFIX,
    REVIEW_CLASSIFICATION_MANUAL_FILTERED_OUT,
    REVIEW_CLASSIFICATION_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
    ROUTE_UNACTIONABLE_CLASSIFICATIONS,
)
from ..checking import (
    DelegationResult,
    GeoPolicyDecision,
    HostResolutionResult,
    IPGeoResult,
)
from ..io.parser import ParsedDomainEntry
from ..shared import SourceJob
from .contracts import ResultRoute

REVIEW_OUTPUT_COLUMNS = (
    "input_name",
    "host",
    "registrable_domain",
    "classification",
    "classification_reason",
    "delegation_status",
    "delegation_reason",
    "host_resolution_status",
    "host_resolution_reason",
    "geo_status",
    "geo_reason",
    "geo_policy_status",
    "geo_policy_reason",
    "geo_provider",
    "source_id",
    "source_input_label",
    "source_ids",
    "source_input_labels",
)


class ReviewOutputRow(TypedDict):
    """Typed projection used by the review CSV output."""

    input_name: str
    host: str
    registrable_domain: str
    classification: str
    classification_reason: str
    delegation_status: str
    delegation_reason: str
    host_resolution_status: str
    host_resolution_reason: str
    geo_status: str
    geo_reason: str
    geo_policy_status: str
    geo_policy_reason: str
    geo_provider: str
    source_id: str
    source_input_label: str
    source_ids: str
    source_input_labels: str


ROUTE_FILTERED = "filtered"
ROUTE_REVIEW = "review"
ROUTE_UNACTIONABLE = "unactionable"


def classify_delegation(result: DelegationResult) -> str:
    """Return the pipeline classification for one delegation result."""
    if result.status == "exists":
        return CLASSIFICATION_DNS_DELEGATION_EXISTS
    if result.status == "nxdomain":
        return CLASSIFICATION_DNS_DELEGATION_NXDOMAIN
    if result.status == "nodata":
        return CLASSIFICATION_DNS_DELEGATION_NODATA
    if result.status == "no_nameservers":
        return CLASSIFICATION_DNS_DELEGATION_NO_NAMESERVERS
    if result.status == "timeout":
        return CLASSIFICATION_DNS_DELEGATION_TIMEOUT
    return CLASSIFICATION_DNS_DELEGATION_SERVFAIL


def classify_host_resolution(result: HostResolutionResult) -> str:
    """Return the pipeline classification for one host-resolution result."""
    if result.status == "resolved":
        return CLASSIFICATION_DNS_RESOLVES
    if result.status == "nxdomain":
        return CLASSIFICATION_DNS_HOST_NXDOMAIN
    if result.status == "nodata":
        return CLASSIFICATION_DNS_HOST_NODATA
    if result.status == "timeout":
        return CLASSIFICATION_DNS_LOOKUP_TIMEOUT
    if result.status == "servfail":
        return CLASSIFICATION_DNS_LOOKUP_SERVFAIL
    return CLASSIFICATION_DNS_RESOLVED_WITHOUT_IP_ADDRESSES


def route_for_classification(classification: str) -> ResultRoute:
    """Return the terminal route for one classification."""
    if classification in ROUTE_UNACTIONABLE_CLASSIFICATIONS:
        return ROUTE_UNACTIONABLE
    if (
        classification in DNS_REVIEW_CLASSIFICATIONS
        or classification in GEO_REVIEW_CLASSIFICATIONS
    ):
        return ROUTE_REVIEW
    if classification in {
        CLASSIFICATION_INPUT_PUBLIC_SUFFIX,
        CLASSIFICATION_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
        CLASSIFICATION_MANUAL_FILTER_OUT,
        CLASSIFICATION_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
    }:
        return ROUTE_REVIEW
    return ROUTE_FILTERED


def public_review_classification(row: dict[str, Any]) -> str:
    """Return the public review classification for one terminal row."""
    classification = str(row.get("classification", ""))
    if classification == CLASSIFICATION_INPUT_PUBLIC_SUFFIX:
        return REVIEW_CLASSIFICATION_INPUT_PUBLIC_SUFFIX
    if classification == CLASSIFICATION_MANUAL_FILTER_PASS_NOT_IN_SOURCES:
        return REVIEW_CLASSIFICATION_MANUAL_FILTER_PASS_NOT_IN_SOURCES
    if classification in {
        CLASSIFICATION_MANUAL_FILTER_OUT,
        CLASSIFICATION_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
    }:
        return REVIEW_CLASSIFICATION_MANUAL_FILTERED_OUT
    if classification in DELEGATION_REVIEW_CLASSIFICATIONS:
        return REVIEW_CLASSIFICATION_DNS_DELEGATION_FILTERED_OUT
    if classification in HOST_RESOLUTION_REVIEW_CLASSIFICATIONS:
        return REVIEW_CLASSIFICATION_DNS_HOST_RESOLUTION_FILTERED_OUT
    if classification in GEO_REVIEW_CLASSIFICATIONS:
        return REVIEW_CLASSIFICATION_GEO_FILTERED_OUT
    return classification


def review_reason_for_row(row: dict[str, Any]) -> str:
    """Return a user-facing reason for why one row landed in review output."""
    classification = str(row.get("classification", ""))
    reason_by_classification = {
        CLASSIFICATION_INPUT_PUBLIC_SUFFIX: (
            "input is a public suffix rather than a registrable host"
        ),
        CLASSIFICATION_MANUAL_FILTER_PASS_NOT_IN_SOURCES: (
            "manual_filter_pass entry was not present in any configured source"
        ),
        CLASSIFICATION_MANUAL_FILTER_OUT: (
            "host was explicitly sent to review by manual_filter_out"
        ),
        CLASSIFICATION_MANUAL_FILTER_OUT_NOT_IN_SOURCES: (
            "manual_filter_out entry was not present in any configured source"
        ),
        CLASSIFICATION_DNS_DELEGATION_TIMEOUT: (
            "NS delegation lookup timed out after retries"
        ),
        CLASSIFICATION_DNS_DELEGATION_SERVFAIL: (
            "NS delegation lookup returned SERVFAIL after retries"
        ),
        CLASSIFICATION_DNS_HOST_NXDOMAIN: "host resolution returned NXDOMAIN",
        CLASSIFICATION_DNS_HOST_NODATA: "host resolution returned NODATA",
        CLASSIFICATION_DNS_LOOKUP_TIMEOUT: "host resolution timed out after retries",
        CLASSIFICATION_DNS_LOOKUP_SERVFAIL: "host resolution returned SERVFAIL after retries",
        CLASSIFICATION_DNS_RESOLVED_WITHOUT_IP_ADDRESSES: (
            "host resolution produced no usable IP addresses"
        ),
        CLASSIFICATION_GEO_LOOKUP_FAILED: "geo lookup did not produce usable data",
        CLASSIFICATION_GEO_REGION_NAME_UNAVAILABLE: (
            "geo policy required a region name unavailable from the provider"
        ),
        CLASSIFICATION_GEO_POLICY_REJECTED: "geo policy rejected the resolved IP set",
    }
    return reason_by_classification.get(classification, classification)


def _json_list(values: list[str] | tuple[str, ...]) -> str:
    return json.dumps(list(values), ensure_ascii=True, sort_keys=True)


def build_base_row(
    *,
    job: SourceJob,
    entry: ParsedDomainEntry,
    classification: str,
    delegation_result: DelegationResult | None = None,
    host_resolution_result: HostResolutionResult | None = None,
    dns_result: HostResolutionResult | None = None,
    geo_results: list[IPGeoResult] | None = None,
    geo_policy: GeoPolicyDecision | None = None,
    source_id_override: str | None = None,
    source_input_label_override: str | None = None,
    source_ids: tuple[str, ...] = (),
    source_input_labels: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Build the raw/terminal row shared by runtime and preparation.

    ``dns_result`` is accepted as a legacy keyword for the optional host-resolution
    result. Row fields use ``host_resolution_*`` for the stage-specific public
    contract; ``dns_status`` remains as a compatibility audit field.
    """
    if host_resolution_result is None and dns_result is not None:
        host_resolution_result = dns_result
    resolved_ips = (
        host_resolution_result.resolved_ips
        if host_resolution_result is not None
        else []
    )
    usable_geo_results = [result for result in geo_results or [] if result.usable]
    row: dict[str, Any] = {
        "input_name": entry.input_name or entry.host,
        "host": entry.host,
        "registrable_domain": entry.registrable_domain,
        "public_suffix": entry.public_suffix,
        "is_public_suffix_input": entry.is_public_suffix_input,
        "input_kind": entry.input_kind,
        "apex_scope": entry.apex_scope,
        "source_format": entry.source_format,
        "classification": classification,
        "classification_reason": review_reason_for_row(
            {"classification": classification}
        ),
        "delegation_status": (
            delegation_result.status if delegation_result is not None else "skipped"
        ),
        "delegation_reason": (
            delegation_result.status if delegation_result is not None else "skipped"
        ),
        "delegation_nameservers": (
            list(delegation_result.nameservers) if delegation_result is not None else []
        ),
        "host_resolution_status": (
            host_resolution_result.status
            if host_resolution_result is not None
            else "skipped"
        ),
        "host_resolution_reason": (
            host_resolution_result.status
            if host_resolution_result is not None
            else "skipped"
        ),
        "dns_status": (
            host_resolution_result.status
            if host_resolution_result is not None
            else "skipped"
        ),
        "canonical_name": (
            host_resolution_result.canonical_name
            if host_resolution_result is not None
            else ""
        ),
        "resolved_ips": resolved_ips,
        "geo_status": geo_policy.status if geo_policy is not None else "skipped",
        "geo_reason": geo_policy.reason if geo_policy is not None else "skipped",
        "geo_policy_status": geo_policy.status if geo_policy is not None else "skipped",
        "geo_policy_reason": geo_policy.reason if geo_policy is not None else "skipped",
        "geo_provider": usable_geo_results[0].provider if usable_geo_results else "",
        "geo_countries": sorted(
            {
                result.country_code
                for result in usable_geo_results
                if result.country_code
            }
        ),
        "geo_region_codes": sorted(
            {result.region_code for result in usable_geo_results if result.region_code}
        ),
        "geo_region_names": sorted(
            {result.region_name for result in usable_geo_results if result.region_name}
        ),
        "source_id": source_id_override or job.source_id,
        "source_input_label": source_input_label_override or job.input_label,
        "source_ids": list(source_ids or (job.source_id,)),
        "source_input_labels": list(source_input_labels or (job.input_label,)),
    }
    row["classification_reason"] = review_reason_for_row(row)
    return row


def build_review_output_row(row: dict[str, Any]) -> ReviewOutputRow:
    """Project one raw terminal row into the public review CSV schema."""
    projected = {
        "input_name": str(row.get("input_name", "")),
        "host": str(row.get("host", "")),
        "registrable_domain": str(row.get("registrable_domain", "")),
        "classification": public_review_classification(row),
        "classification_reason": review_reason_for_row(row),
        "delegation_status": str(row.get("delegation_status", "")),
        "delegation_reason": str(row.get("delegation_reason", "")),
        "host_resolution_status": str(row.get("host_resolution_status", "")),
        "host_resolution_reason": str(row.get("host_resolution_reason", "")),
        "geo_status": str(row.get("geo_status", "")),
        "geo_reason": str(row.get("geo_reason", "")),
        "geo_policy_status": str(row.get("geo_policy_status", "")),
        "geo_policy_reason": str(row.get("geo_policy_reason", "")),
        "geo_provider": str(row.get("geo_provider", "")),
        "source_id": str(row.get("source_id", "")),
        "source_input_label": str(row.get("source_input_label", "")),
        "source_ids": _json_list(
            tuple(str(value) for value in row.get("source_ids", []))
        ),
        "source_input_labels": _json_list(
            tuple(str(value) for value in row.get("source_input_labels", []))
        ),
    }
    return projected  # type: ignore[return-value]


def skipped_host_resolution_result(host: str) -> HostResolutionResult:
    """Return a skipped host-resolution placeholder for row building."""
    return HostResolutionResult(host=host)


def host_resolution_skipped_classification() -> str:
    """Return the classification used when host resolution is intentionally skipped."""
    return CLASSIFICATION_HOST_RESOLUTION_SKIPPED


def ordered_geo_provider_names(configured_provider_name: str) -> tuple[str, ...]:
    """Return deterministic geo provider order for one configured provider."""
    return (configured_provider_name,)


def geo_policy_classification(
    policy: GeoPolicyDecision | None,
    results: list[IPGeoResult],
    policy_payload: dict[str, Any],
) -> str:
    """Return the terminal geo classification for one host."""
    if policy is None:
        return CLASSIFICATION_GEO_LOOKUP_FAILED
    if policy.status == "accepted":
        return CLASSIFICATION_GEO_POLICY_ACCEPTED
    include = policy_payload.get("include", {})
    exclude = policy_payload.get("exclude", {})
    has_region_rules = bool(include.get("regions", []) or exclude.get("regions", []))
    if has_region_rules and any(
        result.usable and not result.region_name for result in results
    ):
        return CLASSIFICATION_GEO_REGION_NAME_UNAVAILABLE
    return CLASSIFICATION_GEO_POLICY_REJECTED
