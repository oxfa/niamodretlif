"""Raw terminal row and review CSV row projection helpers."""

from __future__ import annotations

import json
from typing import Any, Protocol, TypedDict

from domain_pipeline.prepare.classifications import (
    PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_PUBLIC_SUFFIX,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
)
from domain_pipeline.worker.dns.result_codes import (
    PIPELINE_RESULT_CODE_DNS_DELEGATION_NS_NODATA_SOA_ABSENT,
    PIPELINE_RESULT_CODE_DNS_DELEGATION_NS_NODATA_SOA_SERVFAIL,
    PIPELINE_RESULT_CODE_DNS_DELEGATION_NS_NODATA_SOA_TIMEOUT,
    PIPELINE_RESULT_CODE_DNS_DELEGATION_SERVFAIL,
    PIPELINE_RESULT_CODE_DNS_DELEGATION_TIMEOUT,
    PIPELINE_RESULT_CODE_DNS_HOST_NODATA,
    PIPELINE_RESULT_CODE_DNS_HOST_NXDOMAIN,
    PIPELINE_RESULT_CODE_DNS_HOST_RESOLUTION_RESOLVED_WITHOUT_IP_ADDRESSES,
    PIPELINE_RESULT_CODE_DNS_HOST_RESOLUTION_SERVFAIL,
    PIPELINE_RESULT_CODE_DNS_HOST_RESOLUTION_TIMEOUT,
    HOST_RESOLUTION_REVIEW_PIPELINE_RESULT_CODES,
)
from domain_pipeline.worker.geo.result_codes import (
    PIPELINE_RESULT_CODE_GEO_LOOKUP_FAILED,
    PIPELINE_RESULT_CODE_GEO_POLICY_REJECTED,
    PIPELINE_RESULT_CODE_GEO_REGION_NAME_UNAVAILABLE,
    GEO_REVIEW_PIPELINE_RESULT_CODES,
)
from domain_pipeline.worker.output.review_labels import (
    REVIEW_LABEL_DNS_DELEGATION_NS_NODATA_SOA_SERVFAIL,
    REVIEW_LABEL_DNS_DELEGATION_NS_NODATA_SOA_TIMEOUT,
    REVIEW_LABEL_DNS_DELEGATION_SERVFAIL,
    REVIEW_LABEL_DNS_DELEGATION_TIMEOUT,
    REVIEW_LABEL_DNS_HOST_RESOLUTION_FILTERED_OUT,
    REVIEW_LABEL_GEO_FILTERED_OUT,
    REVIEW_LABEL_INPUT_PUBLIC_SUFFIX,
    REVIEW_LABEL_MANUAL_FILTERED_OUT,
    REVIEW_LABEL_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
)
from domain_pipeline.prepare.sources.parser import ParsedDomainEntry
from domain_pipeline.worker.dns import DelegationResult, HostResolutionResult
from domain_pipeline.worker.geo import GeoPolicyDecision, IPGeoResult

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


class SourceContextLike(Protocol):
    """Source context attributes required for terminal-row projection."""

    @property
    def source_id(self) -> str:
        """Return the source identifier attached to this row."""
        raise NotImplementedError

    @property
    def input_label(self) -> str:
        """Return the operator-facing source input label."""
        raise NotImplementedError


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


def public_review_label(row: dict[str, Any]) -> str:
    """Return the public review label for one terminal row."""
    pipeline_result_code = str(row.get("classification", ""))
    if pipeline_result_code == PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX:
        return REVIEW_LABEL_INPUT_PUBLIC_SUFFIX
    if pipeline_result_code == PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES:
        return REVIEW_LABEL_MANUAL_FILTER_PASS_NOT_IN_SOURCES
    if pipeline_result_code in {
        PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT,
        PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
    }:
        return REVIEW_LABEL_MANUAL_FILTERED_OUT
    if pipeline_result_code == PIPELINE_RESULT_CODE_DNS_DELEGATION_TIMEOUT:
        return REVIEW_LABEL_DNS_DELEGATION_TIMEOUT
    if pipeline_result_code == PIPELINE_RESULT_CODE_DNS_DELEGATION_SERVFAIL:
        return REVIEW_LABEL_DNS_DELEGATION_SERVFAIL
    if (
        pipeline_result_code
        == PIPELINE_RESULT_CODE_DNS_DELEGATION_NS_NODATA_SOA_TIMEOUT
    ):
        return REVIEW_LABEL_DNS_DELEGATION_NS_NODATA_SOA_TIMEOUT
    if (
        pipeline_result_code
        == PIPELINE_RESULT_CODE_DNS_DELEGATION_NS_NODATA_SOA_SERVFAIL
    ):
        return REVIEW_LABEL_DNS_DELEGATION_NS_NODATA_SOA_SERVFAIL
    if pipeline_result_code in HOST_RESOLUTION_REVIEW_PIPELINE_RESULT_CODES:
        return REVIEW_LABEL_DNS_HOST_RESOLUTION_FILTERED_OUT
    if pipeline_result_code in GEO_REVIEW_PIPELINE_RESULT_CODES:
        return REVIEW_LABEL_GEO_FILTERED_OUT
    return pipeline_result_code


def review_reason_for_row(row: dict[str, Any]) -> str:
    """Return a user-facing reason for why one row landed in review output."""
    pipeline_result_code = str(row.get("classification", ""))
    host_resolution_reason = str(row.get("host_resolution_reason", ""))
    host_resolution_status = str(row.get("host_resolution_status", ""))
    if (
        pipeline_result_code in HOST_RESOLUTION_REVIEW_PIPELINE_RESULT_CODES
        and host_resolution_reason
        and host_resolution_reason != host_resolution_status
    ):
        return host_resolution_reason
    reason_by_pipeline_result_code = {
        PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX: (
            "input is a public suffix rather than a registrable host"
        ),
        PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES: (
            "manual_filter_pass entry was not present in any configured source"
        ),
        PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_PUBLIC_SUFFIX: (
            "public suffix input was explicitly allowed by manual_filter_pass"
        ),
        PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT: (
            "host was explicitly sent to review by manual_filter_out"
        ),
        PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES: (
            "manual_filter_out entry was not present in any configured source"
        ),
        PIPELINE_RESULT_CODE_DNS_DELEGATION_TIMEOUT: (
            "NS delegation lookup timed out after retries"
        ),
        PIPELINE_RESULT_CODE_DNS_DELEGATION_SERVFAIL: (
            "NS delegation lookup returned SERVFAIL after retries"
        ),
        PIPELINE_RESULT_CODE_DNS_DELEGATION_NS_NODATA_SOA_ABSENT: (
            "NS delegation returned NODATA and SOA was absent"
        ),
        PIPELINE_RESULT_CODE_DNS_DELEGATION_NS_NODATA_SOA_TIMEOUT: (
            "NS delegation returned NODATA and SOA fallback timed out after retries"
        ),
        PIPELINE_RESULT_CODE_DNS_DELEGATION_NS_NODATA_SOA_SERVFAIL: (
            "NS delegation returned NODATA and SOA fallback returned SERVFAIL after retries"
        ),
        PIPELINE_RESULT_CODE_DNS_HOST_NXDOMAIN: "host resolution returned NXDOMAIN",
        PIPELINE_RESULT_CODE_DNS_HOST_NODATA: "host resolution returned NODATA",
        PIPELINE_RESULT_CODE_DNS_HOST_RESOLUTION_TIMEOUT: (
            "host resolution timed out after retries"
        ),
        PIPELINE_RESULT_CODE_DNS_HOST_RESOLUTION_SERVFAIL: (
            "host resolution returned SERVFAIL after retries"
        ),
        PIPELINE_RESULT_CODE_DNS_HOST_RESOLUTION_RESOLVED_WITHOUT_IP_ADDRESSES: (
            "host resolution produced no usable IP addresses"
        ),
        PIPELINE_RESULT_CODE_GEO_LOOKUP_FAILED: "geo lookup did not produce usable data",
        PIPELINE_RESULT_CODE_GEO_REGION_NAME_UNAVAILABLE: (
            "geo policy required a region name unavailable from the provider"
        ),
        PIPELINE_RESULT_CODE_GEO_POLICY_REJECTED: "geo policy rejected the resolved IP set",
    }
    return reason_by_pipeline_result_code.get(
        pipeline_result_code, pipeline_result_code
    )


def _json_list(values: list[str] | tuple[str, ...]) -> str:
    return json.dumps(list(values), ensure_ascii=True, sort_keys=True)


def build_base_row(
    *,
    source_context: SourceContextLike,
    entry: ParsedDomainEntry,
    pipeline_result_code: str,
    delegation_result: DelegationResult | None = None,
    host_resolution_result: HostResolutionResult | None = None,
    geo_results: list[IPGeoResult] | None = None,
    geo_policy: GeoPolicyDecision | None = None,
    source_id_override: str | None = None,
    source_input_label_override: str | None = None,
    source_ids: tuple[str, ...] = (),
    source_input_labels: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Build the raw/terminal row shared by runtime and preparation."""
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
        "classification": pipeline_result_code,
        "classification_reason": review_reason_for_row(
            {"classification": pipeline_result_code}
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
            host_resolution_result.reason
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
        "source_id": source_id_override or source_context.source_id,
        "source_input_label": source_input_label_override or source_context.input_label,
        "source_ids": list(source_ids or (source_context.source_id,)),
        "source_input_labels": list(
            source_input_labels or (source_context.input_label,)
        ),
    }
    row["classification_reason"] = review_reason_for_row(row)
    return row


def build_review_output_row(row: dict[str, Any]) -> ReviewOutputRow:
    """Project one raw terminal row into the public review CSV schema."""
    projected = {
        "input_name": str(row.get("input_name", "")),
        "host": str(row.get("host", "")),
        "registrable_domain": str(row.get("registrable_domain", "")),
        "classification": public_review_label(row),
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
