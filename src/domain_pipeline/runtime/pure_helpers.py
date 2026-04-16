"""Pure classification, routing, and row-shaping helpers."""

from __future__ import annotations

import json
from typing import Any, TypedDict, cast

from domain_pipeline.classifications import (
    CLASSIFICATION_DNS_LOOKUP_SERVFAIL,
    CLASSIFICATION_DNS_LOOKUP_TIMEOUT,
    CLASSIFICATION_DNS_REGISTERED_APEX_NODATA,
    CLASSIFICATION_DNS_REGISTERED_APEX_NXDOMAIN,
    CLASSIFICATION_DNS_REGISTERED_SUBDOMAIN_NODATA,
    CLASSIFICATION_DNS_REGISTERED_SUBDOMAIN_NXDOMAIN,
    CLASSIFICATION_DNS_RESOLVED_WITHOUT_IP_ADDRESSES,
    CLASSIFICATION_DNS_RESOLVES,
    CLASSIFICATION_GEO_LOOKUP_FAILED,
    CLASSIFICATION_GEO_POLICY_REJECTED,
    CLASSIFICATION_GEO_REGION_NAME_UNAVAILABLE,
    CLASSIFICATION_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
    CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED,
    CLASSIFICATION_RDAP_STATUS_CLIENT_HOLD,
    CLASSIFICATION_RDAP_STATUS_DELETION_OTHER,
    CLASSIFICATION_RDAP_STATUS_HOLD_OTHER,
    CLASSIFICATION_RDAP_STATUS_INACTIVE,
    CLASSIFICATION_RDAP_STATUS_PENDING_DELETE,
    CLASSIFICATION_RDAP_STATUS_PENDING_RENEW,
    CLASSIFICATION_RDAP_STATUS_PENDING_RESTORE,
    CLASSIFICATION_RDAP_STATUS_REDEMPTION_PERIOD,
    CLASSIFICATION_RDAP_STATUS_SERVER_HOLD,
    GEO_REVIEW_CLASSIFICATIONS,
    RDAP_STATUS_CLASSIFICATION_ORDER,
    RDAP_STATUS_CLASSIFICATIONS,
    REVIEW_CLASSIFICATION_DNS_FILTERED_OUT,
    REVIEW_CLASSIFICATION_GEO_FILTERED_OUT,
    ROUTE_DROP_CLASSIFICATIONS,
    ROUTE_NORMAL_CLASSIFICATIONS,
    ROUTE_REVIEW_CLASSIFICATIONS,
)
from ..checking import DNSResult, IPGeoProvider, IPGeoResult, RDAPResult
from ..io.parser import ParsedDomainEntry
from ..shared import SourceJob
from .contracts import ResultRoute

REVIEW_OUTPUT_COLUMNS = (
    "input_name",
    "host",
    "registrable_domain",
    "classification",
    "classification_reason",
    "dns_status",
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

    source_id: str
    source_input_label: str
    input_name: str
    host: str
    registrable_domain: str
    classification: str
    classification_reason: str
    dns_status: str
    geo_status: str
    geo_reason: str
    geo_policy_status: str
    geo_policy_reason: str
    geo_provider: str
    source_ids: str
    source_input_labels: str


ROUTE_NORMAL_OUTPUT = "normal_output"
ROUTE_REVIEW = "review"
ROUTE_DROP = "drop"


def _registered_domain_subject(row: dict[str, Any]) -> str:
    """Return the most specific registered-domain subject available for one row."""
    if str(row.get("input_kind", "")) == "suffix_rule":
        return "registered suffix-rule domain"
    if str(row.get("host", "")) == str(row.get("registrable_domain", "")):
        return "registered apex domain"
    return "registered subdomain"


def review_reason_for_row(row: dict[str, Any]) -> str:
    """Return a user-facing reason for why one row landed in review output."""
    classification = str(row.get("classification", ""))
    geo_policy_status = str(row.get("geo_policy_status", ""))
    geo_policy_reason = str(row.get("geo_policy_reason", ""))
    registered_subject = _registered_domain_subject(row)
    reason_by_classification = {
        CLASSIFICATION_DNS_LOOKUP_TIMEOUT: "DNS lookup returned timeout",
        CLASSIFICATION_DNS_LOOKUP_SERVFAIL: "DNS lookup returned servfail",
        CLASSIFICATION_MANUAL_FILTER_PASS_NOT_IN_SOURCES: (
            "manual filter-pass host was not present in any configured source"
        ),
        CLASSIFICATION_DNS_REGISTERED_APEX_NXDOMAIN: (
            f"{registered_subject} returned NXDOMAIN"
        ),
        CLASSIFICATION_DNS_REGISTERED_APEX_NODATA: (
            f"{registered_subject} has no A/AAAA answers"
        ),
        CLASSIFICATION_DNS_REGISTERED_SUBDOMAIN_NXDOMAIN: (
            f"{registered_subject} returned NXDOMAIN"
        ),
        CLASSIFICATION_DNS_REGISTERED_SUBDOMAIN_NODATA: (
            f"{registered_subject} has no A/AAAA answers"
        ),
        CLASSIFICATION_RDAP_STATUS_INACTIVE: (
            "RDAP status inactive indicates the domain should not resolve"
        ),
        CLASSIFICATION_RDAP_STATUS_CLIENT_HOLD: (
            "RDAP status clientHold indicates the domain should not resolve"
        ),
        CLASSIFICATION_RDAP_STATUS_SERVER_HOLD: (
            "RDAP status serverHold indicates the domain should not resolve"
        ),
        CLASSIFICATION_RDAP_STATUS_HOLD_OTHER: (
            "an RDAP hold status indicates the domain should not resolve"
        ),
        CLASSIFICATION_RDAP_STATUS_REDEMPTION_PERIOD: (
            "RDAP status redemptionPeriod indicates the domain is pending deletion"
        ),
        CLASSIFICATION_RDAP_STATUS_PENDING_DELETE: (
            "RDAP status pendingDelete indicates the domain is pending deletion"
        ),
        CLASSIFICATION_RDAP_STATUS_PENDING_RESTORE: (
            "RDAP status pendingRestore indicates the domain is pending deletion"
        ),
        CLASSIFICATION_RDAP_STATUS_PENDING_RENEW: (
            "RDAP status pendingRenew indicates the domain is pending deletion"
        ),
        CLASSIFICATION_RDAP_STATUS_DELETION_OTHER: (
            "an RDAP deletion status indicates the domain is pending deletion"
        ),
        CLASSIFICATION_DNS_RESOLVED_WITHOUT_IP_ADDRESSES: (
            "DNS did not produce resolved IPs for geo validation"
        ),
        CLASSIFICATION_GEO_LOOKUP_FAILED: "geo lookup failed for all resolved IPs",
        CLASSIFICATION_GEO_REGION_NAME_UNAVAILABLE: (
            "resolved IPs lacked region names required by geo policy"
        ),
    }

    if (
        classification == CLASSIFICATION_GEO_POLICY_REJECTED
        or geo_policy_status == "rejected"
    ):
        if geo_policy_reason:
            return f"geo policy rejected resolved IPs: {geo_policy_reason}"
        return "geo policy rejected resolved IPs"
    if classification in reason_by_classification:
        return reason_by_classification[classification]
    if classification:
        return classification
    return "review routing triggered without a recorded classification"


def review_classification_for_row(row: dict[str, Any]) -> str:
    """Return the public review classification exposed in the CSV output."""
    classification = str(row.get("classification", ""))
    geo_policy_status = str(row.get("geo_policy_status", ""))
    if classification in GEO_REVIEW_CLASSIFICATIONS or geo_policy_status == "rejected":
        return REVIEW_CLASSIFICATION_GEO_FILTERED_OUT
    return REVIEW_CLASSIFICATION_DNS_FILTERED_OUT


def review_rdap_registration_status(rdap_result: RDAPResult | None) -> str:
    """Return a user-facing RDAP registration verdict for review output."""
    if rdap_result is None:
        return "unavailable"
    if rdap_result.exists:
        return "registered"
    return "unregistered"


def classify_host_from_results(
    host: str,
    registrable_domain: str,
    rdap_result: RDAPResult | None,
    dns_result: DNSResult,
    *,
    hold_statuses: set[str],
    deletion_statuses: set[str],
) -> str:
    """Classify one host from RDAP and DNS results."""
    if rdap_result is not None and not rdap_result.exists:
        return CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED
    if dns_result.status == "timeout":
        return CLASSIFICATION_DNS_LOOKUP_TIMEOUT
    if dns_result.status == "servfail":
        return CLASSIFICATION_DNS_LOOKUP_SERVFAIL
    if dns_result.a_nxdomain:
        if host == registrable_domain:
            return CLASSIFICATION_DNS_REGISTERED_APEX_NXDOMAIN
        return CLASSIFICATION_DNS_REGISTERED_SUBDOMAIN_NXDOMAIN
    if dns_result.a_nodata:
        if host == registrable_domain:
            return CLASSIFICATION_DNS_REGISTERED_APEX_NODATA
        return CLASSIFICATION_DNS_REGISTERED_SUBDOMAIN_NODATA
    if rdap_result is not None:
        statuses_lower = {status.lower() for status in rdap_result.statuses}
        for status_name in RDAP_STATUS_CLASSIFICATION_ORDER:
            if status_name in statuses_lower:
                return RDAP_STATUS_CLASSIFICATIONS[status_name]
        if statuses_lower & {status.lower() for status in hold_statuses}:
            return CLASSIFICATION_RDAP_STATUS_HOLD_OTHER
        if statuses_lower & {status.lower() for status in deletion_statuses}:
            return CLASSIFICATION_RDAP_STATUS_DELETION_OTHER
    return CLASSIFICATION_DNS_RESOLVES


def route_for_row(
    classification: str,
    geo_policy_status: str,
    geo_reason: str,
) -> ResultRoute:
    """Return the final route for one classified row."""
    if classification in ROUTE_DROP_CLASSIFICATIONS:
        return ROUTE_DROP
    if classification in ROUTE_REVIEW_CLASSIFICATIONS:
        return ROUTE_REVIEW
    if classification in ROUTE_NORMAL_CLASSIFICATIONS:
        if geo_reason == "no_resolved_ips":
            return ROUTE_REVIEW
        if geo_policy_status == "rejected":
            return ROUTE_REVIEW
        return ROUTE_NORMAL_OUTPUT
    return ROUTE_REVIEW


def ordered_geo_provider_names(configured_provider_name: str) -> list[str]:
    """Return the one runtime-selected geo provider for the current source policy."""
    return [configured_provider_name]


def build_output_row(
    job: SourceJob,
    entry: ParsedDomainEntry,
    classification: str,
    rdap_result: RDAPResult | None,
    dns_result: DNSResult,
    geo_results: list[IPGeoResult],
    geo_status: str,
    geo_reason: str,
    geo_policy_status: str,
    geo_policy_reason: str,
    provider: IPGeoProvider | None,
    *,
    dns_status_override: str | None = None,
    source_ids_override: list[str] | None = None,
    source_input_labels_override: list[str] | None = None,
) -> dict[str, Any]:
    """Build the full audit row for one processed host."""
    effective_geo_provider = str(
        job.config.get("geo", {}).get("effective_provider", "")
    )
    geo_provider_name = ""
    if provider is not None:
        geo_provider_name = provider.provider_name
    elif effective_geo_provider and (
        geo_status == "review"
        or geo_policy_status in {"accepted", "rejected"}
        or geo_reason == "lookup_succeeded"
    ):
        geo_provider_name = effective_geo_provider
    source_ids = source_ids_override or [job.source_id]
    source_input_labels = source_input_labels_override or [job.input_label]
    return {
        "source_id": job.source_id,
        "source_input_label": job.input_label,
        "source_ids": list(source_ids),
        "source_input_labels": list(source_input_labels),
        "input_name": entry.input_name or entry.host,
        "host": entry.host,
        "registrable_domain": entry.registrable_domain,
        "public_suffix": entry.public_suffix,
        "is_public_suffix_input": entry.is_public_suffix_input,
        "input_kind": entry.input_kind,
        "apex_scope": entry.apex_scope,
        "source_format": entry.source_format,
        "classification": classification,
        "rdap_registration_status": review_rdap_registration_status(rdap_result),
        "dns_status": dns_status_override or dns_result.status,
        "canonical_name": dns_result.canonical_name or "",
        "resolved_ips": dns_result.resolved_ips,
        "geo_status": geo_status,
        "geo_reason": geo_reason,
        "geo_policy_status": geo_policy_status,
        "geo_policy_reason": geo_policy_reason,
        "geo_provider": geo_provider_name,
        "geo_countries": sorted(
            {result.country_code for result in geo_results if result.country_code}
        ),
        "geo_region_codes": sorted(
            {result.region_code for result in geo_results if result.region_code}
        ),
        "geo_region_names": sorted(
            {
                result.region_name.strip()
                for result in geo_results
                if result.region_name.strip()
            }
        ),
    }


def build_review_output_row(row: dict[str, Any]) -> ReviewOutputRow:
    """Project one full output row down to the review CSV columns."""
    review_row = dict(row)
    review_row["classification"] = review_classification_for_row(row)
    review_row["classification_reason"] = review_reason_for_row(row)
    for column in ("source_ids", "source_input_labels"):
        value = review_row.get(column, [])
        if isinstance(value, str):
            continue
        review_row[column] = json.dumps(list(value), separators=(",", ":"))
    return cast(
        ReviewOutputRow,
        {column: str(review_row.get(column, "")) for column in REVIEW_OUTPUT_COLUMNS},
    )
