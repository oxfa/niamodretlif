"""Raw terminal row and review CSV row projection helpers."""

from __future__ import annotations

import json
import dataclasses
from typing import Any, Protocol, TypedDict

from domain_pipeline.prepare.classifications import (
    PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_PUBLIC_SUFFIX,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
)
from domain_pipeline.worker.delegation.result_codes import (
    PIPELINE_RESULT_CODE_DELEGATION_NS_NODATA_SOA_ABSENT,
    PIPELINE_RESULT_CODE_DELEGATION_NS_NODATA_SOA_SERVFAIL,
    PIPELINE_RESULT_CODE_DELEGATION_NS_NODATA_SOA_TIMEOUT,
    PIPELINE_RESULT_CODE_DELEGATION_SERVFAIL,
    PIPELINE_RESULT_CODE_DELEGATION_TIMEOUT,
)
from domain_pipeline.worker.host_resolution.result_codes import (
    PIPELINE_RESULT_CODE_HOST_RESOLUTION_NODATA,
    PIPELINE_RESULT_CODE_HOST_RESOLUTION_NXDOMAIN,
    PIPELINE_RESULT_CODE_HOST_RESOLUTION_RESOLVED_WITHOUT_IP_ADDRESSES,
    PIPELINE_RESULT_CODE_HOST_RESOLUTION_SERVFAIL,
    PIPELINE_RESULT_CODE_HOST_RESOLUTION_TIMEOUT,
    HOST_RESOLUTION_REVIEW_PIPELINE_RESULT_CODES,
)
from domain_pipeline.worker.ip_location.result_codes import (
    PIPELINE_RESULT_CODE_IP_LOCATION_LOOKUP_FAILED,
    PIPELINE_RESULT_CODE_IP_LOCATION_POLICY_REJECTED,
    PIPELINE_RESULT_CODE_IP_LOCATION_REGION_NAME_UNAVAILABLE,
    IP_LOCATION_REVIEW_PIPELINE_RESULT_CODES,
)
from domain_pipeline.worker.output.review_labels import (
    REVIEW_LABEL_DELEGATION_NS_NODATA_SOA_SERVFAIL,
    REVIEW_LABEL_DELEGATION_NS_NODATA_SOA_TIMEOUT,
    REVIEW_LABEL_DELEGATION_SERVFAIL,
    REVIEW_LABEL_DELEGATION_TIMEOUT,
    REVIEW_LABEL_HOST_RESOLUTION_FILTERED_OUT,
    REVIEW_LABEL_IP_LOCATION_FILTERED_OUT,
    REVIEW_LABEL_INPUT_PUBLIC_SUFFIX,
    REVIEW_LABEL_MANUAL_FILTERED_OUT,
    REVIEW_LABEL_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
)
from domain_pipeline.prepare.sources.parser import ParsedDomainEntry
from domain_pipeline.prepare.models import PreparedProvenance
from domain_pipeline.worker.delegation.lookup import DelegationResult
from domain_pipeline.worker.host_resolution.lookup import HostResolutionResult
from domain_pipeline.worker.ip_location.providers import (
    LocationPolicyDecision,
    IPLocationResult,
)

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
    "ip_location_status",
    "ip_location_reason",
    "ip_location_policy_status",
    "ip_location_policy_reason",
    "ip_location_provider",
    "source_id",
    "source_input_label",
    "source_ids",
    "source_input_labels",
)

_PUBLIC_REVIEW_LABEL_BY_RESULT_CODE = {
    PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX: REVIEW_LABEL_INPUT_PUBLIC_SUFFIX,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES: (
        REVIEW_LABEL_MANUAL_FILTER_PASS_NOT_IN_SOURCES
    ),
    PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT: REVIEW_LABEL_MANUAL_FILTERED_OUT,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES: (
        REVIEW_LABEL_MANUAL_FILTERED_OUT
    ),
    PIPELINE_RESULT_CODE_DELEGATION_TIMEOUT: REVIEW_LABEL_DELEGATION_TIMEOUT,
    PIPELINE_RESULT_CODE_DELEGATION_SERVFAIL: REVIEW_LABEL_DELEGATION_SERVFAIL,
    PIPELINE_RESULT_CODE_DELEGATION_NS_NODATA_SOA_TIMEOUT: (
        REVIEW_LABEL_DELEGATION_NS_NODATA_SOA_TIMEOUT
    ),
    PIPELINE_RESULT_CODE_DELEGATION_NS_NODATA_SOA_SERVFAIL: (
        REVIEW_LABEL_DELEGATION_NS_NODATA_SOA_SERVFAIL
    ),
}


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
    ip_location_status: str
    ip_location_reason: str
    ip_location_policy_status: str
    ip_location_policy_reason: str
    ip_location_provider: str
    source_id: str
    source_input_label: str
    source_ids: str
    source_input_labels: str


@dataclasses.dataclass(frozen=True)
class BaseRowSourceRequest:
    """Source identity fields for raw terminal-row projection."""

    source_context: SourceContextLike
    provenance: PreparedProvenance = dataclasses.field(
        default_factory=PreparedProvenance
    )

    @property
    def source_id_override(self) -> str | None:
        """Return an optional source-id override for projected output rows."""
        return self.provenance.source_id_override

    @property
    def source_input_label_override(self) -> str | None:
        """Return an optional source-label override for projected output rows."""
        return self.provenance.source_input_label_override

    @property
    def source_ids(self) -> tuple[str, ...]:
        """Return all contributing source ids for projected output rows."""
        return self.provenance.source_ids

    @property
    def source_input_labels(self) -> tuple[str, ...]:
        """Return all contributing source labels for projected output rows."""
        return self.provenance.source_input_labels


@dataclasses.dataclass(frozen=True)
class BaseRowDNSRequest:
    """DNS-stage evidence for raw terminal-row projection."""

    delegation_result: DelegationResult | None = None
    host_resolution_result: HostResolutionResult | None = None


@dataclasses.dataclass(frozen=True)
class BaseRowIpLocationRequest:
    """IP-location evidence for raw terminal-row projection."""

    results: list[IPLocationResult] | None = None
    policy: LocationPolicyDecision | None = None


@dataclasses.dataclass(frozen=True)
class BaseRowRequest:
    """Complete raw terminal-row projection request."""

    source: BaseRowSourceRequest
    entry: ParsedDomainEntry
    pipeline_result_code: str
    dns: BaseRowDNSRequest = dataclasses.field(default_factory=BaseRowDNSRequest)
    ip_location: BaseRowIpLocationRequest = dataclasses.field(
        default_factory=BaseRowIpLocationRequest
    )


def public_review_label(row: dict[str, Any]) -> str:
    """Return the public review label for one terminal row."""
    pipeline_result_code = str(row.get("classification", ""))
    if pipeline_result_code in _PUBLIC_REVIEW_LABEL_BY_RESULT_CODE:
        return _PUBLIC_REVIEW_LABEL_BY_RESULT_CODE[pipeline_result_code]
    if pipeline_result_code in HOST_RESOLUTION_REVIEW_PIPELINE_RESULT_CODES:
        return REVIEW_LABEL_HOST_RESOLUTION_FILTERED_OUT
    if pipeline_result_code in IP_LOCATION_REVIEW_PIPELINE_RESULT_CODES:
        return REVIEW_LABEL_IP_LOCATION_FILTERED_OUT
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
        PIPELINE_RESULT_CODE_DELEGATION_TIMEOUT: (
            "delegation authority check timed out after retries"
        ),
        PIPELINE_RESULT_CODE_DELEGATION_SERVFAIL: (
            "delegation authority check returned SERVFAIL after retries"
        ),
        PIPELINE_RESULT_CODE_DELEGATION_NS_NODATA_SOA_ABSENT: (
            "delegation NS query returned NODATA and SOA was absent"
        ),
        PIPELINE_RESULT_CODE_DELEGATION_NS_NODATA_SOA_TIMEOUT: (
            "delegation NS query returned NODATA and SOA fallback timed out "
            "after retries"
        ),
        PIPELINE_RESULT_CODE_DELEGATION_NS_NODATA_SOA_SERVFAIL: (
            "delegation NS query returned NODATA and SOA fallback returned "
            "SERVFAIL after retries"
        ),
        PIPELINE_RESULT_CODE_HOST_RESOLUTION_NXDOMAIN: (
            "host resolution returned NXDOMAIN"
        ),
        PIPELINE_RESULT_CODE_HOST_RESOLUTION_NODATA: "host resolution returned NODATA",
        PIPELINE_RESULT_CODE_HOST_RESOLUTION_TIMEOUT: (
            "host resolution timed out after retries"
        ),
        PIPELINE_RESULT_CODE_HOST_RESOLUTION_SERVFAIL: (
            "host resolution returned SERVFAIL after retries"
        ),
        PIPELINE_RESULT_CODE_HOST_RESOLUTION_RESOLVED_WITHOUT_IP_ADDRESSES: (
            "host resolution produced no usable IP addresses"
        ),
        PIPELINE_RESULT_CODE_IP_LOCATION_LOOKUP_FAILED: (
            "ip_location lookup did not produce usable data"
        ),
        PIPELINE_RESULT_CODE_IP_LOCATION_REGION_NAME_UNAVAILABLE: (
            "ip location policy required a region name unavailable from the provider"
        ),
        PIPELINE_RESULT_CODE_IP_LOCATION_POLICY_REJECTED: (
            "ip location policy rejected the resolved IP set"
        ),
    }
    return reason_by_pipeline_result_code.get(
        pipeline_result_code, pipeline_result_code
    )


def _json_list(values: list[str] | tuple[str, ...]) -> str:
    return json.dumps(list(values), ensure_ascii=True, sort_keys=True)


def build_base_row(request: BaseRowRequest) -> dict[str, Any]:
    """Build the raw/terminal row shared by runtime and preparation."""
    source_context = request.source.source_context
    entry = request.entry
    pipeline_result_code = request.pipeline_result_code
    delegation_result = request.dns.delegation_result
    host_resolution_result = request.dns.host_resolution_result
    ip_location_results = request.ip_location.results
    ip_location_policy = request.ip_location.policy
    resolved_ips = (
        host_resolution_result.resolved_ips
        if host_resolution_result is not None
        else []
    )
    usable_ip_location_results = [
        result for result in ip_location_results or [] if result.usable
    ]
    row: dict[str, Any] = {
        "input_name": entry.semantics.input_name or entry.host,
        "host": entry.host,
        "registrable_domain": entry.registrable_domain,
        "public_suffix": entry.semantics.public_suffix,
        "is_public_suffix_input": entry.semantics.is_public_suffix_input,
        "input_kind": entry.semantics.input_kind,
        "apex_scope": entry.semantics.apex_scope,
        "source_format": entry.semantics.source_format,
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
        "ip_location_status": (
            ip_location_policy.status if ip_location_policy is not None else "skipped"
        ),
        "ip_location_reason": (
            ip_location_policy.reason if ip_location_policy is not None else "skipped"
        ),
        "ip_location_policy_status": (
            ip_location_policy.status if ip_location_policy is not None else "skipped"
        ),
        "ip_location_policy_reason": (
            ip_location_policy.reason if ip_location_policy is not None else "skipped"
        ),
        "ip_location_provider": (
            usable_ip_location_results[0].provider if usable_ip_location_results else ""
        ),
        "ip_location_countries": sorted(
            {
                result.country_code
                for result in usable_ip_location_results
                if result.country_code
            }
        ),
        "ip_location_region_codes": sorted(
            {
                result.region_code
                for result in usable_ip_location_results
                if result.region_code
            }
        ),
        "ip_location_region_names": sorted(
            {
                result.region_name
                for result in usable_ip_location_results
                if result.region_name
            }
        ),
        "source_id": request.source.source_id_override or source_context.source_id,
        "source_input_label": (
            request.source.source_input_label_override or source_context.input_label
        ),
        "source_ids": list(request.source.source_ids or (source_context.source_id,)),
        "source_input_labels": list(
            request.source.source_input_labels or (source_context.input_label,)
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
        "ip_location_status": str(row.get("ip_location_status", "")),
        "ip_location_reason": str(row.get("ip_location_reason", "")),
        "ip_location_policy_status": str(row.get("ip_location_policy_status", "")),
        "ip_location_policy_reason": str(row.get("ip_location_policy_reason", "")),
        "ip_location_provider": str(row.get("ip_location_provider", "")),
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
