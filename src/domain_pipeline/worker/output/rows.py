"""Raw terminal row and review CSV row projection helpers."""

from __future__ import annotations

from collections.abc import Iterable
import json
import dataclasses
from typing import Any, Protocol, TypedDict

from domain_pipeline.routing.decisions import (
    TerminalDecision,
    TerminalDecisionPolicy,
)
from domain_pipeline.prepare.reason_codes import (
    DECISION_REASON_CODE_INPUT_PUBLIC_SUFFIX,
    DECISION_REASON_CODE_MANUAL_FILTER_OUT,
    DECISION_REASON_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
    DECISION_REASON_CODE_MANUAL_FILTER_PASS_PUBLIC_SUFFIX,
    DECISION_REASON_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
)
from domain_pipeline.worker.delegation.reason_codes import (
    DECISION_REASON_CODE_DELEGATION_NS_LOOKUP_ERROR,
    DECISION_REASON_CODE_DELEGATION_NS_NXDOMAIN_SOA_RETRY_EXHAUSTED,
    DECISION_REASON_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_ABSENT,
    DECISION_REASON_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_RETRY_EXHAUSTED,
)
from domain_pipeline.worker.host_resolution.reason_codes import (
    DECISION_REASON_CODE_HOST_RESOLUTION_NODATA,
    DECISION_REASON_CODE_HOST_RESOLUTION_NXDOMAIN,
    DECISION_REASON_CODE_HOST_RESOLUTION_RESOLVED_WITHOUT_IP_ADDRESSES,
    DECISION_REASON_CODE_HOST_RESOLUTION_SERVFAIL,
    DECISION_REASON_CODE_HOST_RESOLUTION_TIMEOUT,
    HOST_RESOLUTION_REVIEW_DECISION_REASON_CODES,
)
from domain_pipeline.worker.ip_location.reason_codes import (
    DECISION_REASON_CODE_IP_LOCATION_LOOKUP_FAILED,
    DECISION_REASON_CODE_IP_LOCATION_POLICY_REJECTED,
    DECISION_REASON_CODE_IP_LOCATION_REGION_NAME_UNAVAILABLE,
)
from domain_pipeline.prepare.sources.parser import ParsedDomainEntry
from domain_pipeline.prepare.models import PreparedProvenance
from domain_pipeline.worker.delegation.lookup import DelegationResult
from domain_pipeline.worker.host_resolution.lookup import HostResolutionResult
from domain_pipeline.worker.ip_location.providers import (
    IP_LOCATION_FAILURE_REASON_INVALID_PAYLOAD,
    IP_LOCATION_FAILURE_REASON_RATE_LIMITED,
    IP_LOCATION_FAILURE_REASON_REQUEST_FAILED,
    LocationPolicyDecision,
    IPLocationResult,
)

REVIEW_OUTPUT_COLUMNS = (
    "input_name",
    "host",
    "registrable_domain",
    "final_result_code",
    "review_reason_code",
    "review_reason",
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

_IP_LOCATION_FAILURE_REASON_PRIORITY = (
    IP_LOCATION_FAILURE_REASON_RATE_LIMITED,
    IP_LOCATION_FAILURE_REASON_INVALID_PAYLOAD,
    IP_LOCATION_FAILURE_REASON_REQUEST_FAILED,
)

_IP_LOCATION_LOOKUP_FAILURE_REVIEW_REASON = {
    IP_LOCATION_FAILURE_REASON_RATE_LIMITED: (
        "ip_location lookup failed because the ip_location provider rate limited the request"
    ),
    IP_LOCATION_FAILURE_REASON_INVALID_PAYLOAD: (
        "ip_location lookup failed because the ip_location provider returned unusable data"
    ),
    IP_LOCATION_FAILURE_REASON_REQUEST_FAILED: (
        "ip_location lookup failed because the ip_location provider request failed"
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
    final_result_code: str
    review_reason_code: str
    review_reason: str
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
    decision: TerminalDecision | None = None
    dns: BaseRowDNSRequest = dataclasses.field(default_factory=BaseRowDNSRequest)
    ip_location: BaseRowIpLocationRequest = dataclasses.field(
        default_factory=BaseRowIpLocationRequest
    )


def _ip_location_failure_reason(result: IPLocationResult) -> str:
    """Return one normalized failure reason from an IP-location result."""
    return str(result.failure_reason).strip()


def _representative_ip_location_result(
    ip_location_results: list[IPLocationResult],
) -> IPLocationResult | None:
    """Return the result that best explains the row-level IP-location status."""
    if not ip_location_results:
        return None
    failed_results = [result for result in ip_location_results if not result.usable]
    if not failed_results:
        return ip_location_results[0]
    for failure_reason in _IP_LOCATION_FAILURE_REASON_PRIORITY:
        for result in failed_results:
            if _ip_location_failure_reason(result) == failure_reason:
                return result
    return failed_results[0]


def _ip_location_status_for_row(
    ip_location_policy: LocationPolicyDecision | None,
    selected_result: IPLocationResult | None,
) -> str:
    """Return the row-level IP-location status for raw and review output."""
    if ip_location_policy is not None:
        return ip_location_policy.status
    if selected_result is not None:
        return selected_result.status
    return "skipped"


def _ip_location_reason_for_row(
    ip_location_policy: LocationPolicyDecision | None,
    selected_result: IPLocationResult | None,
) -> str:
    """Return the row-level IP-location reason for raw and review output."""
    if ip_location_policy is not None:
        return ip_location_policy.reason
    if selected_result is not None:
        return _ip_location_failure_reason(selected_result) or "skipped"
    return "skipped"


def review_reason_for_row(row: dict[str, Any]) -> str:
    """Return a user-facing reason for why one row landed in review output."""
    decision_reason_code = str(row.get("decision_reason_code", ""))
    host_resolution_reason = str(row.get("host_resolution_reason", ""))
    host_resolution_status = str(row.get("host_resolution_status", ""))
    if (
        decision_reason_code in HOST_RESOLUTION_REVIEW_DECISION_REASON_CODES
        and host_resolution_reason
        and host_resolution_reason != host_resolution_status
    ):
        return host_resolution_reason
    if decision_reason_code == DECISION_REASON_CODE_IP_LOCATION_LOOKUP_FAILED:
        ip_location_reason = str(row.get("ip_location_reason", ""))
        specific_reason = _IP_LOCATION_LOOKUP_FAILURE_REVIEW_REASON.get(
            ip_location_reason
        )
        if specific_reason is not None:
            return specific_reason
    reason_by_decision_reason_code = {
        DECISION_REASON_CODE_INPUT_PUBLIC_SUFFIX: (
            "input is a public suffix rather than a registrable host"
        ),
        DECISION_REASON_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES: (
            "manual_filter_pass entry was not present in any configured source"
        ),
        DECISION_REASON_CODE_MANUAL_FILTER_PASS_PUBLIC_SUFFIX: (
            "public suffix input was explicitly allowed by manual_filter_pass"
        ),
        DECISION_REASON_CODE_MANUAL_FILTER_OUT: (
            "host was explicitly sent to review by manual_filter_out"
        ),
        DECISION_REASON_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES: (
            "manual_filter_out entry was not present in any configured source"
        ),
        DECISION_REASON_CODE_DELEGATION_NS_NXDOMAIN_SOA_RETRY_EXHAUSTED: (
            "delegation NS query returned NXDOMAIN and SOA retry budget was exhausted"
        ),
        DECISION_REASON_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_ABSENT: (
            "delegation NS retry budget was exhausted and SOA was absent"
        ),
        DECISION_REASON_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_RETRY_EXHAUSTED: (
            "delegation NS retry budget was exhausted and SOA retry budget was exhausted"
        ),
        DECISION_REASON_CODE_DELEGATION_NS_LOOKUP_ERROR: (
            "delegation NS lookup failed before a definitive delegation result"
        ),
        DECISION_REASON_CODE_HOST_RESOLUTION_NXDOMAIN: (
            "host resolution returned NXDOMAIN"
        ),
        DECISION_REASON_CODE_HOST_RESOLUTION_NODATA: "host resolution returned NODATA",
        DECISION_REASON_CODE_HOST_RESOLUTION_TIMEOUT: (
            "host resolution timed out after retries"
        ),
        DECISION_REASON_CODE_HOST_RESOLUTION_SERVFAIL: (
            "host resolution returned SERVFAIL after retries"
        ),
        DECISION_REASON_CODE_HOST_RESOLUTION_RESOLVED_WITHOUT_IP_ADDRESSES: (
            "host resolution produced no usable IP addresses"
        ),
        DECISION_REASON_CODE_IP_LOCATION_LOOKUP_FAILED: (
            "ip_location lookup did not produce usable data"
        ),
        DECISION_REASON_CODE_IP_LOCATION_REGION_NAME_UNAVAILABLE: (
            "ip location policy required a region name unavailable from the provider"
        ),
        DECISION_REASON_CODE_IP_LOCATION_POLICY_REJECTED: (
            "ip location policy rejected the resolved IP set"
        ),
    }
    return reason_by_decision_reason_code.get(
        decision_reason_code, decision_reason_code
    )


def _json_list(values: list[str] | tuple[str, ...]) -> str:
    return json.dumps(list(values), ensure_ascii=True, sort_keys=True)


class TerminalRowBuilder:
    """Build raw terminal rows from a terminal decision and stage evidence."""

    def build(self, request: BaseRowRequest) -> dict[str, Any]:
        """Build the raw/terminal row shared by runtime and preparation."""
        return _build_terminal_row(request)

    def build_many(self, requests: Iterable[BaseRowRequest]) -> list[dict[str, Any]]:
        """Build multiple raw/terminal rows in request order."""
        return [self.build(request) for request in requests]


def _build_terminal_row(request: BaseRowRequest) -> dict[str, Any]:
    """Build the raw/terminal row shared by runtime and preparation."""
    source_context = request.source.source_context
    entry = request.entry
    if request.decision is None:
        raise ValueError("base row requires a terminal decision")
    decision = request.decision
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
    selected_ip_location_result = _representative_ip_location_result(
        list(ip_location_results or [])
    )
    row: dict[str, Any] = {
        "input_name": entry.semantics.input_name or entry.host,
        "host": entry.host,
        "registrable_domain": entry.registrable_domain,
        "public_suffix": entry.semantics.public_suffix,
        "is_public_suffix_input": entry.semantics.is_public_suffix_input,
        "input_kind": entry.semantics.input_kind,
        "apex_scope": entry.semantics.apex_scope,
        "source_format": entry.semantics.source_format,
        "final_result_code": decision.final_result_code,
        "decision_reason_code": decision.decision_reason_code,
        "decision_reason": TerminalDecisionPolicy().reason_text(
            decision.decision_reason_code
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
        "ip_location_status": _ip_location_status_for_row(
            ip_location_policy, selected_ip_location_result
        ),
        "ip_location_reason": _ip_location_reason_for_row(
            ip_location_policy, selected_ip_location_result
        ),
        "ip_location_policy_status": (
            ip_location_policy.status if ip_location_policy is not None else "skipped"
        ),
        "ip_location_policy_reason": (
            ip_location_policy.reason if ip_location_policy is not None else "skipped"
        ),
        "ip_location_provider": (
            selected_ip_location_result.provider
            if selected_ip_location_result is not None
            else ""
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
    return row


class ReviewRowProjector:
    """Project raw terminal rows into the review CSV schema."""

    def project(self, row: dict[str, Any]) -> ReviewOutputRow:
        """Project one raw terminal row into the public review CSV schema."""
        final_result_code = row.get("final_result_code")
        projected = {
            "input_name": str(row.get("input_name", "")),
            "host": str(row.get("host", "")),
            "registrable_domain": str(row.get("registrable_domain", "")),
            "final_result_code": (
                "" if final_result_code is None else str(final_result_code)
            ),
            "review_reason_code": str(row.get("decision_reason_code", "")),
            "review_reason": review_reason_for_row(row),
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

    def project_many(self, rows: Iterable[dict[str, Any]]) -> list[ReviewOutputRow]:
        """Project multiple raw terminal rows in input order."""
        return [self.project(row) for row in rows]
