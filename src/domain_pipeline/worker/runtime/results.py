"""Runtime completed-result builders and cache-record projections."""

from __future__ import annotations

import dataclasses
from typing import Any

from domain_pipeline.routing.route_codes import RouteCode, TerminalRouteTransition
from domain_pipeline.prepare.sources.parser import DomainEntry
from domain_pipeline.worker.output.rows import review_reason_for_row
from domain_pipeline.worker.delegation.lookup import (
    DelegationResult,
    DelegationSoaEvidence,
)
from domain_pipeline.worker.host_resolution.lookup import (
    HostResolutionAddressEvidence,
    HostResolutionResult,
)
from domain_pipeline.worker.ip_location.providers import (
    IP_LOCATION_FAILURE_REASON_INVALID_PAYLOAD,
    IP_LOCATION_FAILURE_REASON_RATE_LIMITED,
    IP_LOCATION_FAILURE_REASON_REQUEST_FAILED,
    IP_LOCATION_STATUS_CACHE_HIT,
    IPLocationResult,
    LocationPolicyDecision,
)
from domain_pipeline.worker.runtime.contracts import (
    CompletedInputDomainResult,
    CompletedResultEvidence,
)

_IP_LOCATION_FAILURE_PRIORITY = (
    IP_LOCATION_FAILURE_REASON_RATE_LIMITED,
    IP_LOCATION_FAILURE_REASON_INVALID_PAYLOAD,
    IP_LOCATION_FAILURE_REASON_REQUEST_FAILED,
)


@dataclasses.dataclass(frozen=True)
class CompletedResultRequest:
    """Inputs needed to build one terminal input-domain result."""

    entry: DomainEntry
    route_transition: TerminalRouteTransition
    evidence: CompletedResultEvidence = dataclasses.field(
        default_factory=CompletedResultEvidence
    )


def _representative_ip_location_result(
    results: list[IPLocationResult],
) -> IPLocationResult | None:
    if not results:
        return None
    failed = [result for result in results if not result.usable]
    if not failed:
        return results[0]
    for reason in _IP_LOCATION_FAILURE_PRIORITY:
        for result in failed:
            if result.failure_reason.strip() == reason:
                return result
    return failed[0]


def build_completed_result(request: CompletedResultRequest) -> CompletedInputDomainResult:
    """Build one final source-blind result for the assigned input domain."""
    transition = request.route_transition
    evidence = request.evidence
    delegation_result = evidence.delegation_result
    host_result = evidence.host_resolution_result
    selected_ip_result = _representative_ip_location_result(
        evidence.ip_location_results
    )
    ip_policy: LocationPolicyDecision | None = evidence.ip_location_policy
    row: dict[str, Any] = {
        "host": request.entry.host,
        "registrable_domain": request.entry.registrable_domain or "",
        "route": transition.route,
        "route_code": transition.route_code.value,
        "route_reason": transition.route_reason,
        "delegation_status": (
            delegation_result.status if delegation_result is not None else "skipped"
        ),
        "delegation_reason": (
            delegation_result.status if delegation_result is not None else "skipped"
        ),
        "delegation_nameservers": (
            list(delegation_result.nameservers)
            if delegation_result is not None
            else []
        ),
        "host_resolution_status": (
            host_result.status if host_result is not None else "skipped"
        ),
        "host_resolution_reason": (
            host_result.reason if host_result is not None else "skipped"
        ),
        "canonical_name": (
            host_result.canonical_name if host_result is not None else ""
        ),
        "resolved_ips": host_result.resolved_ips if host_result is not None else [],
        "ip_location_status": (
            ip_policy.status
            if ip_policy is not None
            else selected_ip_result.status
            if selected_ip_result is not None
            else "skipped"
        ),
        "ip_location_reason": (
            ip_policy.reason
            if ip_policy is not None
            else selected_ip_result.failure_reason.strip()
            if selected_ip_result is not None
            else "skipped"
        ),
        "ip_location_policy_status": (
            ip_policy.status if ip_policy is not None else "skipped"
        ),
        "ip_location_policy_reason": (
            ip_policy.reason if ip_policy is not None else "skipped"
        ),
        "ip_location_provider": (
            selected_ip_result.provider if selected_ip_result is not None else ""
        ),
    }
    row["review_reason"] = review_reason_for_row(row)
    return CompletedInputDomainResult(
        entry=request.entry,
        route=transition.route,
        route_code=RouteCode(transition.route_code),
        route_reason=transition.route_reason,
        row=row,
        evidence=evidence,
    )


def delegation_result_from_cache_record(record: Any) -> DelegationResult:
    """Build a delegation result from one cached delegation row."""
    return DelegationResult(
        domain=record.identity.name,
        dns=record.dns,
        soa=DelegationSoaEvidence(
            soa_exists=record.soa.soa_exists,
            soa_absent=record.soa.soa_absent,
            soa_retry_exhausted=record.soa.soa_retry_exhausted,
            soa_source="cache" if record.soa.soa_exists else "",
        ),
        no_nameservers=record.no_nameservers,
        nameservers=record.nameservers,
        from_cache=True,
    )


def host_resolution_result_from_cache_record(record: Any) -> HostResolutionResult:
    """Build a host-resolution result from the physical cache history row."""
    return HostResolutionResult(
        host=record.identity.name,
        dns=record.dns,
        addresses=HostResolutionAddressEvidence(
            canonical_name=record.addresses.canonical_name or None,
            ipv4_addresses=record.addresses.ipv4_addresses,
            ipv6_addresses=record.addresses.ipv6_addresses,
        ),
        from_cache=True,
    )


def ip_location_result_from_cache_record(record: Any) -> IPLocationResult:
    """Build an IP-location result from one cached lookup row."""
    return IPLocationResult(
        ip=record.identity.ip,
        provider=record.identity.provider,
        country_code=record.evidence.country_code,
        region_code=record.evidence.region_code,
        region_name=record.evidence.region_name,
        status=IP_LOCATION_STATUS_CACHE_HIT,
    )


__all__ = [
    "CompletedResultRequest",
    "build_completed_result",
    "delegation_result_from_cache_record",
    "ip_location_result_from_cache_record",
    "host_resolution_result_from_cache_record",
]
