"""Runtime completed-result factory exports."""

from __future__ import annotations

import dataclasses
from typing import Any

from domain_pipeline.routing.decisions import TerminalDecisionPolicy
from domain_pipeline.prepare.sources.parser import ParsedDomainEntry
from domain_pipeline.worker.output.rows import (
    BaseRowDNSRequest,
    BaseRowIpLocationRequest,
    BaseRowRequest,
    BaseRowSourceRequest,
    TerminalRowBuilder,
)
from domain_pipeline.prepare.models import PreparedProvenance
from domain_pipeline.worker.delegation.lookup import (
    DelegationResult,
    DelegationSoaEvidence,
)
from domain_pipeline.worker.host_resolution.lookup import (
    HostResolutionAddressEvidence,
    HostResolutionResult,
)
from domain_pipeline.worker.ip_location.providers import (
    IP_LOCATION_STATUS_CACHE_HIT,
    IPLocationResult,
)
from domain_pipeline.worker.runtime.contracts import (
    CompletedResultEvidence,
    CompletedHostResult,
    WorkerSourceContext,
)


@dataclasses.dataclass(frozen=True)
class CompletedResultRequest:
    """Inputs needed to build one terminal runtime result."""

    source_context: WorkerSourceContext
    entry: ParsedDomainEntry
    decision_reason_code: str
    evidence: CompletedResultEvidence = dataclasses.field(
        default_factory=CompletedResultEvidence
    )
    provenance: dict[str, Any] = dataclasses.field(default_factory=dict)
    row_overrides: dict[str, Any] = dataclasses.field(default_factory=dict)


def build_completed_result(request: CompletedResultRequest) -> CompletedHostResult:
    """Build a completed host result from a base output row."""
    decision = TerminalDecisionPolicy().from_reason_code(request.decision_reason_code)
    row = TerminalRowBuilder().build(
        BaseRowRequest(
            source=BaseRowSourceRequest(
                source_context=request.source_context,
                provenance=PreparedProvenance(
                    source_id_override=request.provenance.get("source_id_override"),
                    source_input_label_override=request.provenance.get(
                        "source_input_label_override"
                    ),
                    source_ids=tuple(request.provenance.get("source_ids", ())),
                    source_input_labels=tuple(
                        request.provenance.get("source_input_labels", ())
                    ),
                ),
            ),
            entry=request.entry,
            decision=decision,
            dns=BaseRowDNSRequest(
                delegation_result=request.evidence.delegation_result,
                host_resolution_result=request.evidence.host_resolution_result,
            ),
            ip_location=BaseRowIpLocationRequest(
                results=request.evidence.ip_location_results,
                policy=request.evidence.ip_location_policy,
            ),
        )
    )
    if request.row_overrides:
        row.update(request.row_overrides)
    return CompletedHostResult(
        source_context=request.source_context,
        entry=request.entry,
        final_result_code=decision.final_result_code,
        decision_reason_code=decision.decision_reason_code,
        route=decision.route,
        row=row,
        evidence=CompletedResultEvidence(
            delegation_result=request.evidence.delegation_result,
            host_resolution_result=request.evidence.host_resolution_result,
            ip_location_results=request.evidence.ip_location_results,
            ip_location_policy=request.evidence.ip_location_policy,
        ),
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
    """Build a host-resolution result from the physical host_resolution_history table."""
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
    """Build an IP-location result from one cached IP-location row."""
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
