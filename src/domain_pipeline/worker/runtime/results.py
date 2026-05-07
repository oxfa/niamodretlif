"""Runtime completed-result factory exports."""

from __future__ import annotations

from typing import Any

from domain_pipeline.routing import route_for_pipeline_result_code
from domain_pipeline.prepare.sources.parser import ParsedDomainEntry
from domain_pipeline.worker.output import (
    build_base_row,
)
from domain_pipeline.worker.dns import DelegationResult, HostResolutionResult
from domain_pipeline.worker.geo import GEO_STATUS_CACHE_HIT, IPGeoResult
from domain_pipeline.worker.runtime.contracts import (
    CompletedHostResult,
    WorkerSourceContext,
)


class CompletedResultFactory:
    """Build terminal runtime result objects."""

    def build(
        self,
        *,
        source_context: WorkerSourceContext,
        entry: ParsedDomainEntry,
        pipeline_result_code: str,
        delegation_result: DelegationResult | None = None,
        host_resolution_result: HostResolutionResult | None = None,
        geo_results: list[IPGeoResult] | None = None,
        geo_policy: Any | None = None,
        provenance: dict[str, Any] | None = None,
        row_overrides: dict[str, Any] | None = None,
    ) -> CompletedHostResult:
        """Build a completed host result from a base output row."""
        provenance = provenance or {}
        row = build_base_row(
            source_context=source_context,
            entry=entry,
            pipeline_result_code=pipeline_result_code,
            delegation_result=delegation_result,
            host_resolution_result=host_resolution_result,
            geo_results=geo_results or [],
            geo_policy=geo_policy,
            source_id_override=provenance.get("source_id_override"),
            source_input_label_override=provenance.get("source_input_label_override"),
            source_ids=tuple(provenance.get("source_ids", ())),
            source_input_labels=tuple(provenance.get("source_input_labels", ())),
        )
        if row_overrides:
            row.update(row_overrides)
        return CompletedHostResult(
            source_context=source_context,
            entry=entry,
            pipeline_result_code=pipeline_result_code,
            route=route_for_pipeline_result_code(pipeline_result_code),
            row=row,
            delegation_result=delegation_result,
            host_resolution_result=host_resolution_result,
            geo_results=geo_results or [],
            geo_policy=geo_policy,
        )


def delegation_result_from_cache_record(record: Any) -> DelegationResult:
    """Build a delegation result from one cached delegation row."""
    return DelegationResult(
        domain=record.domain,
        ns_exists=record.ns_exists,
        ns_nodata=record.ns_nodata,
        ns_nxdomain=record.ns_nxdomain,
        ns_timeout=record.ns_timeout,
        ns_servfail=record.ns_servfail,
        soa_exists=record.soa_exists,
        soa_nodata=record.soa_nodata,
        soa_nxdomain=record.soa_nxdomain,
        soa_timeout=record.soa_timeout,
        soa_servfail=record.soa_servfail,
        soa_source="cache" if record.soa_exists else "",
        no_nameservers=record.no_nameservers,
        nameservers=record.nameservers,
        from_cache=True,
    )


def host_resolution_result_from_cache_record(record: Any) -> HostResolutionResult:
    """Build a host-resolution result from the physical dns_history table."""
    return HostResolutionResult(
        host=record.host,
        a_exists=record.a_exists,
        a_nodata=record.a_nodata,
        a_nxdomain=record.a_nxdomain,
        a_timeout=record.a_timeout,
        a_servfail=record.a_servfail,
        canonical_name=record.canonical_name or None,
        ipv4_addresses=record.ipv4_addresses,
        ipv6_addresses=record.ipv6_addresses,
        from_cache=True,
    )


def geo_result_from_cache_record(record: Any) -> IPGeoResult:
    """Build a geo result from one cached geo row."""
    return IPGeoResult(
        ip=record.ip,
        provider=record.provider,
        country_code=record.country_code,
        region_code=record.region_code,
        region_name=record.region_name,
        status=GEO_STATUS_CACHE_HIT,
    )


__all__ = [
    "CompletedResultFactory",
    "delegation_result_from_cache_record",
    "geo_result_from_cache_record",
    "host_resolution_result_from_cache_record",
]
