"""Runtime completed-result factory exports."""

from __future__ import annotations

from typing import Any

from domain_pipeline.routing import route_for_pipeline_result_code
from domain_pipeline.prepare.sources.parser import ParsedDomainEntry
from domain_pipeline.worker.output import (
    build_base_row,
)
from domain_pipeline.worker.dns import DelegationResult, HostResolutionResult
from domain_pipeline.worker.geo import IPGeoResult
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


__all__ = ["CompletedResultFactory"]
