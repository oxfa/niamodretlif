"""Worker runtime stage owners."""

from __future__ import annotations

from typing import Any

from domain_pipeline.prepare.classifications import (
    PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX,
    PIPELINE_RESULT_CODE_MANUAL_ADD_ACTIONABLE,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_PASSED,
)
from domain_pipeline.worker.dns import (
    DelegationResult,
    HostResolutionResult,
    classify_delegation,
    classify_host_resolution,
    host_resolution_skipped_result_code,
)
from domain_pipeline.routing import route_for_pipeline_result_code
from domain_pipeline.worker.runtime.contracts import (
    GeoWorkItem,
    HostResolutionWorkItem,
    ParsedHostItem,
)
from domain_pipeline.worker.runtime.queues import RuntimeQueueSet


class DelegationStage:
    """Own delegation queue consumption and delegation routing."""

    def __init__(self, runtime: Any) -> None:
        self.runtime = runtime

    async def worker(self, queue_bundle: RuntimeQueueSet) -> None:
        """Consume worker-local delegation input and route each result."""
        while True:
            parsed = await queue_bundle.delegation_input.get()
            try:
                if parsed is None:
                    return
                if (
                    parsed.entry.is_public_suffix_input
                    or not parsed.entry.registrable_domain
                ):
                    await self.runtime.put_completed(
                        queue_bundle,
                        parsed,
                        pipeline_result_code=PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX,
                    )
                    continue
                delegation_result = await self.runtime.lookup_delegation(
                    parsed.source_context, parsed.entry
                )
                await self.route(queue_bundle, parsed, delegation_result)
            finally:
                queue_bundle.delegation_input.task_done()

    async def route(
        self,
        queue_bundle: RuntimeQueueSet,
        parsed: ParsedHostItem,
        delegation_result: DelegationResult,
    ) -> None:
        """Route one delegation result to terminal output or host resolution."""
        delegation_result_code = classify_delegation(delegation_result)
        if not delegation_result.actionable:
            await self.runtime.put_completed(
                queue_bundle,
                parsed,
                pipeline_result_code=delegation_result_code,
                delegation_result=delegation_result,
            )
            return
        if parsed.manual_filter_pass:
            await self.runtime.put_completed(
                queue_bundle,
                parsed,
                pipeline_result_code=PIPELINE_RESULT_CODE_MANUAL_FILTER_PASSED,
                delegation_result=delegation_result,
            )
            return
        if parsed.manual_add:
            await self.runtime.put_completed(
                queue_bundle,
                parsed,
                pipeline_result_code=PIPELINE_RESULT_CODE_MANUAL_ADD_ACTIONABLE,
                delegation_result=delegation_result,
            )
            return
        dns_config = parsed.source_context.config["dns"]
        if not bool(dns_config.get("host_resolution", {}).get("enabled", False)):
            await self.runtime.put_completed(
                queue_bundle,
                parsed,
                pipeline_result_code=host_resolution_skipped_result_code(),
                delegation_result=delegation_result,
            )
            return
        await queue_bundle.delegation_to_host_resolution.put(
            HostResolutionWorkItem(parsed=parsed, delegation_result=delegation_result)
        )


class HostResolutionStage:
    """Own host-resolution queue consumption and routing."""

    def __init__(self, runtime: Any) -> None:
        self.runtime = runtime

    async def worker(self, queue_bundle: RuntimeQueueSet) -> None:
        """Consume host-resolution work and route review, filtered, or geo cases."""
        while True:
            work_item = await queue_bundle.delegation_to_host_resolution.get()
            try:
                if work_item is None:
                    return
                host_resolution_result = await self.runtime.lookup_host_resolution(
                    work_item.parsed.source_context, work_item.parsed.entry
                )
                await self.route(queue_bundle, work_item, host_resolution_result)
            finally:
                queue_bundle.delegation_to_host_resolution.task_done()

    async def route(
        self,
        queue_bundle: RuntimeQueueSet,
        work_item: HostResolutionWorkItem,
        host_resolution_result: HostResolutionResult,
    ) -> None:
        """Route one host-resolution result to terminal output or geo."""
        host_result_code = classify_host_resolution(host_resolution_result)
        if route_for_pipeline_result_code(host_result_code) == "review":
            await self.runtime.put_completed(
                queue_bundle,
                work_item.parsed,
                pipeline_result_code=host_result_code,
                delegation_result=work_item.delegation_result,
                host_resolution_result=host_resolution_result,
            )
            return
        if not bool(
            work_item.parsed.source_context.config["geo"].get("enabled", False)
        ):
            await self.runtime.put_completed(
                queue_bundle,
                work_item.parsed,
                pipeline_result_code=host_result_code,
                delegation_result=work_item.delegation_result,
                host_resolution_result=host_resolution_result,
            )
            return
        await queue_bundle.host_resolution_to_geo.put(
            GeoWorkItem(
                parsed=work_item.parsed,
                delegation_result=work_item.delegation_result,
                host_resolution_result=host_resolution_result,
                pipeline_result_code=host_result_code,
            )
        )


class GeoStage:
    """Own geo queue consumption and terminal policy routing."""

    def __init__(self, runtime: Any) -> None:
        self.runtime = runtime

    async def worker(self, queue_bundle: RuntimeQueueSet) -> None:
        """Consume geo work and emit terminal policy results."""
        while True:
            work_item = await queue_bundle.host_resolution_to_geo.get()
            try:
                if work_item is None:
                    return
                geo_result_code, geo_results, geo_policy = (
                    await self.runtime.lookup_geo(
                        work_item.parsed.source_context,
                        work_item.host_resolution_result,
                    )
                )
                await self.runtime.put_completed(
                    queue_bundle,
                    work_item.parsed,
                    pipeline_result_code=geo_result_code,
                    delegation_result=work_item.delegation_result,
                    host_resolution_result=work_item.host_resolution_result,
                    geo_results=geo_results,
                    geo_policy=geo_policy,
                )
            finally:
                queue_bundle.host_resolution_to_geo.task_done()


__all__ = ["DelegationStage", "GeoStage", "HostResolutionStage"]
