"""Worker runtime stage owners."""

from __future__ import annotations

from typing import Any

from domain_pipeline.prepare.classifications import (
    PIPELINE_RESULT_CODE_MANUAL_ADD_ACTIONABLE,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_PASSED,
)
from domain_pipeline.worker.delegation import (
    DelegationResult,
    classify_delegation,
)
from domain_pipeline.worker.host_resolution import (
    HostResolutionResult,
    classify_host_resolution,
    host_resolution_skipped_result_code,
)
from domain_pipeline.routing import route_for_pipeline_result_code
from domain_pipeline.worker.runtime.contracts import (
    DelegationRootWorkItem,
    IpLocationWorkItem,
    HostResolutionWorkItem,
    ParsedHostItem,
)
from domain_pipeline.worker.runtime.busy_state import BusyReason
from domain_pipeline.worker.runtime.queues import RuntimeQueueSet


class DelegationStage:
    """Own root-level delegation queue consumption and host-level fanout."""

    def __init__(self, runtime: Any) -> None:
        self.runtime = runtime

    async def consume(self, queue_bundle: RuntimeQueueSet) -> None:
        """Consume root-level delegation input and route each host result."""
        while True:
            async with self.runtime.busy_state.track(BusyReason.QUEUE_WAIT):
                work_item = await queue_bundle.delegation_input.get()
            try:
                if work_item is None:
                    return
                async with self.runtime.busy_state.track(BusyReason.ITEM_PROCESSING):
                    delegation_result = await self.runtime.lookup_delegation_root(
                        work_item.delegation_source_context,
                        work_item.registrable_domain,
                    )
                    await self.route_root(queue_bundle, work_item, delegation_result)
            finally:
                queue_bundle.delegation_input.task_done()

    async def route_root(
        self,
        queue_bundle: RuntimeQueueSet,
        work_item: DelegationRootWorkItem,
        delegation_result: DelegationResult,
    ) -> None:
        """Fan out one root delegation result to host-level routing."""
        self.runtime.log_delegation_fanout(
            work_item.registrable_domain, len(work_item.items)
        )
        for parsed in work_item.items:
            await self.route(queue_bundle, parsed, delegation_result)

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
        host_resolution_config = parsed.source_context.config["host_resolution"]
        if not bool(host_resolution_config.get("enabled", False)):
            await self.runtime.put_completed(
                queue_bundle,
                parsed,
                pipeline_result_code=host_resolution_skipped_result_code(),
                delegation_result=delegation_result,
            )
            return
        async with self.runtime.busy_state.track(BusyReason.DOWNSTREAM_PUT):
            await queue_bundle.delegation_to_host_resolution.put(
                HostResolutionWorkItem(
                    parsed=parsed, delegation_result=delegation_result
                )
            )


class HostResolutionStage:
    """Own host-resolution queue consumption and routing."""

    def __init__(self, runtime: Any) -> None:
        self.runtime = runtime

    async def consume(self, queue_bundle: RuntimeQueueSet) -> None:
        """Consume host-resolution work and route review, filtered, or ip location cases."""
        while True:
            async with self.runtime.busy_state.track(BusyReason.QUEUE_WAIT):
                work_item = await queue_bundle.delegation_to_host_resolution.get()
            try:
                if work_item is None:
                    return
                async with self.runtime.busy_state.track(BusyReason.ITEM_PROCESSING):
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
        """Route one host-resolution result to terminal output or ip_location."""
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
            work_item.parsed.source_context.config["ip_location"].get("enabled", False)
        ):
            await self.runtime.put_completed(
                queue_bundle,
                work_item.parsed,
                pipeline_result_code=host_result_code,
                delegation_result=work_item.delegation_result,
                host_resolution_result=host_resolution_result,
            )
            return
        async with self.runtime.busy_state.track(BusyReason.DOWNSTREAM_PUT):
            await queue_bundle.host_resolution_to_ip_location.put(
                IpLocationWorkItem(
                    parsed=work_item.parsed,
                    delegation_result=work_item.delegation_result,
                    host_resolution_result=host_resolution_result,
                    pipeline_result_code=host_result_code,
                )
            )


class IpLocationStage:
    """Own ip location queue consumption and terminal policy routing."""

    def __init__(self, runtime: Any) -> None:
        self.runtime = runtime

    async def consume(self, queue_bundle: RuntimeQueueSet) -> None:
        """Consume ip location work and emit terminal policy results."""
        while True:
            async with self.runtime.busy_state.track(BusyReason.QUEUE_WAIT):
                work_item = await queue_bundle.host_resolution_to_ip_location.get()
            try:
                if work_item is None:
                    return
                async with self.runtime.busy_state.track(BusyReason.ITEM_PROCESSING):
                    ip_location_result_code, ip_location_results, ip_location_policy = (
                        await self.runtime.lookup_ip_location(
                            work_item.parsed.source_context,
                            work_item.host_resolution_result,
                        )
                    )
                    await self.runtime.put_completed(
                        queue_bundle,
                        work_item.parsed,
                        pipeline_result_code=ip_location_result_code,
                        delegation_result=work_item.delegation_result,
                        host_resolution_result=work_item.host_resolution_result,
                        ip_location_results=ip_location_results,
                        ip_location_policy=ip_location_policy,
                    )
            finally:
                queue_bundle.host_resolution_to_ip_location.task_done()


__all__ = ["DelegationStage", "IpLocationStage", "HostResolutionStage"]
