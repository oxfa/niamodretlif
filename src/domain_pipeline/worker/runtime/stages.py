"""Worker runtime stage owners."""

from __future__ import annotations

from typing import Any
import dataclasses

from domain_pipeline.routing import (
    DelegationRoutingPolicy,
    HostResolutionRoutingPolicy,
    ManualRoutingPolicy,
    TerminalRouteTransition,
)
from domain_pipeline.worker.delegation.lookup import DelegationResult
from domain_pipeline.worker.host_resolution.lookup import (
    HostResolutionResult,
)
from domain_pipeline.worker.runtime.contracts import (
    CompletedResultEvidence,
    DelegationRootWorkItem,
    IpLocationWorkItem,
    HostResolutionWorkItem,
    ParsedHostItem,
)
from domain_pipeline.worker.runtime.busy_state import BusyReason
from domain_pipeline.worker.runtime.queues import RuntimeQueueSet
from domain_pipeline.worker.runtime.results import CompletedResultRequest


def _completed_request(
    parsed: ParsedHostItem,
    route_transition: TerminalRouteTransition,
    evidence: CompletedResultEvidence | None = None,
) -> CompletedResultRequest:
    """Return a completed-result request preserving parsed source context."""
    return CompletedResultRequest(
        source_context=parsed.source_context,
        entry=parsed.entry,
        route_transition=route_transition,
        evidence=evidence or CompletedResultEvidence(),
        source_id=parsed.output_source.source_id,
        source_input_label=parsed.output_source.input_label,
    )


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
        delegation_transition = DelegationRoutingPolicy().for_result(delegation_result)
        if isinstance(delegation_transition, TerminalRouteTransition):
            await self.runtime.put_completed(
                queue_bundle,
                _completed_request(
                    parsed,
                    delegation_transition,
                    CompletedResultEvidence(delegation_result=delegation_result),
                ),
            )
            return
        if parsed.manual_routing.manually_selected_for_filtered:
            await self.runtime.put_completed(
                queue_bundle,
                _completed_request(
                    parsed,
                    ManualRoutingPolicy().selected_for_filtered(),
                    CompletedResultEvidence(delegation_result=delegation_result),
                ),
            )
            return
        if parsed.manual_routing.manually_added:
            await self.runtime.put_completed(
                queue_bundle,
                _completed_request(
                    parsed,
                    ManualRoutingPolicy().manually_added_actionable(),
                    CompletedResultEvidence(delegation_result=delegation_result),
                ),
            )
            return
        host_resolution_config = parsed.source_context.config["host_resolution"]
        if not bool(host_resolution_config.get("enabled", False)):
            await self.runtime.put_completed(
                queue_bundle,
                _completed_request(
                    parsed,
                    HostResolutionRoutingPolicy().skipped(),
                    CompletedResultEvidence(delegation_result=delegation_result),
                ),
            )
            return
        async with self.runtime.busy_state.track(BusyReason.DOWNSTREAM_PUT):
            await queue_bundle.delegation_to_host_resolution.put(
                HostResolutionWorkItem(
                    parsed=parsed,
                    delegation_result=delegation_result,
                    delegation_transition=delegation_transition,
                )
            )


class HostResolutionStage:
    """Own host-resolution queue consumption and routing."""

    def __init__(self, runtime: Any) -> None:
        self.runtime = runtime

    async def consume(self, queue_bundle: RuntimeQueueSet) -> None:
        """Consume host-resolution work and route review, filtered, or IP-location cases."""
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
        ip_location_enabled = bool(
            work_item.parsed.source_context.config["ip_location"].get("enabled", False)
        )
        transition = HostResolutionRoutingPolicy().for_result(
            host_resolution_result,
            ip_location_enabled=ip_location_enabled,
        )
        if isinstance(transition, TerminalRouteTransition):
            await self.runtime.put_completed(
                queue_bundle,
                _completed_request(
                    work_item.parsed,
                    transition,
                    CompletedResultEvidence(
                        delegation_result=work_item.delegation_result,
                        host_resolution_result=host_resolution_result,
                    ),
                ),
            )
            return
        async with self.runtime.busy_state.track(BusyReason.DOWNSTREAM_PUT):
            await queue_bundle.host_resolution_to_ip_location.put(
                IpLocationWorkItem(
                    parsed=work_item.parsed,
                    delegation_result=work_item.delegation_result,
                    host_resolution_result=host_resolution_result,
                    host_resolution_transition=transition,
                )
            )


class IpLocationStage:
    """Own IP-location queue consumption and terminal policy routing."""

    def __init__(self, runtime: Any) -> None:
        self.runtime = runtime

    async def consume(self, queue_bundle: RuntimeQueueSet) -> None:
        """Consume IP-location work and emit terminal policy results."""
        while True:
            async with self.runtime.busy_state.track(BusyReason.QUEUE_WAIT):
                work_item = await queue_bundle.host_resolution_to_ip_location.get()
            try:
                if work_item is None:
                    return
                async with self.runtime.busy_state.track(BusyReason.ITEM_PROCESSING):
                    ip_location_transition, ip_location_results, ip_location_policy = (
                        await self.runtime.lookup_ip_location(
                            work_item.parsed.source_context,
                            work_item.host_resolution_result,
                        )
                    )
                    await self.route(
                        queue_bundle,
                        IpLocationRouteResult(
                            work_item=work_item,
                            route_transition=ip_location_transition,
                            ip_location_results=ip_location_results,
                            ip_location_policy=ip_location_policy,
                        ),
                    )
            finally:
                queue_bundle.host_resolution_to_ip_location.task_done()

    async def route(
        self,
        queue_bundle: RuntimeQueueSet,
        route_result: "IpLocationRouteResult",
    ) -> None:
        """Emit one terminal IP-location policy result."""
        await self.runtime.put_completed(
            queue_bundle,
            _completed_request(
                route_result.work_item.parsed,
                route_result.route_transition,
                CompletedResultEvidence(
                    delegation_result=route_result.work_item.delegation_result,
                    host_resolution_result=(
                        route_result.work_item.host_resolution_result
                    ),
                    ip_location_results=route_result.ip_location_results,
                    ip_location_policy=route_result.ip_location_policy,
                ),
            ),
        )


@dataclasses.dataclass(frozen=True)
class IpLocationRouteResult:
    """IP-location route outcome consumed by the terminal emitter."""

    work_item: IpLocationWorkItem
    route_transition: TerminalRouteTransition
    ip_location_results: list[Any]
    ip_location_policy: Any | None


__all__ = ["DelegationStage", "IpLocationStage", "HostResolutionStage"]
