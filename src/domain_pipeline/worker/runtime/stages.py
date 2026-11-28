"""Worker runtime stage owners for root and input-domain decisions."""

from __future__ import annotations

import dataclasses
from typing import Any

from domain_pipeline.routing import (
    DelegationRoutingPolicy,
    HostResolutionRoutingPolicy,
    ManualRoutingPolicy,
    TerminalRouteTransition,
)
from domain_pipeline.worker.delegation.lookup import DelegationResult
from domain_pipeline.worker.host_resolution.lookup import HostResolutionResult
from domain_pipeline.worker.runtime.busy_state import BusyReason
from domain_pipeline.worker.runtime.contracts import (
    CompletedResultEvidence,
    DelegationRootWorkItem,
    HostResolutionWorkItem,
    IpLocationWorkItem,
    ParsedInputDomain,
    RegistrableDomainResult,
)
from domain_pipeline.worker.runtime.queues import RuntimeQueueSet
from domain_pipeline.worker.runtime.results import CompletedResultRequest


def _completed_request(
    parsed: ParsedInputDomain,
    route_transition: TerminalRouteTransition,
    evidence: CompletedResultEvidence | None = None,
) -> CompletedResultRequest:
    """Return a completed result request for one input domain."""
    return CompletedResultRequest(
        entry=parsed.entry,
        route_transition=route_transition,
        evidence=evidence or CompletedResultEvidence(),
    )


class DelegationStage:
    """Own one root lookup, result emission, and source-blind domain fanout."""

    def __init__(self, runtime: Any) -> None:
        self.runtime = runtime

    async def consume(self, queue_bundle: RuntimeQueueSet) -> None:
        """Consume root work, emit one root result, then route every input domain."""
        while True:
            async with self.runtime.busy_state.track(BusyReason.QUEUE_WAIT):
                work_item = await queue_bundle.delegation_input.get()
            try:
                if work_item is None:
                    return
                async with self.runtime.busy_state.track(BusyReason.ITEM_PROCESSING):
                    delegation_result = await self.runtime.lookup_delegation_root(
                        work_item.delegation_profile,
                        work_item.registrable_domain,
                    )
                    delegation_transition = DelegationRoutingPolicy().for_result(
                        delegation_result
                    )
                    disposition = (
                        "actionable"
                        if not isinstance(
                            delegation_transition, TerminalRouteTransition
                        )
                        else delegation_transition.route
                    )
                    await self.runtime.put_root_result(
                        queue_bundle,
                        RegistrableDomainResult(
                            registrable_domain=work_item.registrable_domain,
                            disposition=disposition,
                            delegation_result=delegation_result,
                        ),
                    )
                    await self.route_root(
                        queue_bundle,
                        work_item,
                        delegation_result,
                        delegation_transition,
                    )
            finally:
                queue_bundle.delegation_input.task_done()

    async def route_root(
        self,
        queue_bundle: RuntimeQueueSet,
        work_item: DelegationRootWorkItem,
        delegation_result: DelegationResult,
        delegation_transition: Any,
    ) -> None:
        """Fan one root outcome out to every assigned input domain."""
        self.runtime.log_delegation_fanout(
            work_item.registrable_domain, len(work_item.items)
        )
        for parsed in work_item.items:
            await self.route(
                queue_bundle,
                parsed,
                delegation_result,
                delegation_transition,
            )

    async def route(
        self,
        queue_bundle: RuntimeQueueSet,
        parsed: ParsedInputDomain,
        delegation_result: DelegationResult,
        delegation_transition: Any | None = None,
    ) -> None:
        """Apply root outcome first, then manual or per-domain stage routing."""
        transition = delegation_transition or DelegationRoutingPolicy().for_result(
            delegation_result
        )
        evidence = CompletedResultEvidence(delegation_result=delegation_result)
        if isinstance(transition, TerminalRouteTransition):
            await self.runtime.put_completed(
                queue_bundle,
                _completed_request(parsed, transition, evidence),
            )
            return

        if parsed.manual_routing.manually_selected_for_filtered:
            await self.runtime.put_completed(
                queue_bundle,
                _completed_request(
                    parsed,
                    ManualRoutingPolicy().selected_for_filtered(),
                    evidence,
                ),
            )
            return
        if parsed.manual_routing.manually_added:
            await self.runtime.put_completed(
                queue_bundle,
                _completed_request(
                    parsed,
                    ManualRoutingPolicy().manually_added_actionable(),
                    evidence,
                ),
            )
            return
        if parsed.host_resolution_profile is None:
            await self.runtime.put_completed(
                queue_bundle,
                _completed_request(
                    parsed,
                    HostResolutionRoutingPolicy().skipped(),
                    evidence,
                ),
            )
            return

        async with self.runtime.busy_state.track(BusyReason.DOWNSTREAM_PUT):
            await queue_bundle.delegation_to_host_resolution.put(
                HostResolutionWorkItem(
                    parsed=parsed,
                    delegation_result=delegation_result,
                    delegation_transition=transition,
                )
            )


class HostResolutionStage:
    """Own host-resolution lookups and IP-stage routing for input domains."""

    def __init__(self, runtime: Any) -> None:
        self.runtime = runtime

    async def consume(self, queue_bundle: RuntimeQueueSet) -> None:
        """Resolve selected names for each input domain and route the combined result."""
        while True:
            async with self.runtime.busy_state.track(BusyReason.QUEUE_WAIT):
                work_item = await queue_bundle.delegation_to_host_resolution.get()
            try:
                if work_item is None:
                    return
                async with self.runtime.busy_state.track(BusyReason.ITEM_PROCESSING):
                    host_resolution_result, host_resolution_results = (
                        await self.runtime.lookup_host_resolution(work_item.parsed)
                    )
                    await self.route(
                        queue_bundle,
                        work_item,
                        host_resolution_result,
                        host_resolution_results,
                    )
            finally:
                queue_bundle.delegation_to_host_resolution.task_done()

    async def route(
        self,
        queue_bundle: RuntimeQueueSet,
        work_item: HostResolutionWorkItem,
        host_resolution_result: HostResolutionResult,
        host_resolution_results: list[HostResolutionResult],
    ) -> None:
        """Route the combined input-domain DNS outcome to IP location or terminal."""
        ip_location_enabled = work_item.parsed.ip_location_profile is not None
        transition = HostResolutionRoutingPolicy().for_result(
            host_resolution_result,
            ip_location_enabled=ip_location_enabled,
        )
        evidence = CompletedResultEvidence(
            delegation_result=work_item.delegation_result,
            host_resolution_results=host_resolution_results,
            host_resolution_result=host_resolution_result,
        )
        if isinstance(transition, TerminalRouteTransition):
            await self.runtime.put_completed(
                queue_bundle,
                _completed_request(work_item.parsed, transition, evidence),
            )
            return
        async with self.runtime.busy_state.track(BusyReason.DOWNSTREAM_PUT):
            await queue_bundle.host_resolution_to_ip_location.put(
                IpLocationWorkItem(
                    parsed=work_item.parsed,
                    delegation_result=work_item.delegation_result,
                    host_resolution_result=host_resolution_result,
                    host_resolution_results=host_resolution_results,
                    host_resolution_transition=transition,
                )
            )


class IpLocationStage:
    """Own IP-location lookups and final input-domain policy routes."""

    def __init__(self, runtime: Any) -> None:
        self.runtime = runtime

    async def consume(self, queue_bundle: RuntimeQueueSet) -> None:
        """Consume resolved input domains and emit policy outcomes."""
        while True:
            async with self.runtime.busy_state.track(BusyReason.QUEUE_WAIT):
                work_item = await queue_bundle.host_resolution_to_ip_location.get()
            try:
                if work_item is None:
                    return
                async with self.runtime.busy_state.track(BusyReason.ITEM_PROCESSING):
                    ip_location_transition, ip_location_results, ip_location_policy = (
                        await self.runtime.lookup_ip_location(
                            work_item.parsed,
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
        """Emit the final route with evidence from stages actually run."""
        await self.runtime.put_completed(
            queue_bundle,
            _completed_request(
                route_result.work_item.parsed,
                route_result.route_transition,
                CompletedResultEvidence(
                    delegation_result=route_result.work_item.delegation_result,
                    host_resolution_results=(
                        route_result.work_item.host_resolution_results
                    ),
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
    """IP-location route and evidence consumed by terminal result emission."""

    work_item: IpLocationWorkItem
    route_transition: TerminalRouteTransition
    ip_location_results: list[Any]
    ip_location_policy: Any | None


__all__ = ["DelegationStage", "IpLocationStage", "HostResolutionStage"]
