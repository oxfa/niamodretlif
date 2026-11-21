"""Tests for manual routing behavior in the worker runtime."""

from __future__ import annotations

import asyncio

from domain_pipeline.prepare.sources.parser import DomainEntry
from domain_pipeline.routing.policies import DelegationRoutingPolicy, ManualRoutingPolicy
from domain_pipeline.routing.route_codes import RouteCode
from domain_pipeline.worker.delegation.lookup import (
    DelegationDnsEvidence,
    DelegationResult,
    DelegationSoaEvidence,
)
from domain_pipeline.worker.runtime.contracts import (
    ParsedHostItem,
    RuntimeItemPosition,
    RuntimeManualRouting,
    RuntimeOutputSource,
    WorkerSourceContext,
)
from domain_pipeline.worker.runtime.queues import RuntimeQueueSet
from domain_pipeline.worker.runtime.results import CompletedResultRequest
from domain_pipeline.worker.runtime.stages import DelegationStage


class DummyRuntime:
    """Capture completed requests emitted by a delegation stage."""

    def __init__(self) -> None:
        self.requests: list[CompletedResultRequest] = []

    async def put_completed(
        self, queue_bundle: RuntimeQueueSet, request: CompletedResultRequest
    ) -> None:
        """Record a completed request without using the downstream queues."""
        _ = queue_bundle
        self.requests.append(request)

    def completed_requests(self) -> list[CompletedResultRequest]:
        """Return requests captured during the test."""
        return self.requests


def _parsed(
    *, manually_selected_for_filtered: bool = False, manually_added: bool = False
) -> ParsedHostItem:
    """Build a parsed host with the requested manual-routing flags."""
    return ParsedHostItem(
        source_context=WorkerSourceContext(
            source_id="source",
            input_label="input",
            output_stem="output",
            config={"host_resolution": {"enabled": False}},
        ),
        entry=DomainEntry(host="www.example.com", registrable_domain="example.com"),
        position=RuntimeItemPosition(sequence=1, total=1),
        output_source=RuntimeOutputSource(source_id="source", input_label="input"),
        manual_routing=RuntimeManualRouting(
            manually_selected_for_filtered=manually_selected_for_filtered,
            manually_added=manually_added,
        ),
    )


def _actionable_delegation() -> DelegationResult:
    """Return a delegation result eligible for manual routing."""
    return DelegationResult(
        domain="example.com",
        dns=DelegationDnsEvidence(ns_records_exist=True),
        soa=DelegationSoaEvidence(),
        nameservers=["ns1.example.com"],
    )


def _non_actionable_delegation() -> DelegationResult:
    """Return a delegation result that must follow its normal review route."""
    return DelegationResult(
        domain="example.com",
        dns=DelegationDnsEvidence(ns_lookup_error=True),
        soa=DelegationSoaEvidence(),
    )


def test_selected_for_filtered_does_not_override_non_actionable_delegation() -> None:
    """A manual selection cannot override a non-actionable delegation result."""
    runtime = DummyRuntime()
    stage = DelegationStage(runtime)
    delegation_result = _non_actionable_delegation()
    parsed = _parsed(manually_selected_for_filtered=True)

    asyncio.run(stage.route(RuntimeQueueSet.create(), parsed, delegation_result))

    assert len(runtime.completed_requests()) == 1
    request = runtime.completed_requests()[0]
    assert request.route_transition == DelegationRoutingPolicy().for_result(
        delegation_result
    )
    assert request.route_transition.route_code == RouteCode.DELEGATION_TO_REVIEW_NS_LOOKUP_ERROR


def test_manually_added_does_not_override_non_actionable_delegation() -> None:
    """Manual additions cannot override a non-actionable delegation result."""
    runtime = DummyRuntime()
    stage = DelegationStage(runtime)
    delegation_result = _non_actionable_delegation()
    parsed = _parsed(manually_added=True)

    asyncio.run(stage.route(RuntimeQueueSet.create(), parsed, delegation_result))

    assert len(runtime.completed_requests()) == 1
    request = runtime.completed_requests()[0]
    assert request.route_transition == DelegationRoutingPolicy().for_result(
        delegation_result
    )
    assert request.route_transition.route_code == RouteCode.DELEGATION_TO_REVIEW_NS_LOOKUP_ERROR


def test_manual_routes_apply_only_when_delegation_is_actionable() -> None:
    """Manual routing transitions apply to actionable delegation results."""
    runtime = DummyRuntime()
    stage = DelegationStage(runtime)
    parsed_selected = _parsed(manually_selected_for_filtered=True)
    parsed_added = _parsed(manually_added=True)

    queue_bundle = RuntimeQueueSet.create()
    asyncio.run(
        stage.route(queue_bundle, parsed_selected, _actionable_delegation())
    )
    asyncio.run(stage.route(queue_bundle, parsed_added, _actionable_delegation()))

    requests = runtime.completed_requests()
    assert len(requests) == 2
    assert (
        requests[0].route_transition
        == ManualRoutingPolicy().selected_for_filtered()
    )
    assert (
        requests[1].route_transition
        == ManualRoutingPolicy().manually_added_actionable()
    )
