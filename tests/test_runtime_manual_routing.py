"""Tests for source-blind per-input-domain worker routing."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from domain_pipeline.prepare.sources.parser import DomainEntry
from domain_pipeline.routing.policies import DelegationRoutingPolicy, ManualRoutingPolicy
from domain_pipeline.routing.route_codes import RouteCode
from domain_pipeline.worker.delegation.lookup import (
    DelegationDnsEvidence,
    DelegationResult,
    DelegationSoaEvidence,
)
from domain_pipeline.worker.host_resolution.lookup import selected_host_resolution_names
from domain_pipeline.worker.runtime.contracts import (
    ParsedInputDomain,
    RuntimeItemPosition,
    RuntimeManualRouting,
)
from domain_pipeline.worker.runtime.queues import RuntimeQueueSet
from domain_pipeline.worker.runtime.results import CompletedResultRequest
from domain_pipeline.worker.runtime.stages import DelegationStage


class DummyRuntime:
    """Capture completed requests emitted by a delegation stage."""

    def __init__(self) -> None:
        self.requests: list[CompletedResultRequest] = []
        self.busy_state = DummyBusyState()

    async def put_completed(
        self, queue_bundle: RuntimeQueueSet, request: CompletedResultRequest
    ) -> None:
        """Record a completed request without using downstream queues."""
        _ = queue_bundle
        self.requests.append(request)


class DummyBusyState:
    """Provide no-op tracking for stage queue transitions."""

    @asynccontextmanager
    async def track(self, reason: object):
        _ = reason
        yield


def _parsed(
    *,
    input_domain: str = "www.example.com",
    manually_selected_for_filtered: bool = False,
    manually_added: bool = False,
    host_resolution_enabled: bool = False,
) -> ParsedInputDomain:
    """Build one input-domain work item with explicit routing settings."""
    return ParsedInputDomain(
        entry=DomainEntry(host=input_domain, registrable_domain="example.com"),
        position=RuntimeItemPosition(sequence=0, total=1),
        manual_routing=RuntimeManualRouting(
            manually_selected_for_filtered=manually_selected_for_filtered,
            manually_added=manually_added,
        ),
        host_resolution_profile={"resolve_www_for_registrable_domain": False}
        if host_resolution_enabled
        else None,
    )


def _actionable_delegation() -> DelegationResult:
    """Return a root delegation result eligible for downstream routing."""
    return DelegationResult(
        domain="example.com",
        dns=DelegationDnsEvidence(ns_records_exist=True),
        soa=DelegationSoaEvidence(),
        nameservers=["ns1.example.com"],
    )


def _review_delegation() -> DelegationResult:
    """Return a root result that must take the review route."""
    return DelegationResult(
        domain="example.com",
        dns=DelegationDnsEvidence(ns_lookup_error=True),
        soa=DelegationSoaEvidence(),
    )


def test_manual_selection_does_not_override_root_review_outcome() -> None:
    runtime = DummyRuntime()
    stage = DelegationStage(runtime)
    result = _review_delegation()

    asyncio.run(
        stage.route(
            RuntimeQueueSet.create(),
            _parsed(manually_selected_for_filtered=True),
            result,
        )
    )

    assert len(runtime.requests) == 1
    assert runtime.requests[0].route_transition == DelegationRoutingPolicy().for_result(
        result
    )
    assert (
        runtime.requests[0].route_transition.route_code
        == RouteCode.DELEGATION_TO_REVIEW_NS_LOOKUP_ERROR
    )


def test_manual_addition_does_not_override_root_review_outcome() -> None:
    runtime = DummyRuntime()
    stage = DelegationStage(runtime)
    result = _review_delegation()

    asyncio.run(
        stage.route(
            RuntimeQueueSet.create(), _parsed(manually_added=True), result
        )
    )

    assert len(runtime.requests) == 1
    assert runtime.requests[0].route_transition == DelegationRoutingPolicy().for_result(
        result
    )


def test_manual_routes_apply_after_actionable_root_outcome() -> None:
    runtime = DummyRuntime()
    stage = DelegationStage(runtime)
    queue_bundle = RuntimeQueueSet.create()

    asyncio.run(
        stage.route(
            queue_bundle,
            _parsed(manually_selected_for_filtered=True),
            _actionable_delegation(),
        )
    )
    asyncio.run(
        stage.route(
            queue_bundle,
            _parsed(manually_added=True),
            _actionable_delegation(),
        )
    )

    assert [request.route_transition for request in runtime.requests] == [
        ManualRoutingPolicy().selected_for_filtered(),
        ManualRoutingPolicy().manually_added_actionable(),
    ]


def test_host_disabled_route_is_filtered_and_host_enabled_is_queued() -> None:
    runtime = DummyRuntime()
    stage = DelegationStage(runtime)
    queue_bundle = RuntimeQueueSet.create()
    result = _actionable_delegation()

    asyncio.run(stage.route(queue_bundle, _parsed(), result))
    asyncio.run(
        stage.route(
            queue_bundle,
            _parsed(host_resolution_enabled=True),
            result,
        )
    )

    assert len(runtime.requests) == 1
    assert runtime.requests[0].route_transition.route_code == (
        RouteCode.HOST_RESOLUTION_TO_FILTERED_SKIPPED
    )
    queued = queue_bundle.delegation_to_host_resolution.get_nowait()
    assert queued.parsed.entry.host == "www.example.com"


def test_selected_dns_names_follow_root_only_www_policy() -> None:
    assert selected_host_resolution_names(
        input_domain="example.com",
        registrable_domain="example.com",
        resolve_www_for_registrable_domain=True,
    ) == ["example.com", "www.example.com"]
    assert selected_host_resolution_names(
        input_domain="example.com",
        registrable_domain="example.com",
        resolve_www_for_registrable_domain=False,
    ) == ["example.com"]
    assert selected_host_resolution_names(
        input_domain="ads.example.com",
        registrable_domain="example.com",
        resolve_www_for_registrable_domain=True,
    ) == ["ads.example.com"]
