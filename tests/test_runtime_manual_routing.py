from __future__ import annotations

import pytest

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
from domain_pipeline.worker.runtime.stages import DelegationStage


class DummyRuntime:
    def __init__(self) -> None:
        self.requests: list[object] = []

    async def put_completed(self, queue_bundle, request) -> None:
        self.requests.append(request)


def _parsed(*, manually_selected_for_filtered: bool = False, manually_added: bool = False) -> ParsedHostItem:
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
    return DelegationResult(
        domain="example.com",
        dns=DelegationDnsEvidence(ns_records_exist=True),
        soa=DelegationSoaEvidence(),
        nameservers=["ns1.example.com"],
    )


def _non_actionable_delegation() -> DelegationResult:
    return DelegationResult(
        domain="example.com",
        dns=DelegationDnsEvidence(ns_lookup_error=True),
        soa=DelegationSoaEvidence(),
    )


@pytest.mark.asyncio
async def test_selected_for_filtered_does_not_override_non_actionable_delegation() -> None:
    runtime = DummyRuntime()
    stage = DelegationStage(runtime)
    delegation_result = _non_actionable_delegation()
    parsed = _parsed(manually_selected_for_filtered=True)

    await stage.route(None, parsed, delegation_result)

    assert len(runtime.requests) == 1
    request = runtime.requests[0]
    assert request.route_transition == DelegationRoutingPolicy().for_result(delegation_result)
    assert request.route_transition.route_code == RouteCode.DELEGATION_TO_REVIEW_NS_LOOKUP_ERROR


@pytest.mark.asyncio
async def test_manually_added_does_not_override_non_actionable_delegation() -> None:
    runtime = DummyRuntime()
    stage = DelegationStage(runtime)
    delegation_result = _non_actionable_delegation()
    parsed = _parsed(manually_added=True)

    await stage.route(None, parsed, delegation_result)

    assert len(runtime.requests) == 1
    request = runtime.requests[0]
    assert request.route_transition == DelegationRoutingPolicy().for_result(delegation_result)
    assert request.route_transition.route_code == RouteCode.DELEGATION_TO_REVIEW_NS_LOOKUP_ERROR


@pytest.mark.asyncio
async def test_manual_routes_apply_only_when_delegation_is_actionable() -> None:
    runtime = DummyRuntime()
    stage = DelegationStage(runtime)
    parsed_selected = _parsed(manually_selected_for_filtered=True)
    parsed_added = _parsed(manually_added=True)

    await stage.route(None, parsed_selected, _actionable_delegation())
    await stage.route(None, parsed_added, _actionable_delegation())

    assert len(runtime.requests) == 2
    assert runtime.requests[0].route_transition == ManualRoutingPolicy().selected_for_filtered()
    assert runtime.requests[1].route_transition == ManualRoutingPolicy().manually_added_actionable()
