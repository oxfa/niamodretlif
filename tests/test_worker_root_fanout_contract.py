"""Contract coverage for root-level delegation lookup and input-domain fanout."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from domain_pipeline.prepare.sources.parser import DomainEntry
from domain_pipeline.routing.policies import DelegationRoutingPolicy
from domain_pipeline.routing.route_codes import RouteCode
from domain_pipeline.worker.delegation.lookup import (
    DelegationDnsEvidence,
    DelegationResult,
    DelegationSoaEvidence,
)
from domain_pipeline.worker.runtime.contracts import (
    DelegationRootWorkItem,
    ParsedInputDomain,
    RegistrableDomainResult,
    RuntimeItemPosition,
    RuntimeManualRouting,
)
from domain_pipeline.worker.runtime.queues import RuntimeQueueSet
from domain_pipeline.worker.runtime.results import CompletedResultRequest
from domain_pipeline.worker.runtime.stages import DelegationStage


class _DummyBusyState:
    """Provide no-op tracking for the delegation stage."""

    @asynccontextmanager
    async def track(self, reason: object):
        _ = reason
        yield


class _DummyRuntime:
    """Capture root lookups and result emissions from the delegation stage."""

    def __init__(self, delegation_result: DelegationResult) -> None:
        self.delegation_result = delegation_result
        self.busy_state = _DummyBusyState()
        self.lookup_calls: list[tuple[dict[str, object], str]] = []
        self.root_results: list[RegistrableDomainResult] = []
        self.completed_requests: list[CompletedResultRequest] = []

    async def lookup_delegation_root(
        self, delegation_profile: dict[str, object], registrable_domain: str
    ) -> DelegationResult:
        self.lookup_calls.append((delegation_profile, registrable_domain))
        return self.delegation_result

    async def put_root_result(
        self, queue_bundle: RuntimeQueueSet, result: RegistrableDomainResult
    ) -> None:
        _ = queue_bundle
        self.root_results.append(result)

    async def put_completed(
        self, queue_bundle: RuntimeQueueSet, request: CompletedResultRequest
    ) -> None:
        _ = queue_bundle
        self.completed_requests.append(request)

    def log_delegation_fanout(
        self, registrable_domain: str, item_count: int
    ) -> None:
        _ = registrable_domain, item_count


def _parsed(
    input_domain: str,
    *,
    sequence: int,
    total: int,
    manually_selected_for_filtered: bool = False,
    manually_added: bool = False,
) -> ParsedInputDomain:
    return ParsedInputDomain(
        entry=DomainEntry(host=input_domain, registrable_domain="example.com"),
        position=RuntimeItemPosition(sequence=sequence, total=total),
        manual_routing=RuntimeManualRouting(
            manually_selected_for_filtered=manually_selected_for_filtered,
            manually_added=manually_added,
        ),
    )


def _actionable_result() -> DelegationResult:
    return DelegationResult(
        domain="example.com",
        dns=DelegationDnsEvidence(ns_records_exist=True),
        soa=DelegationSoaEvidence(),
        nameservers=["ns1.example.com"],
    )


def _review_result() -> DelegationResult:
    return DelegationResult(
        domain="example.com",
        dns=DelegationDnsEvidence(ns_lookup_error=True),
        soa=DelegationSoaEvidence(),
    )


def _consume(
    delegation_result: DelegationResult,
    items: tuple[ParsedInputDomain, ...],
) -> _DummyRuntime:
    async def run() -> _DummyRuntime:
        runtime = _DummyRuntime(delegation_result)
        queue_bundle = RuntimeQueueSet.create()
        await queue_bundle.delegation_input.put(
            DelegationRootWorkItem(
                registrable_domain="example.com",
                delegation_profile={"profile": "test"},
                items=items,
            )
        )
        await queue_bundle.delegation_input.put(None)
        await DelegationStage(runtime).consume(queue_bundle)
        return runtime

    return asyncio.run(run())


def test_consume_looks_up_one_root_and_fans_out_to_each_input_domain() -> None:
    result = _actionable_result()
    items = (
        _parsed(
            "www.example.com",
            sequence=0,
            total=2,
            manually_selected_for_filtered=True,
        ),
        _parsed("shop.example.com", sequence=1, total=2),
    )

    runtime = _consume(result, items)

    assert runtime.lookup_calls == [({"profile": "test"}, "example.com")]
    assert len(runtime.root_results) == 1
    root_result = runtime.root_results[0]
    assert root_result.registrable_domain == "example.com"
    assert root_result.disposition == "actionable"
    assert root_result.delegation_result is result

    assert {request.entry.host for request in runtime.completed_requests} == {
        "www.example.com",
        "shop.example.com",
    }
    assert len(runtime.completed_requests) == len(items)
    assert all(
        request.evidence.delegation_result is result
        for request in runtime.completed_requests
    )
    assert next(
        request
        for request in runtime.completed_requests
        if request.entry.host == "www.example.com"
    ).route_transition.route_code == (
        RouteCode.MANUALLY_SELECTED_FOR_FILTERED_TO_FILTERED
    )
    assert next(
        request
        for request in runtime.completed_requests
        if request.entry.host == "shop.example.com"
    ).route_transition.route_code == RouteCode.HOST_RESOLUTION_TO_FILTERED_SKIPPED


def test_terminal_root_outcome_takes_precedence_over_manual_routing() -> None:
    result = _review_result()
    items = (
        _parsed(
            "www.example.com",
            sequence=0,
            total=2,
            manually_selected_for_filtered=True,
        ),
        _parsed(
            "shop.example.com",
            sequence=1,
            total=2,
            manually_added=True,
        ),
    )

    runtime = _consume(result, items)
    terminal_transition = DelegationRoutingPolicy().for_result(result)

    assert len(runtime.lookup_calls) == 1
    assert len(runtime.root_results) == 1
    assert runtime.root_results[0].delegation_result is result
    assert runtime.root_results[0].disposition == terminal_transition.route
    assert len(runtime.completed_requests) == len(items)
    assert all(
        request.route_transition == terminal_transition
        for request in runtime.completed_requests
    )
    assert all(
        request.evidence.delegation_result is result
        for request in runtime.completed_requests
    )
