"""Contract coverage for selected host names and combined host outcomes."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import pytest

from domain_pipeline.prepare.sources.parser import DomainEntry
from domain_pipeline.routing.policies import DelegationRoutingPolicy
from domain_pipeline.routing.route_codes import RouteCode, StageRouteTransition
from domain_pipeline.worker.delegation.lookup import (
    DelegationDnsEvidence,
    DelegationResult,
    DelegationSoaEvidence,
)
from domain_pipeline.worker.host_resolution.lookup import (
    HostResolutionAddressEvidence,
    HostResolutionDnsEvidence,
    HostResolutionResult,
    combine_host_resolution_results,
    selected_host_resolution_names,
)
from domain_pipeline.worker.runtime.contracts import (
    HostResolutionWorkItem,
    ParsedInputDomain,
    RuntimeItemPosition,
)
from domain_pipeline.worker.runtime.queues import RuntimeQueueSet
from domain_pipeline.worker.runtime.results import CompletedResultRequest
from domain_pipeline.worker.runtime.stages import HostResolutionStage


class _DummyBusyState:
    """Provide no-op tracking for the stage-to-stage route."""

    @asynccontextmanager
    async def track(self, reason: object):
        _ = reason
        yield


class _DummyRuntime:
    """Capture terminal results emitted by the host-resolution stage."""

    def __init__(self) -> None:
        self.requests: list[CompletedResultRequest] = []
        self.busy_state = _DummyBusyState()

    async def put_completed(
        self, queue_bundle: RuntimeQueueSet, request: CompletedResultRequest
    ) -> None:
        _ = queue_bundle
        self.requests.append(request)


def _delegation_result() -> DelegationResult:
    """Return an actionable root result for constructing stage work."""
    return DelegationResult(
        domain="example.com",
        dns=DelegationDnsEvidence(ns_records_exist=True),
        soa=DelegationSoaEvidence(),
        nameservers=["ns1.example.com"],
    )


def _status_result(status: str) -> HostResolutionResult:
    """Build an exact-host result with no address data and one status flag."""
    evidence_by_status = {
        "timeout": HostResolutionDnsEvidence(a_timeout=True),
        "servfail": HostResolutionDnsEvidence(a_servfail=True),
        "nxdomain": HostResolutionDnsEvidence(a_nxdomain=True),
        "nodata": HostResolutionDnsEvidence(a_nodata=True),
        "unknown": HostResolutionDnsEvidence(),
    }
    return HostResolutionResult(
        host=f"{status}.example.com",
        dns=evidence_by_status[status],
    )


def _parsed_input_domain(*, ip_location_enabled: bool) -> ParsedInputDomain:
    return ParsedInputDomain(
        entry=DomainEntry(host="ads.example.com", registrable_domain="example.com"),
        position=RuntimeItemPosition(sequence=0, total=1),
        host_resolution_profile={"resolve_www_for_registrable_domain": True},
        ip_location_profile={"enabled": True} if ip_location_enabled else None,
    )


def test_selected_names_add_www_only_for_the_root_input() -> None:
    assert selected_host_resolution_names(
        input_domain="example.com",
        registrable_domain="example.com",
        resolve_www_for_registrable_domain=True,
    ) == ["example.com", "www.example.com"]

    assert selected_host_resolution_names(
        input_domain="ads.example.com",
        registrable_domain="example.com",
        resolve_www_for_registrable_domain=True,
    ) == ["ads.example.com"]


def test_combined_addresses_are_unioned_and_deduplicated() -> None:
    root_result = HostResolutionResult(
        host="example.com",
        dns=HostResolutionDnsEvidence(a_exists=True),
        addresses=HostResolutionAddressEvidence(
            ipv4_addresses=["192.0.2.8", "192.0.2.8", "198.51.100.4"],
            ipv6_addresses=["2001:db8::2"],
        ),
    )
    www_result = HostResolutionResult(
        host="www.example.com",
        dns=HostResolutionDnsEvidence(a_exists=True),
        addresses=HostResolutionAddressEvidence(
            ipv4_addresses=["192.0.2.8", "203.0.113.9"],
            ipv6_addresses=["2001:db8::1", "2001:db8::2"],
        ),
    )

    combined = combine_host_resolution_results(
        "example.com", [root_result, www_result]
    )

    assert combined.host == "example.com"
    assert combined.status == "resolved"
    assert combined.ipv4_addresses == [
        "192.0.2.8",
        "198.51.100.4",
        "203.0.113.9",
    ]
    assert combined.ipv6_addresses == ["2001:db8::1", "2001:db8::2"]


def test_any_combined_address_overrides_an_addressless_dns_failure() -> None:
    resolved = HostResolutionResult(
        host="example.com",
        dns=HostResolutionDnsEvidence(a_exists=True),
        addresses=HostResolutionAddressEvidence(
            ipv4_addresses=["192.0.2.8"],
        ),
    )

    combined = combine_host_resolution_results(
        "example.com", [resolved, _status_result("nxdomain")]
    )

    assert combined.status == "resolved"
    assert combined.resolved_ips == ["192.0.2.8"]


@pytest.mark.parametrize(
    ("statuses", "expected_status"),
    [
        (["timeout", "servfail", "nxdomain", "nodata"], "timeout"),
        (["servfail", "nxdomain", "nodata"], "servfail"),
        (["nxdomain", "nodata"], "nxdomain"),
        (["nodata"], "nodata"),
        (["unknown"], "unknown"),
    ],
)
def test_no_address_combination_preserves_failure_precedence(
    statuses: list[str], expected_status: str
) -> None:
    combined = combine_host_resolution_results(
        "example.com", [_status_result(status) for status in statuses]
    )

    assert combined.status == expected_status


@pytest.mark.parametrize(
    ("ip_location_enabled", "expected_route_code"),
    [
        (False, RouteCode.HOST_RESOLUTION_TO_FILTERED_RESOLVES),
        (True, RouteCode.HOST_RESOLUTION_TO_IP_LOCATION_RESOLVES),
    ],
)
def test_resolved_host_routes_according_to_ip_location_setting(
    ip_location_enabled: bool,
    expected_route_code: RouteCode,
) -> None:
    runtime = _DummyRuntime()
    queue_bundle = RuntimeQueueSet.create()
    parsed = _parsed_input_domain(ip_location_enabled=ip_location_enabled)
    delegation_result = _delegation_result()
    delegation_transition = DelegationRoutingPolicy().for_result(delegation_result)
    assert isinstance(delegation_transition, StageRouteTransition)
    work_item = HostResolutionWorkItem(
        parsed=parsed,
        delegation_result=delegation_result,
        delegation_transition=delegation_transition,
    )
    host_result = HostResolutionResult(
        host=parsed.entry.host,
        dns=HostResolutionDnsEvidence(a_exists=True),
        addresses=HostResolutionAddressEvidence(
            ipv4_addresses=["192.0.2.8"],
        ),
    )

    asyncio.run(
        HostResolutionStage(runtime).route(
            queue_bundle,
            work_item,
            host_result,
            [host_result],
        )
    )

    if ip_location_enabled:
        queued = queue_bundle.host_resolution_to_ip_location.get_nowait()
        assert queued.parsed.entry.host == "ads.example.com"
        assert queued.host_resolution_result is host_result
        assert queued.host_resolution_transition.route_code == expected_route_code
        assert runtime.requests == []
    else:
        assert queue_bundle.host_resolution_to_ip_location.empty()
        assert len(runtime.requests) == 1
        completed = runtime.requests[0]
        assert completed.entry.host == "ads.example.com"
        assert completed.route_transition.route_code == expected_route_code
        assert completed.evidence.host_resolution_result is host_result
        assert completed.evidence.host_resolution_results == [host_result]
