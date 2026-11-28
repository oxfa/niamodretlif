"""Focused checks for the baseline worker delegation DNS contract."""

from __future__ import annotations

import socket
from types import SimpleNamespace

import dns.exception
import dns.message
import dns.name
import dns.rcode
import dns.resolver
import dns.rrset
import dns.rdatatype
import pytest

from domain_pipeline.routing.policies import DelegationRoutingPolicy
from domain_pipeline.routing.route_codes import (
    RouteCode,
    RouteDestination,
    StageRouteTransition,
    TerminalRouteTransition,
)
from domain_pipeline.worker.delegation.lookup import (
    DelegationChecker,
    DelegationCheckerRequest,
    DelegationDnsEvidence,
    DelegationResult,
    DelegationSoaEvidence,
)
from domain_pipeline.worker.dns_query.lookup import (
    RetryableDNSLookupError,
)


DOMAIN = "example.com"


@pytest.fixture
def checker() -> DelegationChecker:
    """Build a checker whose DNS calls are replaced by each focused test."""
    return DelegationChecker(DelegationCheckerRequest(delegation_retry_attempts=2))


def _patch_lookup(
    monkeypatch: pytest.MonkeyPatch,
    checker: DelegationChecker,
    outcomes: list[object],
) -> list[tuple[str, str, int]]:
    """Record lookup order and return or raise the supplied outcomes."""
    calls: list[tuple[str, str, int]] = []

    def resolve(domain: str, record_type: str, retry_attempts: int) -> object:
        calls.append((domain, record_type, retry_attempts))
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(checker, "_resolve_delegation_record", resolve)
    return calls


def _nxdomain_without_response(domain: str) -> dns.resolver.NXDOMAIN:
    """Build an NXDOMAIN exception with no reusable NS authority response."""
    qname = dns.name.from_text(domain)
    return dns.resolver.NXDOMAIN(qnames=[qname], responses={})


def _nxdomain_with_authority_soa(
    domain: str, soa_owner: str
) -> dns.resolver.NXDOMAIN:
    """Build an NS NXDOMAIN response with the requested authority SOA owner."""
    query = dns.message.make_query(domain, "NS")
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.NXDOMAIN)
    response.authority.append(
        dns.rrset.from_text(
            soa_owner,
            300,
            "IN",
            "SOA",
            "ns1.example.net. hostmaster.example.net. 1 3600 600 86400 60",
        )
    )
    qname = query.question[0].name
    return dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: response})


def _soa_answer(domain: str) -> SimpleNamespace:
    """Return an answer-shaped value with an exact-owner SOA RRset."""
    return SimpleNamespace(
        rrset=SimpleNamespace(
            rdtype=dns.rdatatype.SOA,
            name=dns.name.from_text(domain),
        )
    )


def test_delegation_lookup_queries_ns_first_and_stops_after_ns_answer(
    checker: DelegationChecker, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _patch_lookup(
        monkeypatch,
        checker,
        [[SimpleNamespace(target="NS1.EXAMPLE.NET.")]],
    )

    result = checker.delegation_lookup(DOMAIN)

    assert calls == [(DOMAIN, "NS", 2)]
    assert result.status == "ns_records_exist"
    assert result.nameservers == ["ns1.example.net"]


@pytest.mark.parametrize(
    ("outcome_kind", "expected_status"),
    [
        ("nodata", "ns_nodata"),
        ("empty_answer", "ns_empty_answer"),
        ("dns_error", "ns_lookup_error"),
        ("socket_error", "ns_lookup_error"),
    ],
)
def test_ns_outcomes_other_than_nxdomain_or_retry_exhaustion_skip_soa(
    checker: DelegationChecker,
    monkeypatch: pytest.MonkeyPatch,
    outcome_kind: str,
    expected_status: str,
) -> None:
    outcome: object
    if outcome_kind == "nodata":
        outcome = dns.resolver.NoAnswer()
    elif outcome_kind == "empty_answer":
        outcome = []
    elif outcome_kind == "dns_error":
        outcome = dns.exception.DNSException("handled DNS failure")
    else:
        outcome = socket.gaierror("handled socket failure")
    calls = _patch_lookup(monkeypatch, checker, [outcome])

    result = checker.delegation_lookup(DOMAIN)

    assert calls == [(DOMAIN, "NS", 2)]
    assert result.status == expected_status


@pytest.mark.parametrize(
    ("ns_failure", "expected_status"),
    [
        ("nxdomain", "ns_nxdomain_soa_exists"),
        ("retry_exhausted", "ns_retry_exhausted_soa_exists"),
    ],
)
def test_ns_nxdomain_and_retry_exhaustion_trigger_soa_fallback(
    checker: DelegationChecker,
    monkeypatch: pytest.MonkeyPatch,
    ns_failure: str,
    expected_status: str,
) -> None:
    ns_outcome: Exception = (
        _nxdomain_without_response(DOMAIN)
        if ns_failure == "nxdomain"
        else RetryableDNSLookupError("NS retry budget exhausted")
    )
    calls = _patch_lookup(monkeypatch, checker, [ns_outcome, _soa_answer(DOMAIN)])

    result = checker.delegation_lookup(DOMAIN)

    assert calls == [(DOMAIN, "NS", 2), (DOMAIN, "SOA", 2)]
    assert result.status == expected_status
    assert result.soa_source == "soa_query"


def test_ns_nxdomain_reuses_same_owner_authority_soa(
    checker: DelegationChecker, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _patch_lookup(
        monkeypatch,
        checker,
        [_nxdomain_with_authority_soa(DOMAIN, "EXAMPLE.COM.")],
    )

    result = checker.delegation_lookup(DOMAIN)
    transition = DelegationRoutingPolicy().for_result(result)

    assert calls == [(DOMAIN, "NS", 2)]
    assert result.status == "ns_nxdomain_soa_exists"
    assert result.soa_source == "ns_authority"
    assert isinstance(transition, StageRouteTransition)
    assert transition.destination == RouteDestination.HOST_RESOLUTION
    assert transition.route_code == (
        RouteCode.DELEGATION_TO_HOST_RESOLUTION_NS_NXDOMAIN_SOA_EXISTS
    )


def test_ns_nxdomain_with_parent_soa_uses_fallback_and_can_be_unactionable(
    checker: DelegationChecker, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _patch_lookup(
        monkeypatch,
        checker,
        [
            _nxdomain_with_authority_soa(DOMAIN, "com."),
            dns.resolver.NoAnswer(),
        ],
    )

    result = checker.delegation_lookup(DOMAIN)
    transition = DelegationRoutingPolicy().for_result(result)

    assert calls == [(DOMAIN, "NS", 2), (DOMAIN, "SOA", 2)]
    assert result.status == "ns_nxdomain_soa_absent"
    assert isinstance(transition, TerminalRouteTransition)
    assert transition.destination == RouteDestination.UNACTIONABLE
    assert transition.route == "unactionable"
    assert transition.route_code == (
        RouteCode.DELEGATION_TO_UNACTIONABLE_NS_NXDOMAIN_SOA_ABSENT
    )


def test_retry_exhausted_soa_fallback_maps_to_review(
    checker: DelegationChecker, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _patch_lookup(
        monkeypatch,
        checker,
        [
            _nxdomain_without_response(DOMAIN),
            RetryableDNSLookupError("SOA retry budget exhausted"),
        ],
    )

    result = checker.delegation_lookup(DOMAIN)
    transition = DelegationRoutingPolicy().for_result(result)

    assert calls == [(DOMAIN, "NS", 2), (DOMAIN, "SOA", 2)]
    assert result.status == "ns_nxdomain_soa_retry_exhausted"
    assert isinstance(transition, TerminalRouteTransition)
    assert transition.destination == RouteDestination.REVIEW
    assert transition.route == "review"
    assert transition.route_code == (
        RouteCode.DELEGATION_TO_REVIEW_NS_NXDOMAIN_SOA_RETRY_EXHAUSTED
    )


def test_unexpected_soa_fallback_error_propagates(
    checker: DelegationChecker, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _patch_lookup(
        monkeypatch,
        checker,
        [
            _nxdomain_without_response(DOMAIN),
            ValueError("unexpected SOA failure"),
        ],
    )

    with pytest.raises(ValueError, match="unexpected SOA failure"):
        checker.delegation_lookup(DOMAIN)

    assert calls == [(DOMAIN, "NS", 2), (DOMAIN, "SOA", 2)]


@pytest.mark.parametrize(
    ("result", "transition_type", "destination", "route_code", "route"),
    [
        (
            DelegationResult(
                domain=DOMAIN,
                dns=DelegationDnsEvidence(ns_records_exist=True),
                nameservers=["ns1.example.net"],
            ),
            StageRouteTransition,
            RouteDestination.HOST_RESOLUTION,
            RouteCode.DELEGATION_TO_HOST_RESOLUTION_NS_RECORDS_EXIST,
            None,
        ),
        (
            DelegationResult(
                domain=DOMAIN,
                dns=DelegationDnsEvidence(ns_nodata=True),
            ),
            StageRouteTransition,
            RouteDestination.HOST_RESOLUTION,
            RouteCode.DELEGATION_TO_HOST_RESOLUTION_NS_NODATA,
            None,
        ),
        (
            DelegationResult(
                domain=DOMAIN,
                dns=DelegationDnsEvidence(ns_nxdomain=True),
                soa=DelegationSoaEvidence(soa_exists=True, soa_source="soa_query"),
            ),
            StageRouteTransition,
            RouteDestination.HOST_RESOLUTION,
            RouteCode.DELEGATION_TO_HOST_RESOLUTION_NS_NXDOMAIN_SOA_EXISTS,
            None,
        ),
        (
            DelegationResult(
                domain=DOMAIN,
                dns=DelegationDnsEvidence(ns_retry_exhausted=True),
                soa=DelegationSoaEvidence(soa_exists=True, soa_source="soa_query"),
            ),
            StageRouteTransition,
            RouteDestination.HOST_RESOLUTION,
            RouteCode.DELEGATION_TO_HOST_RESOLUTION_NS_RETRY_EXHAUSTED_SOA_EXISTS,
            None,
        ),
        (
            DelegationResult(
                domain=DOMAIN,
                dns=DelegationDnsEvidence(ns_nxdomain=True),
                soa=DelegationSoaEvidence(soa_absent=True),
            ),
            TerminalRouteTransition,
            RouteDestination.UNACTIONABLE,
            RouteCode.DELEGATION_TO_UNACTIONABLE_NS_NXDOMAIN_SOA_ABSENT,
            "unactionable",
        ),
        (
            DelegationResult(domain=DOMAIN, no_nameservers=True),
            TerminalRouteTransition,
            RouteDestination.UNACTIONABLE,
            RouteCode.DELEGATION_TO_UNACTIONABLE_NS_EMPTY_ANSWER,
            "unactionable",
        ),
        (
            DelegationResult(
                domain=DOMAIN,
                dns=DelegationDnsEvidence(ns_nxdomain=True),
                soa=DelegationSoaEvidence(soa_retry_exhausted=True),
            ),
            TerminalRouteTransition,
            RouteDestination.REVIEW,
            RouteCode.DELEGATION_TO_REVIEW_NS_NXDOMAIN_SOA_RETRY_EXHAUSTED,
            "review",
        ),
        (
            DelegationResult(
                domain=DOMAIN,
                dns=DelegationDnsEvidence(ns_retry_exhausted=True),
                soa=DelegationSoaEvidence(soa_absent=True),
            ),
            TerminalRouteTransition,
            RouteDestination.REVIEW,
            RouteCode.DELEGATION_TO_REVIEW_NS_RETRY_EXHAUSTED_SOA_ABSENT,
            "review",
        ),
        (
            DelegationResult(
                domain=DOMAIN,
                dns=DelegationDnsEvidence(ns_retry_exhausted=True),
                soa=DelegationSoaEvidence(soa_retry_exhausted=True),
            ),
            TerminalRouteTransition,
            RouteDestination.REVIEW,
            RouteCode.DELEGATION_TO_REVIEW_NS_RETRY_EXHAUSTED_SOA_RETRY_EXHAUSTED,
            "review",
        ),
        (
            DelegationResult(
                domain=DOMAIN,
                dns=DelegationDnsEvidence(ns_lookup_error=True),
            ),
            TerminalRouteTransition,
            RouteDestination.REVIEW,
            RouteCode.DELEGATION_TO_REVIEW_NS_LOOKUP_ERROR,
            "review",
        ),
    ],
)
def test_delegation_evidence_maps_to_baseline_dispositions(
    result: DelegationResult,
    transition_type: type[StageRouteTransition] | type[TerminalRouteTransition],
    destination: RouteDestination,
    route_code: RouteCode,
    route: str | None,
) -> None:
    transition = DelegationRoutingPolicy().for_result(result)

    assert isinstance(transition, transition_type)
    assert transition.destination == destination
    assert transition.route_code == route_code
    if isinstance(transition, TerminalRouteTransition):
        assert transition.route == route
    else:
        assert route is None
