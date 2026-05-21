"""Terminal decision objects for final outcome and evidence routing."""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from types import MappingProxyType

from domain_pipeline.prepare.reason_codes import (
    DECISION_REASON_CODE_INPUT_PUBLIC_SUFFIX,
    DECISION_REASON_CODE_MANUAL_ADD_ACTIONABLE,
    DECISION_REASON_CODE_MANUAL_FILTER_OUT,
    DECISION_REASON_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
    DECISION_REASON_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
    DECISION_REASON_CODE_MANUAL_FILTER_PASS_PUBLIC_SUFFIX,
    DECISION_REASON_CODE_MANUAL_FILTER_PASSED,
)
from domain_pipeline.routing.types import (
    ROUTE_FILTERED,
    ROUTE_REVIEW,
    ROUTE_UNACTIONABLE,
    ResultRoute,
)
from domain_pipeline.worker.delegation.reason_codes import (
    DECISION_REASON_CODE_DELEGATION_NS_EMPTY_ANSWER,
    DECISION_REASON_CODE_DELEGATION_NS_LOOKUP_ERROR,
    DECISION_REASON_CODE_DELEGATION_NS_NODATA,
    DECISION_REASON_CODE_DELEGATION_NS_NXDOMAIN_SOA_ABSENT,
    DECISION_REASON_CODE_DELEGATION_NS_NXDOMAIN_SOA_EXISTS,
    DECISION_REASON_CODE_DELEGATION_NS_NXDOMAIN_SOA_RETRY_EXHAUSTED,
    DECISION_REASON_CODE_DELEGATION_NS_RECORDS_EXIST,
    DECISION_REASON_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_ABSENT,
    DECISION_REASON_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_EXISTS,
    DECISION_REASON_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_RETRY_EXHAUSTED,
)
from domain_pipeline.worker.host_resolution.reason_codes import (
    DECISION_REASON_CODE_HOST_RESOLUTION_NODATA,
    DECISION_REASON_CODE_HOST_RESOLUTION_NXDOMAIN,
    DECISION_REASON_CODE_HOST_RESOLUTION_RESOLVED_WITHOUT_IP_ADDRESSES,
    DECISION_REASON_CODE_HOST_RESOLUTION_RESOLVES,
    DECISION_REASON_CODE_HOST_RESOLUTION_SERVFAIL,
    DECISION_REASON_CODE_HOST_RESOLUTION_SKIPPED,
    DECISION_REASON_CODE_HOST_RESOLUTION_TIMEOUT,
)
from domain_pipeline.worker.ip_location.reason_codes import (
    DECISION_REASON_CODE_IP_LOCATION_LOOKUP_FAILED,
    DECISION_REASON_CODE_IP_LOCATION_POLICY_ACCEPTED,
    DECISION_REASON_CODE_IP_LOCATION_POLICY_REJECTED,
    DECISION_REASON_CODE_IP_LOCATION_REGION_NAME_UNAVAILABLE,
)

FINAL_RESULT_CODE_DOMAIN_ACTIONABLE = "domain_actionable"
FINAL_RESULT_CODE_DOMAIN_UNACTIONABLE = "domain_unactionable"
FINAL_RESULT_CODES = frozenset(
    {
        FINAL_RESULT_CODE_DOMAIN_ACTIONABLE,
        FINAL_RESULT_CODE_DOMAIN_UNACTIONABLE,
    }
)


@dataclasses.dataclass(frozen=True)
class TerminalDecision:
    """Immutable terminal route, final outcome, and reason-code decision."""

    route: ResultRoute
    decision_reason_code: str
    final_result_code: str | None = None


_DECISION_REASON_ROUTE_MAP: Mapping[str, ResultRoute] = MappingProxyType(
    {
        DECISION_REASON_CODE_INPUT_PUBLIC_SUFFIX: ROUTE_REVIEW,
        DECISION_REASON_CODE_MANUAL_FILTER_PASSED: ROUTE_FILTERED,
        DECISION_REASON_CODE_MANUAL_FILTER_PASS_PUBLIC_SUFFIX: ROUTE_FILTERED,
        DECISION_REASON_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES: ROUTE_REVIEW,
        DECISION_REASON_CODE_MANUAL_FILTER_OUT: ROUTE_REVIEW,
        DECISION_REASON_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES: ROUTE_REVIEW,
        DECISION_REASON_CODE_MANUAL_ADD_ACTIONABLE: ROUTE_FILTERED,
        DECISION_REASON_CODE_DELEGATION_NS_RECORDS_EXIST: ROUTE_FILTERED,
        DECISION_REASON_CODE_DELEGATION_NS_NODATA: ROUTE_FILTERED,
        DECISION_REASON_CODE_DELEGATION_NS_NXDOMAIN_SOA_EXISTS: ROUTE_FILTERED,
        DECISION_REASON_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_EXISTS: ROUTE_FILTERED,
        DECISION_REASON_CODE_DELEGATION_NS_NXDOMAIN_SOA_ABSENT: ROUTE_UNACTIONABLE,
        DECISION_REASON_CODE_DELEGATION_NS_EMPTY_ANSWER: ROUTE_UNACTIONABLE,
        DECISION_REASON_CODE_DELEGATION_NS_NXDOMAIN_SOA_RETRY_EXHAUSTED: ROUTE_REVIEW,
        DECISION_REASON_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_ABSENT: ROUTE_REVIEW,
        DECISION_REASON_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_RETRY_EXHAUSTED: (
            ROUTE_REVIEW
        ),
        DECISION_REASON_CODE_DELEGATION_NS_LOOKUP_ERROR: ROUTE_REVIEW,
        DECISION_REASON_CODE_HOST_RESOLUTION_SKIPPED: ROUTE_FILTERED,
        DECISION_REASON_CODE_HOST_RESOLUTION_RESOLVES: ROUTE_FILTERED,
        DECISION_REASON_CODE_HOST_RESOLUTION_RESOLVED_WITHOUT_IP_ADDRESSES: ROUTE_REVIEW,
        DECISION_REASON_CODE_HOST_RESOLUTION_TIMEOUT: ROUTE_REVIEW,
        DECISION_REASON_CODE_HOST_RESOLUTION_SERVFAIL: ROUTE_REVIEW,
        DECISION_REASON_CODE_HOST_RESOLUTION_NXDOMAIN: ROUTE_REVIEW,
        DECISION_REASON_CODE_HOST_RESOLUTION_NODATA: ROUTE_REVIEW,
        DECISION_REASON_CODE_IP_LOCATION_LOOKUP_FAILED: ROUTE_REVIEW,
        DECISION_REASON_CODE_IP_LOCATION_POLICY_ACCEPTED: ROUTE_FILTERED,
        DECISION_REASON_CODE_IP_LOCATION_POLICY_REJECTED: ROUTE_REVIEW,
        DECISION_REASON_CODE_IP_LOCATION_REGION_NAME_UNAVAILABLE: ROUTE_REVIEW,
    }
)

DECISION_REASON_ROUTE_MAP: Mapping[str, ResultRoute] = _DECISION_REASON_ROUTE_MAP

_FINAL_RESULT_BY_REASON_CODE: Mapping[str, str] = MappingProxyType(
    {
        DECISION_REASON_CODE_MANUAL_ADD_ACTIONABLE: FINAL_RESULT_CODE_DOMAIN_ACTIONABLE,
        DECISION_REASON_CODE_DELEGATION_NS_RECORDS_EXIST: (
            FINAL_RESULT_CODE_DOMAIN_ACTIONABLE
        ),
        DECISION_REASON_CODE_DELEGATION_NS_NODATA: FINAL_RESULT_CODE_DOMAIN_ACTIONABLE,
        DECISION_REASON_CODE_DELEGATION_NS_NXDOMAIN_SOA_EXISTS: (
            FINAL_RESULT_CODE_DOMAIN_ACTIONABLE
        ),
        DECISION_REASON_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_EXISTS: (
            FINAL_RESULT_CODE_DOMAIN_ACTIONABLE
        ),
        DECISION_REASON_CODE_DELEGATION_NS_NXDOMAIN_SOA_ABSENT: (
            FINAL_RESULT_CODE_DOMAIN_UNACTIONABLE
        ),
        DECISION_REASON_CODE_DELEGATION_NS_EMPTY_ANSWER: (
            FINAL_RESULT_CODE_DOMAIN_UNACTIONABLE
        ),
        DECISION_REASON_CODE_HOST_RESOLUTION_SKIPPED: FINAL_RESULT_CODE_DOMAIN_ACTIONABLE,
        DECISION_REASON_CODE_HOST_RESOLUTION_RESOLVES: FINAL_RESULT_CODE_DOMAIN_ACTIONABLE,
        DECISION_REASON_CODE_IP_LOCATION_POLICY_ACCEPTED: (
            FINAL_RESULT_CODE_DOMAIN_ACTIONABLE
        ),
    }
)

_DECISION_REASON_TEXT: Mapping[str, str] = MappingProxyType(
    {
        DECISION_REASON_CODE_INPUT_PUBLIC_SUFFIX: (
            "input is a public suffix rather than a registrable host"
        ),
        DECISION_REASON_CODE_MANUAL_FILTER_PASSED: (
            "host was explicitly allowed by manual_filter_pass"
        ),
        DECISION_REASON_CODE_MANUAL_FILTER_PASS_PUBLIC_SUFFIX: (
            "public suffix input was explicitly allowed by manual_filter_pass"
        ),
        DECISION_REASON_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES: (
            "manual_filter_pass entry was not present in any configured source"
        ),
        DECISION_REASON_CODE_MANUAL_FILTER_OUT: (
            "host was explicitly sent to review by manual_filter_out"
        ),
        DECISION_REASON_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES: (
            "manual_filter_out entry was not present in any configured source"
        ),
        DECISION_REASON_CODE_MANUAL_ADD_ACTIONABLE: (
            "host was explicitly added as actionable"
        ),
        DECISION_REASON_CODE_DELEGATION_NS_RECORDS_EXIST: (
            "delegation NS records exist"
        ),
        DECISION_REASON_CODE_DELEGATION_NS_NODATA: "delegation NS query returned NODATA",
        DECISION_REASON_CODE_DELEGATION_NS_NXDOMAIN_SOA_EXISTS: (
            "delegation NS query returned NXDOMAIN and SOA exists"
        ),
        DECISION_REASON_CODE_DELEGATION_NS_NXDOMAIN_SOA_ABSENT: (
            "delegation NS query returned NXDOMAIN and SOA was absent"
        ),
        DECISION_REASON_CODE_DELEGATION_NS_NXDOMAIN_SOA_RETRY_EXHAUSTED: (
            "delegation NS query returned NXDOMAIN and SOA retry budget was exhausted"
        ),
        DECISION_REASON_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_EXISTS: (
            "delegation NS retry budget was exhausted and SOA exists"
        ),
        DECISION_REASON_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_ABSENT: (
            "delegation NS retry budget was exhausted and SOA was absent"
        ),
        DECISION_REASON_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_RETRY_EXHAUSTED: (
            "delegation NS retry budget was exhausted and SOA retry budget was exhausted"
        ),
        DECISION_REASON_CODE_DELEGATION_NS_EMPTY_ANSWER: (
            "delegation NS query returned an empty answer"
        ),
        DECISION_REASON_CODE_DELEGATION_NS_LOOKUP_ERROR: (
            "delegation NS lookup failed before a definitive delegation result"
        ),
        DECISION_REASON_CODE_HOST_RESOLUTION_SKIPPED: "host resolution was skipped",
        DECISION_REASON_CODE_HOST_RESOLUTION_RESOLVES: "host resolution resolved",
        DECISION_REASON_CODE_HOST_RESOLUTION_RESOLVED_WITHOUT_IP_ADDRESSES: (
            "host resolution produced no usable IP addresses"
        ),
        DECISION_REASON_CODE_HOST_RESOLUTION_TIMEOUT: (
            "host resolution timed out after retries"
        ),
        DECISION_REASON_CODE_HOST_RESOLUTION_SERVFAIL: (
            "host resolution returned SERVFAIL after retries"
        ),
        DECISION_REASON_CODE_HOST_RESOLUTION_NXDOMAIN: (
            "host resolution returned NXDOMAIN"
        ),
        DECISION_REASON_CODE_HOST_RESOLUTION_NODATA: "host resolution returned NODATA",
        DECISION_REASON_CODE_IP_LOCATION_LOOKUP_FAILED: (
            "ip_location lookup did not produce usable data"
        ),
        DECISION_REASON_CODE_IP_LOCATION_POLICY_ACCEPTED: (
            "ip location policy accepted the resolved IP set"
        ),
        DECISION_REASON_CODE_IP_LOCATION_POLICY_REJECTED: (
            "ip location policy rejected the resolved IP set"
        ),
        DECISION_REASON_CODE_IP_LOCATION_REGION_NAME_UNAVAILABLE: (
            "ip location policy required a region name unavailable from the provider"
        ),
    }
)


class TerminalDecisionPolicy:
    """Build terminal decisions from stage/manual decision reason codes."""

    def from_reason_code(self, decision_reason_code: str) -> TerminalDecision:
        """Return the terminal decision for one decision reason code."""
        try:
            route = DECISION_REASON_ROUTE_MAP[decision_reason_code]
        except KeyError as exc:
            raise ValueError(
                f"unknown decision reason code: {decision_reason_code!r}"
            ) from exc
        return TerminalDecision(
            route=route,
            decision_reason_code=decision_reason_code,
            final_result_code=_FINAL_RESULT_BY_REASON_CODE.get(decision_reason_code),
        )

    def reason_text(self, decision_reason_code: str) -> str:
        """Return the user-facing reason text for a decision reason code."""
        try:
            return _DECISION_REASON_TEXT[decision_reason_code]
        except KeyError as exc:
            raise ValueError(
                f"unknown decision reason code: {decision_reason_code!r}"
            ) from exc


def decision_for_reason_code(decision_reason_code: str) -> TerminalDecision:
    """Return the canonical terminal decision for one reason code."""
    return TerminalDecisionPolicy().from_reason_code(decision_reason_code)
