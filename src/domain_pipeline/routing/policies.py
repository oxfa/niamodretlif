"""OOP routing policies that map stage evidence to route transitions."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from domain_pipeline.routing.route_codes import (
    PipelineStage,
    RouteCode,
    RouteDestination,
    StageRouteTransition,
    TerminalRouteTransition,
)
from domain_pipeline.routing.types import (
    ROUTE_FILTERED,
    ROUTE_REVIEW,
    ROUTE_UNACTIONABLE,
    ResultRoute,
)

ROUTE_REASON_TEXT: Mapping[RouteCode, str] = MappingProxyType(
    {
        RouteCode.INPUT_VALIDATION_TO_REVIEW_PUBLIC_SUFFIX: (
            "input is a public suffix rather than a registrable host"
        ),
        RouteCode.MANUALLY_SELECTED_FOR_FILTERED_TO_FILTERED: (
            "host was explicitly selected for filtered output"
        ),
        RouteCode.MANUALLY_SELECTED_FOR_FILTERED_TO_FILTERED_PUBLIC_SUFFIX: (
            "public suffix input was explicitly selected for filtered output"
        ),
        RouteCode.MANUALLY_SELECTED_FOR_FILTERED_TO_REVIEW_NOT_IN_SOURCES: (
            "manually selected entry was not present in any configured source"
        ),
        RouteCode.MANUALLY_ADDED_TO_FILTERED_ACTIONABLE: (
            "host was explicitly added as actionable"
        ),
        RouteCode.DELEGATION_TO_HOST_RESOLUTION_NS_RECORDS_EXIST: (
            "delegation NS records exist"
        ),
        RouteCode.DELEGATION_TO_HOST_RESOLUTION_NS_NODATA: (
            "delegation NS query returned NODATA"
        ),
        RouteCode.DELEGATION_TO_HOST_RESOLUTION_NS_NXDOMAIN_SOA_EXISTS: (
            "delegation NS query returned NXDOMAIN and SOA exists"
        ),
        RouteCode.DELEGATION_TO_HOST_RESOLUTION_NS_RETRY_EXHAUSTED_SOA_EXISTS: (
            "delegation NS retry budget was exhausted and SOA exists"
        ),
        RouteCode.DELEGATION_TO_UNACTIONABLE_NS_NXDOMAIN_SOA_ABSENT: (
            "delegation NS query returned NXDOMAIN and SOA was absent"
        ),
        RouteCode.DELEGATION_TO_UNACTIONABLE_NS_EMPTY_ANSWER: (
            "delegation NS query returned an empty answer"
        ),
        RouteCode.DELEGATION_TO_REVIEW_NS_NXDOMAIN_SOA_RETRY_EXHAUSTED: (
            "delegation NS query returned NXDOMAIN and SOA retry budget was exhausted"
        ),
        RouteCode.DELEGATION_TO_REVIEW_NS_RETRY_EXHAUSTED_SOA_ABSENT: (
            "delegation NS retry budget was exhausted and SOA was absent"
        ),
        RouteCode.DELEGATION_TO_REVIEW_NS_RETRY_EXHAUSTED_SOA_RETRY_EXHAUSTED: (
            "delegation NS retry budget was exhausted and SOA retry budget was exhausted"
        ),
        RouteCode.DELEGATION_TO_REVIEW_NS_LOOKUP_ERROR: (
            "delegation NS lookup failed before a definitive delegation result"
        ),
        RouteCode.HOST_RESOLUTION_TO_FILTERED_SKIPPED: ("host resolution was skipped"),
        RouteCode.HOST_RESOLUTION_TO_IP_LOCATION_RESOLVES: (
            "host resolution resolved and IP-location policy is enabled"
        ),
        RouteCode.HOST_RESOLUTION_TO_FILTERED_RESOLVES: (
            "host resolution resolved and IP-location policy is disabled"
        ),
        RouteCode.HOST_RESOLUTION_TO_REVIEW_RESOLVED_WITHOUT_IP_ADDRESSES: (
            "host resolution produced no usable IP addresses"
        ),
        RouteCode.HOST_RESOLUTION_TO_REVIEW_TIMEOUT: (
            "host resolution timed out after retries"
        ),
        RouteCode.HOST_RESOLUTION_TO_REVIEW_SERVFAIL: (
            "host resolution returned SERVFAIL after retries"
        ),
        RouteCode.HOST_RESOLUTION_TO_REVIEW_NXDOMAIN: (
            "host resolution returned NXDOMAIN"
        ),
        RouteCode.HOST_RESOLUTION_TO_REVIEW_NODATA: ("host resolution returned NODATA"),
        RouteCode.IP_LOCATION_TO_REVIEW_LOOKUP_FAILED: (
            "ip_location lookup did not produce usable data"
        ),
        RouteCode.IP_LOCATION_TO_FILTERED_POLICY_ACCEPTED: (
            "ip location policy accepted the resolved IP set"
        ),
        RouteCode.IP_LOCATION_TO_REVIEW_POLICY_REJECTED: (
            "ip location policy rejected the resolved IP set"
        ),
        RouteCode.IP_LOCATION_TO_REVIEW_REGION_NAME_UNAVAILABLE: (
            "ip location policy required a region name unavailable from the provider"
        ),
    }
)

_TERMINAL_ROUTE_BY_DESTINATION: Mapping[RouteDestination, ResultRoute] = {
    RouteDestination.FILTERED: ROUTE_FILTERED,
    RouteDestination.REVIEW: ROUTE_REVIEW,
    RouteDestination.UNACTIONABLE: ROUTE_UNACTIONABLE,
}

_DELEGATION_STAGE_ROUTE_CODES: Mapping[str, RouteCode] = MappingProxyType(
    {
        "ns_records_exist": RouteCode.DELEGATION_TO_HOST_RESOLUTION_NS_RECORDS_EXIST,
        "ns_nodata": RouteCode.DELEGATION_TO_HOST_RESOLUTION_NS_NODATA,
        "ns_nxdomain_soa_exists": (
            RouteCode.DELEGATION_TO_HOST_RESOLUTION_NS_NXDOMAIN_SOA_EXISTS
        ),
        "ns_retry_exhausted_soa_exists": (
            RouteCode.DELEGATION_TO_HOST_RESOLUTION_NS_RETRY_EXHAUSTED_SOA_EXISTS
        ),
    }
)

_DELEGATION_TERMINAL_ROUTE_CODES: Mapping[str, tuple[RouteDestination, RouteCode]] = (
    MappingProxyType(
        {
            "ns_nxdomain_soa_absent": (
                RouteDestination.UNACTIONABLE,
                RouteCode.DELEGATION_TO_UNACTIONABLE_NS_NXDOMAIN_SOA_ABSENT,
            ),
            "ns_empty_answer": (
                RouteDestination.UNACTIONABLE,
                RouteCode.DELEGATION_TO_UNACTIONABLE_NS_EMPTY_ANSWER,
            ),
            "ns_nxdomain_soa_retry_exhausted": (
                RouteDestination.REVIEW,
                RouteCode.DELEGATION_TO_REVIEW_NS_NXDOMAIN_SOA_RETRY_EXHAUSTED,
            ),
            "ns_retry_exhausted_soa_absent": (
                RouteDestination.REVIEW,
                RouteCode.DELEGATION_TO_REVIEW_NS_RETRY_EXHAUSTED_SOA_ABSENT,
            ),
            "ns_retry_exhausted_soa_retry_exhausted": (
                RouteDestination.REVIEW,
                RouteCode.DELEGATION_TO_REVIEW_NS_RETRY_EXHAUSTED_SOA_RETRY_EXHAUSTED,
            ),
        }
    )
)


def _reason(route_code: RouteCode) -> str:
    return ROUTE_REASON_TEXT[route_code]


def _terminal(
    *,
    source_stage: PipelineStage,
    destination: RouteDestination,
    route_code: RouteCode,
) -> TerminalRouteTransition:
    return TerminalRouteTransition(
        source_stage=source_stage,
        destination=destination,
        route_code=route_code,
        route_reason=_reason(route_code),
        route=_TERMINAL_ROUTE_BY_DESTINATION[destination],
    )


def _stage(
    *,
    source_stage: PipelineStage,
    destination: RouteDestination,
    route_code: RouteCode,
) -> StageRouteTransition:
    return StageRouteTransition(
        source_stage=source_stage,
        destination=destination,
        route_code=route_code,
        route_reason=_reason(route_code),
    )


class InputValidationRoutingPolicy:
    """Route input-validation terminal cases."""

    def source_stages(self) -> tuple[PipelineStage, ...]:
        """Return stages owned by this policy."""
        return (PipelineStage.INPUT_VALIDATION,)

    def public_suffix(self) -> TerminalRouteTransition:
        """Route a public-suffix input to review."""
        return _terminal(
            source_stage=PipelineStage.INPUT_VALIDATION,
            destination=RouteDestination.REVIEW,
            route_code=RouteCode.INPUT_VALIDATION_TO_REVIEW_PUBLIC_SUFFIX,
        )


class ManualRoutingPolicy:
    """Route manual input decisions."""

    def source_stages(self) -> tuple[PipelineStage, ...]:
        """Return stages owned by this policy."""
        return (
            PipelineStage.MANUALLY_SELECTED_FOR_FILTERED,
            PipelineStage.MANUALLY_ADDED,
        )

    def selected_for_filtered(self) -> TerminalRouteTransition:
        """Route a manually selected entry to filtered output."""
        return _terminal(
            source_stage=PipelineStage.MANUALLY_SELECTED_FOR_FILTERED,
            destination=RouteDestination.FILTERED,
            route_code=RouteCode.MANUALLY_SELECTED_FOR_FILTERED_TO_FILTERED,
        )

    def selected_public_suffix_for_filtered(self) -> TerminalRouteTransition:
        """Route a manually selected public suffix to filtered output."""
        return _terminal(
            source_stage=PipelineStage.MANUALLY_SELECTED_FOR_FILTERED,
            destination=RouteDestination.FILTERED,
            route_code=(
                RouteCode.MANUALLY_SELECTED_FOR_FILTERED_TO_FILTERED_PUBLIC_SUFFIX
            ),
        )

    def selected_for_filtered_not_in_sources(self) -> TerminalRouteTransition:
        """Route a missing manually selected source entry to review."""
        return _terminal(
            source_stage=PipelineStage.MANUALLY_SELECTED_FOR_FILTERED,
            destination=RouteDestination.REVIEW,
            route_code=(
                RouteCode.MANUALLY_SELECTED_FOR_FILTERED_TO_REVIEW_NOT_IN_SOURCES
            ),
        )

    def manually_added_actionable(self) -> TerminalRouteTransition:
        """Route a manually added entry to filtered output."""
        return _terminal(
            source_stage=PipelineStage.MANUALLY_ADDED,
            destination=RouteDestination.FILTERED,
            route_code=RouteCode.MANUALLY_ADDED_TO_FILTERED_ACTIONABLE,
        )


class DelegationRoutingPolicy:
    """Route delegation evidence to host resolution, review, or unactionable."""

    def source_stages(self) -> tuple[PipelineStage, ...]:
        """Return stages owned by this policy."""
        return (PipelineStage.DELEGATION,)

    def for_result(self, result: Any) -> StageRouteTransition | TerminalRouteTransition:
        """Route one delegation lookup result to the next stage or terminal bucket."""
        status = str(getattr(result, "status", ""))
        stage_route_code = _DELEGATION_STAGE_ROUTE_CODES.get(status)
        if stage_route_code is not None:
            return _stage(
                source_stage=PipelineStage.DELEGATION,
                destination=RouteDestination.HOST_RESOLUTION,
                route_code=stage_route_code,
            )
        destination, route_code = _DELEGATION_TERMINAL_ROUTE_CODES.get(
            status,
            (RouteDestination.REVIEW, RouteCode.DELEGATION_TO_REVIEW_NS_LOOKUP_ERROR),
        )
        return _terminal(
            source_stage=PipelineStage.DELEGATION,
            destination=destination,
            route_code=route_code,
        )


class HostResolutionRoutingPolicy:
    """Route host-resolution evidence to IP-location, filtered, or review."""

    def source_stages(self) -> tuple[PipelineStage, ...]:
        """Return stages owned by this policy."""
        return (PipelineStage.HOST_RESOLUTION,)

    def skipped(self) -> TerminalRouteTransition:
        """Route a skipped host-resolution stage to filtered output."""
        return _terminal(
            source_stage=PipelineStage.HOST_RESOLUTION,
            destination=RouteDestination.FILTERED,
            route_code=RouteCode.HOST_RESOLUTION_TO_FILTERED_SKIPPED,
        )

    def for_result(
        self,
        result: Any,
        *,
        ip_location_enabled: bool,
    ) -> StageRouteTransition | TerminalRouteTransition:
        """Route one host-resolution result to IP location, filtered, or review."""
        status = str(getattr(result, "status", ""))
        if status == "resolved":
            if ip_location_enabled:
                return _stage(
                    source_stage=PipelineStage.HOST_RESOLUTION,
                    destination=RouteDestination.IP_LOCATION,
                    route_code=RouteCode.HOST_RESOLUTION_TO_IP_LOCATION_RESOLVES,
                )
            return _terminal(
                source_stage=PipelineStage.HOST_RESOLUTION,
                destination=RouteDestination.FILTERED,
                route_code=RouteCode.HOST_RESOLUTION_TO_FILTERED_RESOLVES,
            )
        if status == "nxdomain":
            route_code = RouteCode.HOST_RESOLUTION_TO_REVIEW_NXDOMAIN
        elif status == "nodata":
            route_code = RouteCode.HOST_RESOLUTION_TO_REVIEW_NODATA
        elif status == "timeout":
            route_code = RouteCode.HOST_RESOLUTION_TO_REVIEW_TIMEOUT
        elif status == "servfail":
            route_code = RouteCode.HOST_RESOLUTION_TO_REVIEW_SERVFAIL
        else:
            route_code = (
                RouteCode.HOST_RESOLUTION_TO_REVIEW_RESOLVED_WITHOUT_IP_ADDRESSES
            )
        return _terminal(
            source_stage=PipelineStage.HOST_RESOLUTION,
            destination=RouteDestination.REVIEW,
            route_code=route_code,
        )


class IpLocationRoutingPolicy:
    """Route IP-location provider and policy evidence to a terminal transition."""

    def source_stages(self) -> tuple[PipelineStage, ...]:
        """Return stages owned by this policy."""
        return (PipelineStage.IP_LOCATION,)

    def lookup_failed(self) -> TerminalRouteTransition:
        """Route an IP-location lookup failure to review."""
        return _terminal(
            source_stage=PipelineStage.IP_LOCATION,
            destination=RouteDestination.REVIEW,
            route_code=RouteCode.IP_LOCATION_TO_REVIEW_LOOKUP_FAILED,
        )

    def for_policy(
        self,
        policy: Any | None,
        results: list[Any],
        policy_payload: dict[str, Any],
    ) -> TerminalRouteTransition:
        """Route IP-location policy evidence to filtered or review output."""
        if policy is None:
            return self.lookup_failed()
        if str(getattr(policy, "status", "")) == "accepted":
            return _terminal(
                source_stage=PipelineStage.IP_LOCATION,
                destination=RouteDestination.FILTERED,
                route_code=RouteCode.IP_LOCATION_TO_FILTERED_POLICY_ACCEPTED,
            )
        include = policy_payload.get("include", {})
        exclude = policy_payload.get("exclude", {})
        has_region_rules = bool(
            include.get("regions", []) or exclude.get("regions", [])
        )
        if has_region_rules and any(
            bool(getattr(result, "usable", False))
            and not str(getattr(result, "region_name", "")).strip()
            for result in results
        ):
            return _terminal(
                source_stage=PipelineStage.IP_LOCATION,
                destination=RouteDestination.REVIEW,
                route_code=RouteCode.IP_LOCATION_TO_REVIEW_REGION_NAME_UNAVAILABLE,
            )
        return _terminal(
            source_stage=PipelineStage.IP_LOCATION,
            destination=RouteDestination.REVIEW,
            route_code=RouteCode.IP_LOCATION_TO_REVIEW_POLICY_REJECTED,
        )
