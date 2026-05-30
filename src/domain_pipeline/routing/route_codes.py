"""Durable route-code vocabulary for pipeline stage transitions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from domain_pipeline.routing.types import (
    ROUTE_FILTERED,
    ROUTE_REVIEW,
    ROUTE_UNACTIONABLE,
    ResultRoute,
)


class PipelineStage(StrEnum):
    """Pipeline stage that owns the routing decision."""

    INPUT_VALIDATION = "input_validation"
    MANUAL_FILTER = "manual_filter"
    MANUAL_ADD = "manual_add"
    DELEGATION = "delegation"
    HOST_RESOLUTION = "host_resolution"
    IP_LOCATION = "ip_location"


class RouteDestination(StrEnum):
    """Next stage or terminal output bucket for one route transition."""

    HOST_RESOLUTION = "host_resolution"
    IP_LOCATION = "ip_location"
    FILTERED = "filtered"
    REVIEW = "review"
    UNACTIONABLE = "unactionable"


class RouteCode(StrEnum):
    """Durable route-code values emitted or used internally by routing policies."""

    INPUT_VALIDATION_TO_REVIEW_PUBLIC_SUFFIX = (
        "input_validation_to_review_public_suffix"
    )

    MANUAL_FILTER_TO_FILTERED_PASSED = "manual_filter_to_filtered_passed"
    MANUAL_FILTER_TO_FILTERED_PUBLIC_SUFFIX_PASSED = (
        "manual_filter_to_filtered_public_suffix_passed"
    )
    MANUAL_FILTER_TO_REVIEW_PASS_NOT_IN_SOURCES = (
        "manual_filter_to_review_pass_not_in_sources"
    )
    MANUAL_FILTER_TO_REVIEW_OUT = "manual_filter_to_review_out"
    MANUAL_FILTER_TO_REVIEW_OUT_NOT_IN_SOURCES = (
        "manual_filter_to_review_out_not_in_sources"
    )

    MANUAL_ADD_TO_FILTERED_ACTIONABLE = "manual_add_to_filtered_actionable"

    DELEGATION_TO_HOST_RESOLUTION_NS_RECORDS_EXIST = (
        "delegation_to_host_resolution_ns_records_exist"
    )
    DELEGATION_TO_HOST_RESOLUTION_NS_NODATA = "delegation_to_host_resolution_ns_nodata"
    DELEGATION_TO_HOST_RESOLUTION_NS_NXDOMAIN_SOA_EXISTS = (
        "delegation_to_host_resolution_ns_nxdomain_soa_exists"
    )
    DELEGATION_TO_HOST_RESOLUTION_NS_RETRY_EXHAUSTED_SOA_EXISTS = (
        "delegation_to_host_resolution_ns_retry_exhausted_soa_exists"
    )
    DELEGATION_TO_UNACTIONABLE_NS_NXDOMAIN_SOA_ABSENT = (
        "delegation_to_unactionable_ns_nxdomain_soa_absent"
    )
    DELEGATION_TO_UNACTIONABLE_NS_EMPTY_ANSWER = (
        "delegation_to_unactionable_ns_empty_answer"
    )
    DELEGATION_TO_REVIEW_NS_NXDOMAIN_SOA_RETRY_EXHAUSTED = (
        "delegation_to_review_ns_nxdomain_soa_retry_exhausted"
    )
    DELEGATION_TO_REVIEW_NS_RETRY_EXHAUSTED_SOA_ABSENT = (
        "delegation_to_review_ns_retry_exhausted_soa_absent"
    )
    DELEGATION_TO_REVIEW_NS_RETRY_EXHAUSTED_SOA_RETRY_EXHAUSTED = (
        "delegation_to_review_ns_retry_exhausted_soa_retry_exhausted"
    )
    DELEGATION_TO_REVIEW_NS_LOOKUP_ERROR = "delegation_to_review_ns_lookup_error"

    HOST_RESOLUTION_TO_FILTERED_SKIPPED = "host_resolution_to_filtered_skipped"
    HOST_RESOLUTION_TO_IP_LOCATION_RESOLVES = "host_resolution_to_ip_location_resolves"
    HOST_RESOLUTION_TO_FILTERED_RESOLVES = "host_resolution_to_filtered_resolves"
    HOST_RESOLUTION_TO_REVIEW_RESOLVED_WITHOUT_IP_ADDRESSES = (
        "host_resolution_to_review_resolved_without_ip_addresses"
    )
    HOST_RESOLUTION_TO_REVIEW_TIMEOUT = "host_resolution_to_review_timeout"
    HOST_RESOLUTION_TO_REVIEW_SERVFAIL = "host_resolution_to_review_servfail"
    HOST_RESOLUTION_TO_REVIEW_NXDOMAIN = "host_resolution_to_review_nxdomain"
    HOST_RESOLUTION_TO_REVIEW_NODATA = "host_resolution_to_review_nodata"

    IP_LOCATION_TO_REVIEW_LOOKUP_FAILED = "ip_location_to_review_lookup_failed"
    IP_LOCATION_TO_FILTERED_POLICY_ACCEPTED = "ip_location_to_filtered_policy_accepted"
    IP_LOCATION_TO_REVIEW_POLICY_REJECTED = "ip_location_to_review_policy_rejected"
    IP_LOCATION_TO_REVIEW_REGION_NAME_UNAVAILABLE = (
        "ip_location_to_review_region_name_unavailable"
    )


TERMINAL_ROUTE_BY_DESTINATION: Final[dict[RouteDestination, ResultRoute]] = {
    RouteDestination.FILTERED: ROUTE_FILTERED,
    RouteDestination.REVIEW: ROUTE_REVIEW,
    RouteDestination.UNACTIONABLE: ROUTE_UNACTIONABLE,
}


@dataclass(frozen=True)
class RouteTransition:
    """Base route transition from one source stage to a next stage or terminal bucket."""

    source_stage: PipelineStage
    destination: RouteDestination
    route_code: RouteCode
    route_reason: str


@dataclass(frozen=True)
class StageRouteTransition(RouteTransition):
    """Non-terminal transition to another worker stage."""

    def __post_init__(self) -> None:
        if self.destination in TERMINAL_ROUTE_BY_DESTINATION:
            raise ValueError(
                f"stage transition cannot target terminal destination: {self.destination}"
            )


@dataclass(frozen=True)
class TerminalRouteTransition(RouteTransition):
    """Terminal transition into a public output route."""

    route: ResultRoute

    def __post_init__(self) -> None:
        expected_route = TERMINAL_ROUTE_BY_DESTINATION.get(self.destination)
        if expected_route is None:
            raise ValueError(
                f"terminal transition cannot target stage destination: {self.destination}"
            )
        if self.route != expected_route:
            raise ValueError(
                f"terminal route {self.route!r} does not match destination "
                f"{self.destination.value!r}"
            )
