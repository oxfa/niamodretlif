"""Route decisions for pipeline result codes."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from functools import cache
from types import MappingProxyType

from domain_pipeline.prepare.classifications import (
    PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX,
    PIPELINE_RESULT_CODE_MANUAL_ADD_ACTIONABLE,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_PUBLIC_SUFFIX,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_PASSED,
)
from domain_pipeline.routing.types import (
    ROUTE_FILTERED,
    ROUTE_REVIEW,
    ROUTE_UNACTIONABLE,
    ResultRoute,
)
from domain_pipeline.worker.delegation.result_codes import (
    PIPELINE_RESULT_CODE_DELEGATION_NS_EMPTY_ANSWER,
    PIPELINE_RESULT_CODE_DELEGATION_NS_LOOKUP_ERROR,
    PIPELINE_RESULT_CODE_DELEGATION_NS_NODATA,
    PIPELINE_RESULT_CODE_DELEGATION_NS_NXDOMAIN_SOA_ABSENT,
    PIPELINE_RESULT_CODE_DELEGATION_NS_NXDOMAIN_SOA_EXISTS,
    PIPELINE_RESULT_CODE_DELEGATION_NS_NXDOMAIN_SOA_INCONCLUSIVE,
    PIPELINE_RESULT_CODE_DELEGATION_NS_RECORDS_EXIST,
    PIPELINE_RESULT_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_ABSENT,
    PIPELINE_RESULT_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_EXISTS,
    PIPELINE_RESULT_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_INCONCLUSIVE,
)
from domain_pipeline.worker.host_resolution.result_codes import (
    PIPELINE_RESULT_CODE_HOST_RESOLUTION_NODATA,
    PIPELINE_RESULT_CODE_HOST_RESOLUTION_NXDOMAIN,
    PIPELINE_RESULT_CODE_HOST_RESOLUTION_RESOLVED_WITHOUT_IP_ADDRESSES,
    PIPELINE_RESULT_CODE_HOST_RESOLUTION_RESOLVES,
    PIPELINE_RESULT_CODE_HOST_RESOLUTION_SERVFAIL,
    PIPELINE_RESULT_CODE_HOST_RESOLUTION_SKIPPED,
    PIPELINE_RESULT_CODE_HOST_RESOLUTION_TIMEOUT,
)
from domain_pipeline.worker.ip_location.result_codes import (
    PIPELINE_RESULT_CODE_IP_LOCATION_LOOKUP_FAILED,
    PIPELINE_RESULT_CODE_IP_LOCATION_POLICY_ACCEPTED,
    PIPELINE_RESULT_CODE_IP_LOCATION_POLICY_REJECTED,
    PIPELINE_RESULT_CODE_IP_LOCATION_REGION_NAME_UNAVAILABLE,
)


class _LazyPipelineResultCodeRouteMap(Mapping[str, ResultRoute]):
    """Read-only result-code route map that loads stage constants on access."""

    def __getitem__(self, pipeline_result_code: str) -> ResultRoute:
        return _pipeline_result_code_route_map()[pipeline_result_code]

    def __iter__(self) -> Iterator[str]:
        return iter(_pipeline_result_code_route_map())

    def __len__(self) -> int:
        return len(_pipeline_result_code_route_map())


PIPELINE_RESULT_CODE_ROUTE_MAP: Mapping[str, ResultRoute] = (
    _LazyPipelineResultCodeRouteMap()
)


@cache
def _pipeline_result_code_route_map() -> Mapping[str, ResultRoute]:
    """Return the complete pipeline result-code-to-route policy."""
    return MappingProxyType(
        {
            **_prepare_route_map(),
            **_delegation_route_map(),
            **_host_resolution_route_map(),
            **_ip_location_route_map(),
        }
    )


def _prepare_route_map() -> dict[str, ResultRoute]:
    """Return prepare-stage route policy."""
    return {
        PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX: ROUTE_REVIEW,
        PIPELINE_RESULT_CODE_MANUAL_FILTER_PASSED: ROUTE_FILTERED,
        PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_PUBLIC_SUFFIX: ROUTE_FILTERED,
        PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES: ROUTE_REVIEW,
        PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT: ROUTE_REVIEW,
        PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES: ROUTE_REVIEW,
        PIPELINE_RESULT_CODE_MANUAL_ADD_ACTIONABLE: ROUTE_FILTERED,
    }


def _delegation_route_map() -> dict[str, ResultRoute]:
    """Return delegation-stage route policy."""
    return {
        PIPELINE_RESULT_CODE_DELEGATION_NS_RECORDS_EXIST: ROUTE_FILTERED,
        PIPELINE_RESULT_CODE_DELEGATION_NS_NODATA: ROUTE_FILTERED,
        PIPELINE_RESULT_CODE_DELEGATION_NS_NXDOMAIN_SOA_EXISTS: ROUTE_FILTERED,
        PIPELINE_RESULT_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_EXISTS: ROUTE_FILTERED,
        PIPELINE_RESULT_CODE_DELEGATION_NS_NXDOMAIN_SOA_ABSENT: ROUTE_UNACTIONABLE,
        PIPELINE_RESULT_CODE_DELEGATION_NS_EMPTY_ANSWER: ROUTE_UNACTIONABLE,
        PIPELINE_RESULT_CODE_DELEGATION_NS_NXDOMAIN_SOA_INCONCLUSIVE: ROUTE_REVIEW,
        PIPELINE_RESULT_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_ABSENT: ROUTE_REVIEW,
        PIPELINE_RESULT_CODE_DELEGATION_NS_RETRY_EXHAUSTED_SOA_INCONCLUSIVE: (
            ROUTE_REVIEW
        ),
        PIPELINE_RESULT_CODE_DELEGATION_NS_LOOKUP_ERROR: ROUTE_REVIEW,
    }


def _host_resolution_route_map() -> dict[str, ResultRoute]:
    """Return host-resolution-stage route policy."""
    return {
        PIPELINE_RESULT_CODE_HOST_RESOLUTION_SKIPPED: ROUTE_FILTERED,
        PIPELINE_RESULT_CODE_HOST_RESOLUTION_RESOLVES: ROUTE_FILTERED,
        PIPELINE_RESULT_CODE_HOST_RESOLUTION_RESOLVED_WITHOUT_IP_ADDRESSES: ROUTE_REVIEW,
        PIPELINE_RESULT_CODE_HOST_RESOLUTION_TIMEOUT: ROUTE_REVIEW,
        PIPELINE_RESULT_CODE_HOST_RESOLUTION_SERVFAIL: ROUTE_REVIEW,
        PIPELINE_RESULT_CODE_HOST_RESOLUTION_NXDOMAIN: ROUTE_REVIEW,
        PIPELINE_RESULT_CODE_HOST_RESOLUTION_NODATA: ROUTE_REVIEW,
    }


def _ip_location_route_map() -> dict[str, ResultRoute]:
    """Return IP-location-stage route policy."""
    return {
        PIPELINE_RESULT_CODE_IP_LOCATION_LOOKUP_FAILED: ROUTE_REVIEW,
        PIPELINE_RESULT_CODE_IP_LOCATION_POLICY_ACCEPTED: ROUTE_FILTERED,
        PIPELINE_RESULT_CODE_IP_LOCATION_POLICY_REJECTED: ROUTE_REVIEW,
        PIPELINE_RESULT_CODE_IP_LOCATION_REGION_NAME_UNAVAILABLE: ROUTE_REVIEW,
    }


def route_for_pipeline_result_code(pipeline_result_code: str) -> ResultRoute:
    """Return the terminal route for one pipeline result code."""
    try:
        return PIPELINE_RESULT_CODE_ROUTE_MAP[pipeline_result_code]
    except KeyError as exc:
        raise ValueError(
            f"unknown pipeline result code: {pipeline_result_code!r}"
        ) from exc
