"""Route decisions for pipeline result codes."""

# pylint: disable=import-outside-toplevel

from __future__ import annotations

from collections.abc import Iterator, Mapping
from functools import cache
from types import MappingProxyType

from domain_pipeline.routing.types import (
    ROUTE_FILTERED,
    ROUTE_REVIEW,
    ROUTE_UNACTIONABLE,
    ResultRoute,
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
    # Keep these imports local so route values can be imported without loading
    # heavier stage package exports during package initialization.
    from domain_pipeline.prepare.classifications import (
        PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX,
        PIPELINE_RESULT_CODE_MANUAL_ADD_ACTIONABLE,
        PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT,
        PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
        PIPELINE_RESULT_CODE_MANUAL_FILTER_PASSED,
        PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
    )
    from domain_pipeline.worker.dns.classifications import (
        PIPELINE_RESULT_CODE_DNS_DELEGATION_EXISTS,
        PIPELINE_RESULT_CODE_DNS_DELEGATION_NODATA,
        PIPELINE_RESULT_CODE_DNS_DELEGATION_NO_NAMESERVERS,
        PIPELINE_RESULT_CODE_DNS_DELEGATION_NXDOMAIN,
        PIPELINE_RESULT_CODE_DNS_DELEGATION_SERVFAIL,
        PIPELINE_RESULT_CODE_DNS_DELEGATION_TIMEOUT,
        PIPELINE_RESULT_CODE_DNS_HOST_NODATA,
        PIPELINE_RESULT_CODE_DNS_HOST_NXDOMAIN,
        PIPELINE_RESULT_CODE_DNS_HOST_RESOLUTION_SKIPPED,
        PIPELINE_RESULT_CODE_DNS_LOOKUP_SERVFAIL,
        PIPELINE_RESULT_CODE_DNS_LOOKUP_TIMEOUT,
        PIPELINE_RESULT_CODE_DNS_RESOLVED_WITHOUT_IP_ADDRESSES,
        PIPELINE_RESULT_CODE_DNS_RESOLVES,
    )
    from domain_pipeline.worker.geo.classifications import (
        PIPELINE_RESULT_CODE_GEO_LOOKUP_FAILED,
        PIPELINE_RESULT_CODE_GEO_POLICY_ACCEPTED,
        PIPELINE_RESULT_CODE_GEO_POLICY_REJECTED,
        PIPELINE_RESULT_CODE_GEO_REGION_NAME_UNAVAILABLE,
    )

    return MappingProxyType(
        {
            PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX: ROUTE_REVIEW,
            PIPELINE_RESULT_CODE_MANUAL_FILTER_PASSED: ROUTE_FILTERED,
            PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES: ROUTE_REVIEW,
            PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT: ROUTE_REVIEW,
            PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES: ROUTE_REVIEW,
            PIPELINE_RESULT_CODE_MANUAL_ADD_ACTIONABLE: ROUTE_FILTERED,
            PIPELINE_RESULT_CODE_DNS_DELEGATION_EXISTS: ROUTE_FILTERED,
            PIPELINE_RESULT_CODE_DNS_DELEGATION_NXDOMAIN: ROUTE_UNACTIONABLE,
            PIPELINE_RESULT_CODE_DNS_DELEGATION_NODATA: ROUTE_UNACTIONABLE,
            PIPELINE_RESULT_CODE_DNS_DELEGATION_NO_NAMESERVERS: ROUTE_UNACTIONABLE,
            PIPELINE_RESULT_CODE_DNS_DELEGATION_TIMEOUT: ROUTE_REVIEW,
            PIPELINE_RESULT_CODE_DNS_DELEGATION_SERVFAIL: ROUTE_REVIEW,
            PIPELINE_RESULT_CODE_DNS_HOST_RESOLUTION_SKIPPED: ROUTE_FILTERED,
            PIPELINE_RESULT_CODE_DNS_RESOLVES: ROUTE_FILTERED,
            PIPELINE_RESULT_CODE_DNS_RESOLVED_WITHOUT_IP_ADDRESSES: ROUTE_REVIEW,
            PIPELINE_RESULT_CODE_DNS_LOOKUP_TIMEOUT: ROUTE_REVIEW,
            PIPELINE_RESULT_CODE_DNS_LOOKUP_SERVFAIL: ROUTE_REVIEW,
            PIPELINE_RESULT_CODE_DNS_HOST_NXDOMAIN: ROUTE_REVIEW,
            PIPELINE_RESULT_CODE_DNS_HOST_NODATA: ROUTE_REVIEW,
            PIPELINE_RESULT_CODE_GEO_LOOKUP_FAILED: ROUTE_REVIEW,
            PIPELINE_RESULT_CODE_GEO_POLICY_ACCEPTED: ROUTE_FILTERED,
            PIPELINE_RESULT_CODE_GEO_POLICY_REJECTED: ROUTE_REVIEW,
            PIPELINE_RESULT_CODE_GEO_REGION_NAME_UNAVAILABLE: ROUTE_REVIEW,
        }
    )


def route_for_pipeline_result_code(pipeline_result_code: str) -> ResultRoute:
    """Return the terminal route for one pipeline result code."""
    try:
        return PIPELINE_RESULT_CODE_ROUTE_MAP[pipeline_result_code]
    except KeyError as exc:
        raise ValueError(
            f"unknown pipeline result code: {pipeline_result_code!r}"
        ) from exc
