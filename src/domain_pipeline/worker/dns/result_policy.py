"""DNS result-code policy helpers owned by the worker DNS stage."""

from __future__ import annotations

from typing import Any

from domain_pipeline.worker.dns.result_codes import (
    PIPELINE_RESULT_CODE_DNS_DELEGATION_EXISTS,
    PIPELINE_RESULT_CODE_DNS_DELEGATION_NODATA,
    PIPELINE_RESULT_CODE_DNS_DELEGATION_NO_NAMESERVERS,
    PIPELINE_RESULT_CODE_DNS_DELEGATION_NS_NODATA_SOA_ABSENT,
    PIPELINE_RESULT_CODE_DNS_DELEGATION_NS_NODATA_SOA_EXISTS,
    PIPELINE_RESULT_CODE_DNS_DELEGATION_NS_NODATA_SOA_SERVFAIL,
    PIPELINE_RESULT_CODE_DNS_DELEGATION_NS_NODATA_SOA_TIMEOUT,
    PIPELINE_RESULT_CODE_DNS_DELEGATION_NXDOMAIN,
    PIPELINE_RESULT_CODE_DNS_DELEGATION_SERVFAIL,
    PIPELINE_RESULT_CODE_DNS_DELEGATION_TIMEOUT,
    PIPELINE_RESULT_CODE_DNS_HOST_NODATA,
    PIPELINE_RESULT_CODE_DNS_HOST_NXDOMAIN,
    PIPELINE_RESULT_CODE_DNS_HOST_RESOLUTION_RESOLVED_WITHOUT_IP_ADDRESSES,
    PIPELINE_RESULT_CODE_DNS_HOST_RESOLUTION_RESOLVES,
    PIPELINE_RESULT_CODE_DNS_HOST_RESOLUTION_SKIPPED,
    PIPELINE_RESULT_CODE_DNS_HOST_RESOLUTION_SERVFAIL,
    PIPELINE_RESULT_CODE_DNS_HOST_RESOLUTION_TIMEOUT,
)


def classify_delegation(result: Any) -> str:
    """Return the pipeline result code for one delegation result."""
    if result.status == "exists":
        return PIPELINE_RESULT_CODE_DNS_DELEGATION_EXISTS
    if result.status == "nxdomain":
        return PIPELINE_RESULT_CODE_DNS_DELEGATION_NXDOMAIN
    if result.status == "ns_nodata_soa_exists":
        return PIPELINE_RESULT_CODE_DNS_DELEGATION_NS_NODATA_SOA_EXISTS
    if result.status == "ns_nodata_soa_absent":
        return PIPELINE_RESULT_CODE_DNS_DELEGATION_NS_NODATA_SOA_ABSENT
    if result.status == "ns_nodata_soa_timeout":
        return PIPELINE_RESULT_CODE_DNS_DELEGATION_NS_NODATA_SOA_TIMEOUT
    if result.status == "ns_nodata_soa_servfail":
        return PIPELINE_RESULT_CODE_DNS_DELEGATION_NS_NODATA_SOA_SERVFAIL
    if result.status == "nodata":
        return PIPELINE_RESULT_CODE_DNS_DELEGATION_NODATA
    if result.status == "no_nameservers":
        return PIPELINE_RESULT_CODE_DNS_DELEGATION_NO_NAMESERVERS
    if result.status == "timeout":
        return PIPELINE_RESULT_CODE_DNS_DELEGATION_TIMEOUT
    return PIPELINE_RESULT_CODE_DNS_DELEGATION_SERVFAIL


def classify_host_resolution(result: Any) -> str:
    """Return the pipeline result code for one host-resolution result."""
    if result.status == "resolved":
        return PIPELINE_RESULT_CODE_DNS_HOST_RESOLUTION_RESOLVES
    if result.status == "nxdomain":
        return PIPELINE_RESULT_CODE_DNS_HOST_NXDOMAIN
    if result.status == "nodata":
        return PIPELINE_RESULT_CODE_DNS_HOST_NODATA
    if result.status == "timeout":
        return PIPELINE_RESULT_CODE_DNS_HOST_RESOLUTION_TIMEOUT
    if result.status == "servfail":
        return PIPELINE_RESULT_CODE_DNS_HOST_RESOLUTION_SERVFAIL
    return PIPELINE_RESULT_CODE_DNS_HOST_RESOLUTION_RESOLVED_WITHOUT_IP_ADDRESSES


def host_resolution_skipped_result_code() -> str:
    """Return the result code used when host resolution is intentionally skipped."""
    return PIPELINE_RESULT_CODE_DNS_HOST_RESOLUTION_SKIPPED


__all__ = [
    "classify_delegation",
    "classify_host_resolution",
    "host_resolution_skipped_result_code",
]
