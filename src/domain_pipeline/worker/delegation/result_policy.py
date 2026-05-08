"""Delegation result-code policy helpers."""

from __future__ import annotations

from typing import Any

from domain_pipeline.worker.delegation.result_codes import (
    PIPELINE_RESULT_CODE_DELEGATION_EXISTS,
    PIPELINE_RESULT_CODE_DELEGATION_NODATA,
    PIPELINE_RESULT_CODE_DELEGATION_NO_NAMESERVERS,
    PIPELINE_RESULT_CODE_DELEGATION_NS_NODATA_SOA_ABSENT,
    PIPELINE_RESULT_CODE_DELEGATION_NS_NODATA_SOA_EXISTS,
    PIPELINE_RESULT_CODE_DELEGATION_NS_NODATA_SOA_SERVFAIL,
    PIPELINE_RESULT_CODE_DELEGATION_NS_NODATA_SOA_TIMEOUT,
    PIPELINE_RESULT_CODE_DELEGATION_NXDOMAIN,
    PIPELINE_RESULT_CODE_DELEGATION_SERVFAIL,
    PIPELINE_RESULT_CODE_DELEGATION_TIMEOUT,
)


def classify_delegation(result: Any) -> str:
    """Return the pipeline result code for one delegation result."""
    if result.status == "exists":
        return PIPELINE_RESULT_CODE_DELEGATION_EXISTS
    if result.status == "nxdomain":
        return PIPELINE_RESULT_CODE_DELEGATION_NXDOMAIN
    if result.status == "ns_nodata_soa_exists":
        return PIPELINE_RESULT_CODE_DELEGATION_NS_NODATA_SOA_EXISTS
    if result.status == "ns_nodata_soa_absent":
        return PIPELINE_RESULT_CODE_DELEGATION_NS_NODATA_SOA_ABSENT
    if result.status == "ns_nodata_soa_timeout":
        return PIPELINE_RESULT_CODE_DELEGATION_NS_NODATA_SOA_TIMEOUT
    if result.status == "ns_nodata_soa_servfail":
        return PIPELINE_RESULT_CODE_DELEGATION_NS_NODATA_SOA_SERVFAIL
    if result.status == "nodata":
        return PIPELINE_RESULT_CODE_DELEGATION_NODATA
    if result.status == "no_nameservers":
        return PIPELINE_RESULT_CODE_DELEGATION_NO_NAMESERVERS
    if result.status == "timeout":
        return PIPELINE_RESULT_CODE_DELEGATION_TIMEOUT
    return PIPELINE_RESULT_CODE_DELEGATION_SERVFAIL


__all__ = ["classify_delegation"]
