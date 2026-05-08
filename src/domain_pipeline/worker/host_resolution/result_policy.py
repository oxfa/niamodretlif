"""Host-resolution result-code policy helpers."""

from __future__ import annotations

from typing import Any

from domain_pipeline.worker.host_resolution.result_codes import (
    PIPELINE_RESULT_CODE_HOST_RESOLUTION_NODATA,
    PIPELINE_RESULT_CODE_HOST_RESOLUTION_NXDOMAIN,
    PIPELINE_RESULT_CODE_HOST_RESOLUTION_RESOLVED_WITHOUT_IP_ADDRESSES,
    PIPELINE_RESULT_CODE_HOST_RESOLUTION_RESOLVES,
    PIPELINE_RESULT_CODE_HOST_RESOLUTION_SKIPPED,
    PIPELINE_RESULT_CODE_HOST_RESOLUTION_SERVFAIL,
    PIPELINE_RESULT_CODE_HOST_RESOLUTION_TIMEOUT,
)


def classify_host_resolution(result: Any) -> str:
    """Return the pipeline result code for one host-resolution result."""
    if result.status == "resolved":
        return PIPELINE_RESULT_CODE_HOST_RESOLUTION_RESOLVES
    if result.status == "nxdomain":
        return PIPELINE_RESULT_CODE_HOST_RESOLUTION_NXDOMAIN
    if result.status == "nodata":
        return PIPELINE_RESULT_CODE_HOST_RESOLUTION_NODATA
    if result.status == "timeout":
        return PIPELINE_RESULT_CODE_HOST_RESOLUTION_TIMEOUT
    if result.status == "servfail":
        return PIPELINE_RESULT_CODE_HOST_RESOLUTION_SERVFAIL
    return PIPELINE_RESULT_CODE_HOST_RESOLUTION_RESOLVED_WITHOUT_IP_ADDRESSES


def host_resolution_skipped_result_code() -> str:
    """Return the result code used when host resolution is intentionally skipped."""
    return PIPELINE_RESULT_CODE_HOST_RESOLUTION_SKIPPED


__all__ = ["classify_host_resolution", "host_resolution_skipped_result_code"]
