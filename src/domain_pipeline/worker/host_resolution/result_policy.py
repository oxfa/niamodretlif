"""Host-resolution decision reason-code policy helpers."""

from __future__ import annotations

from typing import Any

from domain_pipeline.worker.host_resolution.reason_codes import (
    DECISION_REASON_CODE_HOST_RESOLUTION_NODATA,
    DECISION_REASON_CODE_HOST_RESOLUTION_NXDOMAIN,
    DECISION_REASON_CODE_HOST_RESOLUTION_RESOLVED_WITHOUT_IP_ADDRESSES,
    DECISION_REASON_CODE_HOST_RESOLUTION_RESOLVES,
    DECISION_REASON_CODE_HOST_RESOLUTION_SKIPPED,
    DECISION_REASON_CODE_HOST_RESOLUTION_SERVFAIL,
    DECISION_REASON_CODE_HOST_RESOLUTION_TIMEOUT,
)


def host_resolution_reason_code(result: Any) -> str:
    """Return the decision reason code for one host-resolution result."""
    if result.status == "resolved":
        return DECISION_REASON_CODE_HOST_RESOLUTION_RESOLVES
    if result.status == "nxdomain":
        return DECISION_REASON_CODE_HOST_RESOLUTION_NXDOMAIN
    if result.status == "nodata":
        return DECISION_REASON_CODE_HOST_RESOLUTION_NODATA
    if result.status == "timeout":
        return DECISION_REASON_CODE_HOST_RESOLUTION_TIMEOUT
    if result.status == "servfail":
        return DECISION_REASON_CODE_HOST_RESOLUTION_SERVFAIL
    return DECISION_REASON_CODE_HOST_RESOLUTION_RESOLVED_WITHOUT_IP_ADDRESSES


def host_resolution_skipped_reason_code() -> str:
    """Return the reason code used when host resolution is intentionally skipped."""
    return DECISION_REASON_CODE_HOST_RESOLUTION_SKIPPED


__all__ = ["host_resolution_reason_code", "host_resolution_skipped_reason_code"]
