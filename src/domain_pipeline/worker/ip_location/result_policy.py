"""IpLocation result-code policy helpers owned by the worker ip location stage."""

from __future__ import annotations

from typing import Any

from domain_pipeline.worker.ip_location.providers import (
    LocationPolicyDecision,
    IPLocationResult,
)
from domain_pipeline.worker.ip_location.result_codes import (
    PIPELINE_RESULT_CODE_IP_LOCATION_LOOKUP_FAILED,
    PIPELINE_RESULT_CODE_IP_LOCATION_POLICY_ACCEPTED,
    PIPELINE_RESULT_CODE_IP_LOCATION_POLICY_REJECTED,
    PIPELINE_RESULT_CODE_IP_LOCATION_REGION_NAME_UNAVAILABLE,
)


def ip_location_policy_result_code(
    policy: LocationPolicyDecision | None,
    results: list[IPLocationResult],
    policy_payload: dict[str, Any],
) -> str:
    """Return the terminal ip location result code for one host."""
    if policy is None:
        return PIPELINE_RESULT_CODE_IP_LOCATION_LOOKUP_FAILED
    if policy.status == "accepted":
        return PIPELINE_RESULT_CODE_IP_LOCATION_POLICY_ACCEPTED
    include = policy_payload.get("include", {})
    exclude = policy_payload.get("exclude", {})
    has_region_rules = bool(include.get("regions", []) or exclude.get("regions", []))
    if has_region_rules and any(
        result.usable and not result.region_name for result in results
    ):
        return PIPELINE_RESULT_CODE_IP_LOCATION_REGION_NAME_UNAVAILABLE
    return PIPELINE_RESULT_CODE_IP_LOCATION_POLICY_REJECTED
