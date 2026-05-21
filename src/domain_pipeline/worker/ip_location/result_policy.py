"""IP-location decision reason-code policy helpers."""

from __future__ import annotations

from typing import Any

from domain_pipeline.worker.ip_location.providers import (
    LocationPolicyDecision,
    IPLocationResult,
)
from domain_pipeline.worker.ip_location.reason_codes import (
    DECISION_REASON_CODE_IP_LOCATION_LOOKUP_FAILED,
    DECISION_REASON_CODE_IP_LOCATION_POLICY_ACCEPTED,
    DECISION_REASON_CODE_IP_LOCATION_POLICY_REJECTED,
    DECISION_REASON_CODE_IP_LOCATION_REGION_NAME_UNAVAILABLE,
)


def ip_location_policy_reason_code(
    policy: LocationPolicyDecision | None,
    results: list[IPLocationResult],
    policy_payload: dict[str, Any],
) -> str:
    """Return the terminal IP-location decision reason code for one host."""
    if policy is None:
        return DECISION_REASON_CODE_IP_LOCATION_LOOKUP_FAILED
    if policy.status == "accepted":
        return DECISION_REASON_CODE_IP_LOCATION_POLICY_ACCEPTED
    include = policy_payload.get("include", {})
    exclude = policy_payload.get("exclude", {})
    has_region_rules = bool(include.get("regions", []) or exclude.get("regions", []))
    if has_region_rules and any(
        result.usable and not result.region_name for result in results
    ):
        return DECISION_REASON_CODE_IP_LOCATION_REGION_NAME_UNAVAILABLE
    return DECISION_REASON_CODE_IP_LOCATION_POLICY_REJECTED
