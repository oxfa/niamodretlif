"""Geo result-code helpers owned by the worker geo stage."""

from __future__ import annotations

from typing import Any

from domain_pipeline.worker.geo.classifications import (
    PIPELINE_RESULT_CODE_GEO_LOOKUP_FAILED,
    PIPELINE_RESULT_CODE_GEO_POLICY_ACCEPTED,
    PIPELINE_RESULT_CODE_GEO_POLICY_REJECTED,
    PIPELINE_RESULT_CODE_GEO_REGION_NAME_UNAVAILABLE,
)
from domain_pipeline.worker.geo.providers import GeoPolicyDecision, IPGeoResult


def geo_policy_result_code(
    policy: GeoPolicyDecision | None,
    results: list[IPGeoResult],
    policy_payload: dict[str, Any],
) -> str:
    """Return the terminal geo result code for one host."""
    if policy is None:
        return PIPELINE_RESULT_CODE_GEO_LOOKUP_FAILED
    if policy.status == "accepted":
        return PIPELINE_RESULT_CODE_GEO_POLICY_ACCEPTED
    include = policy_payload.get("include", {})
    exclude = policy_payload.get("exclude", {})
    has_region_rules = bool(include.get("regions", []) or exclude.get("regions", []))
    if has_region_rules and any(
        result.usable and not result.region_name for result in results
    ):
        return PIPELINE_RESULT_CODE_GEO_REGION_NAME_UNAVAILABLE
    return PIPELINE_RESULT_CODE_GEO_POLICY_REJECTED
