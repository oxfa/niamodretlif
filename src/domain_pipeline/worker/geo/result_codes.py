"""Geo pipeline result-code constants."""

from __future__ import annotations

PIPELINE_RESULT_CODE_GEO_LOOKUP_FAILED = "geo_lookup_failed"
PIPELINE_RESULT_CODE_GEO_POLICY_ACCEPTED = "geo_policy_accepted"
PIPELINE_RESULT_CODE_GEO_POLICY_REJECTED = "geo_policy_rejected"
PIPELINE_RESULT_CODE_GEO_REGION_NAME_UNAVAILABLE = "geo_region_name_unavailable"

GEO_REVIEW_PIPELINE_RESULT_CODES = frozenset(
    {
        PIPELINE_RESULT_CODE_GEO_LOOKUP_FAILED,
        PIPELINE_RESULT_CODE_GEO_POLICY_REJECTED,
        PIPELINE_RESULT_CODE_GEO_REGION_NAME_UNAVAILABLE,
    }
)
