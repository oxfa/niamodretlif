"""Prepare-stage pipeline result-code constants."""

from __future__ import annotations

PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX = "input_public_suffix"
PIPELINE_RESULT_CODE_MANUAL_FILTER_PASSED = "manual_filter_passed"
PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_PUBLIC_SUFFIX = (
    "manual_filter_pass_public_suffix"
)
PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES = (
    "manual_filter_pass_not_in_sources"
)
PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT = "manual_filter_out"
PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES = (
    "manual_filter_out_not_in_sources"
)
PIPELINE_RESULT_CODE_MANUAL_ADD_ACTIONABLE = "manual_add_actionable"

PREPARE_REVIEW_PIPELINE_RESULT_CODES = frozenset(
    {
        PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX,
        PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
        PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT,
        PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
    }
)
