"""Prepare-stage decision reason-code constants."""

from __future__ import annotations

DECISION_REASON_CODE_INPUT_PUBLIC_SUFFIX = "input_public_suffix"
DECISION_REASON_CODE_MANUAL_FILTER_PASSED = "manual_filter_passed"
DECISION_REASON_CODE_MANUAL_FILTER_PASS_PUBLIC_SUFFIX = (
    "manual_filter_pass_public_suffix"
)
DECISION_REASON_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES = (
    "manual_filter_pass_not_in_sources"
)
DECISION_REASON_CODE_MANUAL_FILTER_OUT = "manual_filter_out"
DECISION_REASON_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES = (
    "manual_filter_out_not_in_sources"
)
DECISION_REASON_CODE_MANUAL_ADD_ACTIONABLE = "manual_add_actionable"

PREPARE_REVIEW_DECISION_REASON_CODES = frozenset(
    {
        DECISION_REASON_CODE_INPUT_PUBLIC_SUFFIX,
        DECISION_REASON_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
        DECISION_REASON_CODE_MANUAL_FILTER_OUT,
        DECISION_REASON_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
    }
)
