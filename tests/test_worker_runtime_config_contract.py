"""Focused checks for the canonical source-blind runtime payload."""

from __future__ import annotations

from copy import deepcopy

import pytest

from domain_pipeline.worker.runtime.config_validation import (
    validate_worker_runtime_payload,
)


def _runtime_payload() -> dict[str, object]:
    return {
        "config_name": "worker",
        "cache": {
            "cache_file": "/state/cache.sqlite",
            "baseline_cache_file": "",
            "delegation_ttl_days": {"actionable": 7, "unactionable": 1},
            "host_resolution_ttl_days": {
                "resolved": None,
                "nodata": 1,
                "nxdomain": 1,
            },
        },
        "runtime": {
            "stage_concurrency": {
                "minimums": {
                    "delegation": 1,
                    "host_resolution": 1,
                    "ip_location": 1,
                },
                "adaptive": {
                    "enabled": True,
                    "delegation_enabled": True,
                    "host_resolution_enabled": True,
                    "supervisor_interval_seconds": 1.0,
                    "busy_scale_up_after_seconds": 5.0,
                    "idle_scale_down_after_seconds": 5.0,
                    "pressure_window_seconds": 5.0,
                    "queue_pressure_ratio": 0.8,
                    "max_concurrency_multiplier": 4,
                    "scale_up_step": 1,
                    "scale_down_step": 1,
                },
            }
        },
        "output_spec": {
            "result_root": "/state/publish",
            "unactionable": "/state/unactionable-input-domains/worker.txt",
            "review": "/state/review-results-by-input-domain/worker.csv",
            "domain_results": "/state/domain-results.jsonl",
            "cache": "/state/cache.sqlite",
        },
        "debug_log_path": "/state/worker.log",
    }


def test_runtime_payload_accepts_exact_canonical_shape() -> None:
    validate_worker_runtime_payload(_runtime_payload())


@pytest.mark.parametrize("field", ["sources", "unexpected_extra"])
def test_runtime_payload_rejects_unknown_fields(field: str) -> None:
    payload = _runtime_payload()
    payload[field] = []

    with pytest.raises(ValueError, match="worker runtime payload fields mismatch"):
        validate_worker_runtime_payload(payload)


def test_runtime_payload_rejects_unknown_output_path() -> None:
    payload = deepcopy(_runtime_payload())
    payload["output_spec"]["terminal_rows"] = "/state/terminal.yaml"  # type: ignore[index]

    with pytest.raises(ValueError, match="output_spec fields mismatch"):
        validate_worker_runtime_payload(payload)
