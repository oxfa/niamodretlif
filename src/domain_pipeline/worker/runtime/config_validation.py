"""Runtime payload validation for worker-local execution."""

from __future__ import annotations

from typing import Any

RUNTIME_KEYS = frozenset({"stage_concurrency"})
STAGE_CONCURRENCY_KEYS = frozenset({"minimums", "adaptive"})
STAGE_CONCURRENCY_MINIMUM_KEYS = frozenset(
    {"delegation", "host_resolution", "ip_location"}
)
STAGE_CONCURRENCY_ADAPTIVE_KEYS = frozenset(
    {
        "enabled",
        "delegation_enabled",
        "host_resolution_enabled",
        "supervisor_interval_seconds",
        "busy_scale_up_after_seconds",
        "idle_scale_down_after_seconds",
        "pressure_window_seconds",
        "queue_pressure_ratio",
        "max_concurrency_multiplier",
        "scale_up_step",
        "scale_down_step",
    }
)
CACHE_KEYS = frozenset(
    {
        "cache_file",
        "baseline_cache_file",
        "delegation_ttl_days",
        "host_resolution_ttl_days",
    }
)
WORKER_RUNTIME_PAYLOAD_KEYS = frozenset(
    {"config_name", "cache", "runtime", "output_spec", "debug_log_path"}
)
WORKER_OUTPUT_SPEC_KEYS = frozenset(
    {"result_root", "unactionable", "review", "domain_results", "cache"}
)


def mapping_payload(value: Any, *, path: str) -> dict[str, Any]:
    """Return a mapping payload or raise a path-specific validation error."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be a mapping")
    return dict(value)


def reject_unknown_keys(
    payload: dict[str, Any],
    *,
    allowed_keys: frozenset[str],
    path: str,
) -> None:
    """Reject unknown keys with a stable dotted config path."""
    unknown_keys = sorted(set(payload) - allowed_keys)
    if unknown_keys:
        raise ValueError(f"{path}.{unknown_keys[0]} is unsupported")


def require_exact_keys(
    payload: dict[str, Any],
    *,
    expected_keys: frozenset[str],
    path: str,
) -> None:
    """Require a closed mapping at one worker runtime boundary."""
    if set(payload) != expected_keys:
        missing = sorted(expected_keys - set(payload))
        unknown = sorted(set(payload) - expected_keys)
        raise ValueError(f"{path} fields mismatch: missing={missing} unknown={unknown}")


def validate_worker_runtime_payload(config: dict[str, Any]) -> None:
    """Require the exact source-blind runtime payload emitted by prepare."""
    if not isinstance(config, dict):
        raise ValueError("worker runtime payload must be a mapping")
    if set(config) != WORKER_RUNTIME_PAYLOAD_KEYS:
        missing = sorted(WORKER_RUNTIME_PAYLOAD_KEYS - set(config))
        unknown = sorted(set(config) - WORKER_RUNTIME_PAYLOAD_KEYS)
        raise ValueError(
            "worker runtime payload fields mismatch: "
            f"missing={missing} unknown={unknown}"
        )
    for key in ("config_name", "debug_log_path"):
        value = config[key]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"worker runtime payload {key} must be a nonempty string")

    output_spec = mapping_payload(config["output_spec"], path="output_spec")
    if set(output_spec) != WORKER_OUTPUT_SPEC_KEYS:
        missing = sorted(WORKER_OUTPUT_SPEC_KEYS - set(output_spec))
        unknown = sorted(set(output_spec) - WORKER_OUTPUT_SPEC_KEYS)
        raise ValueError(
            f"output_spec fields mismatch: missing={missing} unknown={unknown}"
        )
    for key, value in output_spec.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"output_spec.{key} must be a nonempty string")

    cache = mapping_payload(config["cache"], path="cache")
    require_exact_keys(cache, expected_keys=CACHE_KEYS, path="cache")
    runtime = mapping_payload(config["runtime"], path="runtime")
    require_exact_keys(runtime, expected_keys=RUNTIME_KEYS, path="runtime")
    stage_concurrency = mapping_payload(
        runtime["stage_concurrency"], path="runtime.stage_concurrency"
    )
    require_exact_keys(
        stage_concurrency,
        expected_keys=STAGE_CONCURRENCY_KEYS,
        path="runtime.stage_concurrency",
    )
    minimums = mapping_payload(
        stage_concurrency["minimums"], path="runtime.stage_concurrency.minimums"
    )
    require_exact_keys(
        minimums,
        expected_keys=STAGE_CONCURRENCY_MINIMUM_KEYS,
        path="runtime.stage_concurrency.minimums",
    )
    adaptive = mapping_payload(
        stage_concurrency["adaptive"], path="runtime.stage_concurrency.adaptive"
    )
    require_exact_keys(
        adaptive,
        expected_keys=STAGE_CONCURRENCY_ADAPTIVE_KEYS,
        path="runtime.stage_concurrency.adaptive",
    )
    runtime_cache_payload(config)
    runtime_stage_concurrency_payload(config)


def runtime_payload(config: dict[str, Any]) -> dict[str, Any]:
    """Return canonical runtime payload after rejecting stale keys."""
    payload = mapping_payload(config.get("runtime", {}), path="runtime")
    reject_unknown_keys(payload, allowed_keys=RUNTIME_KEYS, path="runtime")
    return payload


def runtime_stage_concurrency_payload(config: dict[str, Any]) -> dict[str, Any]:
    """Return canonical stage concurrency payload after rejecting stale keys."""
    payload = runtime_payload(config)
    stage_concurrency = mapping_payload(
        payload.get("stage_concurrency", {}),
        path="runtime.stage_concurrency",
    )
    reject_unknown_keys(
        stage_concurrency,
        allowed_keys=STAGE_CONCURRENCY_KEYS,
        path="runtime.stage_concurrency",
    )
    minimums = mapping_payload(
        stage_concurrency.get("minimums", {}),
        path="runtime.stage_concurrency.minimums",
    )
    reject_unknown_keys(
        minimums,
        allowed_keys=STAGE_CONCURRENCY_MINIMUM_KEYS,
        path="runtime.stage_concurrency.minimums",
    )
    adaptive = mapping_payload(
        stage_concurrency.get("adaptive", {}),
        path="runtime.stage_concurrency.adaptive",
    )
    reject_unknown_keys(
        adaptive,
        allowed_keys=STAGE_CONCURRENCY_ADAPTIVE_KEYS,
        path="runtime.stage_concurrency.adaptive",
    )
    return stage_concurrency


def runtime_cache_payload(config: dict[str, Any]) -> dict[str, Any]:
    """Return canonical runtime cache payload after rejecting stale keys."""
    cache_payload = mapping_payload(config.get("cache", {}), path="cache")
    reject_unknown_keys(cache_payload, allowed_keys=CACHE_KEYS, path="cache")
    cache_file = str(cache_payload.get("cache_file", "")).strip()
    if not cache_file:
        raise ValueError("cache.cache_file is required")
    return cache_payload
