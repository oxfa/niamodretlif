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
