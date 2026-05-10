"""Shared prepare-owned runtime stage concurrency models."""

from __future__ import annotations

import math

from pydantic import BaseModel, ConfigDict, field_validator


class RuntimeStageConcurrencyAdaptiveConfig(BaseModel):
    """Adaptive worker-local stage concurrency settings."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    delegation_enabled: bool = True
    host_resolution_enabled: bool = True
    supervisor_interval_seconds: float = 1.0
    busy_scale_up_after_seconds: float = 5.0
    idle_scale_down_after_seconds: float = 5.0
    pressure_window_seconds: float = 5.0
    queue_pressure_ratio: float = 0.8
    max_concurrency_multiplier: int = 4
    scale_up_step: int = 1
    scale_down_step: int = 1

    @field_validator(
        "supervisor_interval_seconds",
        "busy_scale_up_after_seconds",
        "idle_scale_down_after_seconds",
        "pressure_window_seconds",
        mode="after",
    )
    @classmethod
    def _validate_timing(cls, value: float) -> float:
        if not math.isfinite(value) or value <= 0:
            raise ValueError("runtime adaptive timing values must be > 0")
        return float(value)

    @field_validator("queue_pressure_ratio", mode="after")
    @classmethod
    def _validate_queue_pressure_ratio(cls, value: float) -> float:
        if not math.isfinite(value) or value <= 0 or value > 1:
            raise ValueError(
                "runtime adaptive queue_pressure_ratio must be > 0 and <= 1"
            )
        return float(value)

    @field_validator("max_concurrency_multiplier", mode="after")
    @classmethod
    def _validate_concurrency_multiplier(cls, value: int) -> int:
        if value < 1:
            raise ValueError("runtime adaptive max_concurrency_multiplier must be >= 1")
        return value

    @field_validator("scale_up_step", "scale_down_step", mode="after")
    @classmethod
    def _validate_scale_steps(cls, value: int) -> int:
        if value < 1:
            raise ValueError("runtime adaptive scale steps must be >= 1")
        return value
