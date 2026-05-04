"""Settings for one configured pipeline run."""

from __future__ import annotations

from typing import Any

DEFAULT_WORKER_RUNTIME_BUDGET_SECONDS = 19800


class WorkflowRunPlanner:
    """Own batch identity, worker slots, and workflow runtime limits."""

    def batch_id_from_run(self, run_id: str | int, run_attempt: str | int) -> str:
        """Return the deterministic batch identifier for one workflow run."""
        return f"batch-{run_id}-attempt-{run_attempt}"

    def default_worker_ids(self, worker_count: int) -> list[str]:
        """Return stable worker identities for one configured worker slot count."""
        if worker_count < 1:
            raise ValueError("worker_count must be at least 1")
        return [f"worker-{index:02d}" for index in range(1, worker_count + 1)]

    def validate_run_settings(
        self,
        *,
        worker_count: int,
        max_parallel_workers_raw: str | None,
        worker_runtime_seconds_raw: str | None,
        max_parallel_workers_default_raw: str | None = None,
    ) -> dict[str, Any]:
        """Validate and normalize settings for one pipeline run."""
        worker_ids = self.default_worker_ids(worker_count)
        max_parallel_workers_source = "PIPELINE_RUN_MAX_PARALLEL_WORKERS"
        max_parallel_workers = self._parse_optional_positive_int(
            max_parallel_workers_raw,
            field_name="PIPELINE_RUN_MAX_PARALLEL_WORKERS",
        )
        if max_parallel_workers is None:
            max_parallel_workers_source = "max_parallel_workers_default"
            max_parallel_workers = self._parse_optional_positive_int(
                max_parallel_workers_default_raw,
                field_name=max_parallel_workers_source,
            )
        if max_parallel_workers is None:
            max_parallel_workers_source = "worker_count"
            max_parallel_workers = worker_count
        if max_parallel_workers > worker_count:
            raise ValueError(
                f"{max_parallel_workers_source} must not exceed worker_count "
                f"({max_parallel_workers} > {worker_count})"
            )
        worker_runtime_budget_seconds = self._parse_optional_positive_int(
            worker_runtime_seconds_raw,
            field_name="PIPELINE_MAX_RUNTIME_SECONDS",
        )
        if worker_runtime_budget_seconds is None:
            worker_runtime_budget_seconds = DEFAULT_WORKER_RUNTIME_BUDGET_SECONDS
        if worker_runtime_budget_seconds > DEFAULT_WORKER_RUNTIME_BUDGET_SECONDS:
            raise ValueError(
                "PIPELINE_MAX_RUNTIME_SECONDS must be less than or equal to "
                f"{DEFAULT_WORKER_RUNTIME_BUDGET_SECONDS}"
            )
        return {
            "worker_count": worker_count,
            "worker_ids": worker_ids,
            "max_parallel_workers": max_parallel_workers,
            "worker_runtime_budget_seconds": worker_runtime_budget_seconds,
        }

    def _parse_optional_positive_int(
        self, raw_value: str | None, *, field_name: str
    ) -> int | None:
        if raw_value is None:
            return None
        stripped = str(raw_value).strip()
        if not stripped:
            return None
        try:
            parsed = int(stripped)
        except ValueError as exc:
            raise ValueError(f"{field_name} must be an integer") from exc
        if parsed < 1:
            raise ValueError(f"{field_name} must be at least 1")
        return parsed


def batch_id_from_run(run_id: str | int, run_attempt: str | int) -> str:
    """Return the deterministic batch identifier for one workflow run."""
    return WorkflowRunPlanner().batch_id_from_run(run_id, run_attempt)


def default_worker_ids(worker_count: int) -> list[str]:
    """Return stable worker identities for one configured worker slot count."""
    return WorkflowRunPlanner().default_worker_ids(worker_count)


def validate_run_settings(
    *,
    worker_count: int,
    max_parallel_workers_raw: str | None,
    worker_runtime_seconds_raw: str | None,
    max_parallel_workers_default_raw: str | None = None,
) -> dict[str, Any]:
    """Validate and normalize settings for one pipeline run."""
    return WorkflowRunPlanner().validate_run_settings(
        worker_count=worker_count,
        max_parallel_workers_raw=max_parallel_workers_raw,
        worker_runtime_seconds_raw=worker_runtime_seconds_raw,
        max_parallel_workers_default_raw=max_parallel_workers_default_raw,
    )
