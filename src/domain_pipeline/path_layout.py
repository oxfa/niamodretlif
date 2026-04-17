"""Shared path-layout helpers for publish, workflow-state, and debug artifacts."""

from __future__ import annotations

from pathlib import Path

PUBLISH_WORKTREE_DIR = Path(".publish_worktree")
WORKFLOW_STATE_DIR = Path(".workflow_state")
DEBUG_ARTIFACTS_DIR = Path(".debug_artifacts")


def publish_worktree_root(workspace_root: Path) -> Path:
    """Return the dedicated publish worktree root for one workspace."""
    return workspace_root / PUBLISH_WORKTREE_DIR


def workflow_state_root(workspace_root: Path) -> Path:
    """Return the workflow-internal state root for one workspace."""
    return workspace_root / WORKFLOW_STATE_DIR


def debug_artifacts_root(workspace_root: Path) -> Path:
    """Return the debug-artifact root for one workspace."""
    return workspace_root / DEBUG_ARTIFACTS_DIR


def runtime_cache_path(workspace_root: Path) -> Path:
    """Return the shared runtime cache path for one workspace."""
    return (
        workflow_state_root(workspace_root)
        / "runtime"
        / "cache"
        / "check-cache.sqlite3"
    )


def runtime_raw_audit_path(workspace_root: Path, *, config_name: str) -> Path:
    """Return the debug raw-audit path for one config."""
    return (
        debug_artifacts_root(workspace_root)
        / "runtime"
        / "raw"
        / f"{config_name}.jsonl"
    )


def runtime_log_path(workspace_root: Path, *, config_name: str) -> Path:
    """Return the merged runtime log path for one config."""
    return (
        debug_artifacts_root(workspace_root) / "runtime" / "logs" / f"{config_name}.log"
    )


def aggregate_log_path(workspace_root: Path, *, config_name: str) -> Path:
    """Return the aggregate-job log path for one config."""
    return (
        debug_artifacts_root(workspace_root)
        / "runtime"
        / "logs"
        / f"{config_name}--aggregate.log"
    )


def incomplete_run_state_root(workspace_root: Path, *, config_name: str) -> Path:
    """Return the workflow-internal incomplete-run root for one config."""
    return workflow_state_root(workspace_root) / "incomplete_runs" / config_name


def incomplete_run_manifest_path(workspace_root: Path, *, config_name: str) -> Path:
    """Return the incomplete-run manifest path for one config."""
    return (
        incomplete_run_state_root(workspace_root, config_name=config_name)
        / "manifest.json"
    )


def incomplete_run_publish_snapshot_root(
    workspace_root: Path, *, config_name: str
) -> Path:
    """Return the publish-snapshot root for one incomplete run."""
    return (
        incomplete_run_state_root(workspace_root, config_name=config_name)
        / "publish_snapshot"
    )


def incomplete_run_debug_root(workspace_root: Path, *, config_name: str) -> Path:
    """Return the debug root for one incomplete run."""
    return debug_artifacts_root(workspace_root) / "incomplete_runs" / config_name


def incomplete_run_raw_audit_path(workspace_root: Path, *, config_name: str) -> Path:
    """Return the partial raw-audit path for one incomplete run."""
    return (
        incomplete_run_debug_root(workspace_root, config_name=config_name)
        / "raw"
        / (f"{config_name}.jsonl")
    )


def batch_manifest_path(workspace_root: Path, *, batch_id: str) -> Path:
    """Return the workflow-state batch-manifest path."""
    return (
        workflow_state_root(workspace_root)
        / "batches"
        / batch_id
        / "batch-manifest.json"
    )


def worker_bundle_path(workspace_root: Path, *, batch_id: str, worker_id: str) -> Path:
    """Return the workflow-state worker-bundle path."""
    return (
        workflow_state_root(workspace_root)
        / "batches"
        / batch_id
        / "workers"
        / worker_id
        / "worker-bundle.json"
    )


def aggregate_input_review_path(workspace_root: Path, *, batch_id: str) -> Path:
    """Return the workflow-state prepare-owned review input path."""
    return (
        workflow_state_root(workspace_root)
        / "batches"
        / batch_id
        / "aggregate_inputs"
        / "review.csv"
    )


def aggregate_input_terminal_rows_path(workspace_root: Path, *, batch_id: str) -> Path:
    """Return the workflow-state prepare-owned terminal-row input path."""
    return (
        workflow_state_root(workspace_root)
        / "batches"
        / batch_id
        / "aggregate_inputs"
        / "terminal_rows.jsonl"
    )


def worker_status_path(workspace_root: Path, *, batch_id: str, worker_id: str) -> Path:
    """Return the workflow-state worker-status path."""
    return (
        workflow_state_root(workspace_root) / "status" / batch_id / f"{worker_id}.json"
    )


def worker_state_root(workspace_root: Path, *, batch_id: str, worker_id: str) -> Path:
    """Return the workflow-state root for one worker execution."""
    return workflow_state_root(workspace_root) / "workers" / batch_id / worker_id


def worker_publish_output_root(
    workspace_root: Path, *, batch_id: str, worker_id: str
) -> Path:
    """Return the publish-snapshot output root for one worker execution."""
    return (
        worker_state_root(workspace_root, batch_id=batch_id, worker_id=worker_id)
        / ("publish_snapshot")
        / "output"
    )


def worker_filtered_path(
    workspace_root: Path, *, batch_id: str, worker_id: str, config_name: str
) -> Path:
    """Return the worker filtered-output path."""
    return (
        worker_publish_output_root(
            workspace_root, batch_id=batch_id, worker_id=worker_id
        )
        / "filtered"
        / f"{config_name}.txt"
    )


def worker_dead_path(
    workspace_root: Path, *, batch_id: str, worker_id: str, config_name: str
) -> Path:
    """Return the worker dead-output path."""
    return (
        worker_publish_output_root(
            workspace_root, batch_id=batch_id, worker_id=worker_id
        )
        / "dead"
        / f"{config_name}.txt"
    )


def worker_review_path(
    workspace_root: Path, *, batch_id: str, worker_id: str, config_name: str
) -> Path:
    """Return the worker review-output path."""
    return (
        worker_publish_output_root(
            workspace_root, batch_id=batch_id, worker_id=worker_id
        )
        / "review"
        / f"{config_name}.csv"
    )


def worker_terminal_rows_path(
    workspace_root: Path, *, batch_id: str, worker_id: str, config_name: str
) -> Path:
    """Return the worker workflow-internal terminal-row JSONL path."""
    return (
        worker_state_root(workspace_root, batch_id=batch_id, worker_id=worker_id)
        / "terminal_rows"
        / f"{config_name}.jsonl"
    )


def worker_cache_path(workspace_root: Path, *, batch_id: str, worker_id: str) -> Path:
    """Return the worker overlay cache path."""
    return (
        worker_state_root(workspace_root, batch_id=batch_id, worker_id=worker_id)
        / "cache"
        / "check-cache.sqlite3"
    )


def worker_log_path(workspace_root: Path, *, batch_id: str, worker_id: str) -> Path:
    """Return the worker debug log path."""
    return (
        debug_artifacts_root(workspace_root)
        / "workers"
        / batch_id
        / worker_id
        / "logs"
        / "worker.log"
    )


def current_pointer_path(workspace_root: Path, *, config_name: str) -> Path:
    """Return the workflow-state current-pointer path for one config."""
    return workflow_state_root(workspace_root) / "current" / f"{config_name}.json"


def aggregate_done_marker_path(workspace_root: Path, *, batch_id: str) -> Path:
    """Return the workflow-state aggregate done-marker path."""
    return workflow_state_root(workspace_root) / "aggregate" / batch_id / "done.json"


def aggregate_failed_marker_path(workspace_root: Path, *, batch_id: str) -> Path:
    """Return the workflow-state aggregate failed-marker path."""
    return workflow_state_root(workspace_root) / "aggregate" / batch_id / "failed.json"
