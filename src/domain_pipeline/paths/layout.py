"""Object-owned path derivation for pipeline artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

PUBLISH_WORKTREE_DIR = Path(".publish_worktree")
WORKFLOW_STATE_DIR = Path(".workflow_state")
DEBUG_ARTIFACTS_DIR = Path(".debug_artifacts")


@dataclass(frozen=True)
class BatchPathSpec:
    """Repo path locations for one prepared pipeline-run batch."""

    prepare_aggregate_manifest: Path
    prepare_worker_manifest_root: Path

    def prepare_worker_manifest(self, *, worker_id: str) -> Path:
        """Return the persisted prepare-to-worker manifest path for one worker."""
        return (
            self.prepare_worker_manifest_root
            / worker_id
            / "prepare-worker-manifest.json"
        )


@dataclass(frozen=True)
class WorkerPathSpec:  # pylint: disable=too-many-instance-attributes
    """Repo path locations used during one worker execution."""

    result_root: Path
    output_directory: Path
    filtered: Path
    unactionable: Path
    review: Path
    terminal_rows: Path
    cache: Path
    debug_log: Path


@dataclass(frozen=True)
class AggregatePathSpec:
    """Repo paths persisted into the prepare-to-aggregate manifest."""

    filtered: Path
    unactionable: Path
    review: Path
    raw_audit: Path
    runtime_log: Path
    cache: Path


@dataclass(frozen=True)
class OutputPathLayout:
    """Derive publish-output and debug-artifact paths for one workspace."""

    workspace_root: Path

    def publish_worktree_root(self) -> Path:
        """Return the dedicated publish worktree root."""
        return self.workspace_root / PUBLISH_WORKTREE_DIR

    def debug_artifacts_root(self) -> Path:
        """Return the debug-artifact root."""
        return self.workspace_root / DEBUG_ARTIFACTS_DIR

    def runtime_raw_audit_path(self, *, config_name: str) -> Path:
        """Return the debug raw-audit path for one config."""
        return self.debug_artifacts_root() / "runtime" / "raw" / f"{config_name}.jsonl"

    def runtime_log_path(self, *, config_name: str) -> Path:
        """Return the merged runtime log path for one config."""
        return self.debug_artifacts_root() / "runtime" / "logs" / f"{config_name}.log"

    def aggregate_log_path(self, *, config_name: str) -> Path:
        """Return the aggregate-job log path for one config."""
        return (
            self.debug_artifacts_root()
            / "runtime"
            / "logs"
            / f"{config_name}--aggregate.log"
        )

    def worker_log_path(self, *, batch_id: str, worker_id: str) -> Path:
        """Return the worker debug log path."""
        return (
            self.debug_artifacts_root()
            / "workers"
            / batch_id
            / worker_id
            / "logs"
            / "worker.log"
        )


@dataclass(frozen=True)
class WorkflowPathLayout:  # pylint: disable=too-many-public-methods
    """Derive workflow-state paths for one workspace."""

    workspace_root: Path

    def workflow_state_root(self) -> Path:
        """Return the workflow-internal state root."""
        return self.workspace_root / WORKFLOW_STATE_DIR

    def runtime_cache_path(self) -> Path:
        """Return the shared runtime cache path."""
        return self.workflow_state_root() / "runtime" / "cache" / "check-cache.sqlite3"

    def batch_root(self, *, batch_id: str) -> Path:
        """Return the workflow-state root for one prepared batch."""
        return self.workflow_state_root() / "batches" / batch_id

    def prepare_worker_manifest_root(self, *, batch_id: str) -> Path:
        """Return the workflow-state prepare-to-worker manifest root."""
        return self.batch_root(batch_id=batch_id) / "workers"

    def worker_state_batch_root(self, *, batch_id: str) -> Path:
        """Return the workflow-state root for worker execution artifacts."""
        return self.workflow_state_root() / "workers" / batch_id

    def worker_status_batch_root(self, *, batch_id: str) -> Path:
        """Return the workflow-state root for worker status files."""
        return self.workflow_state_root() / "status" / batch_id

    def aggregate_marker_root(self, *, batch_id: str) -> Path:
        """Return the workflow-state root for aggregate markers."""
        return self.workflow_state_root() / "aggregate" / batch_id

    def prepare_aggregate_manifest_path(self, *, batch_id: str) -> Path:
        """Return the workflow-state prepare-to-aggregate manifest path."""
        return self.batch_root(batch_id=batch_id) / "prepare-aggregate-manifest.json"

    def prepare_worker_manifest_path(self, *, batch_id: str, worker_id: str) -> Path:
        """Return the workflow-state prepare-to-worker manifest path."""
        return (
            self.prepare_worker_manifest_root(batch_id=batch_id)
            / worker_id
            / "prepare-worker-manifest.json"
        )

    def worker_status_path(self, *, batch_id: str, worker_id: str) -> Path:
        """Return the workflow-state worker-status path."""
        return self.worker_status_batch_root(batch_id=batch_id) / f"{worker_id}.json"

    def worker_state_root(self, *, batch_id: str, worker_id: str) -> Path:
        """Return the workflow-state root for one worker execution."""
        return self.worker_state_batch_root(batch_id=batch_id) / worker_id

    def worker_aggregate_manifest_path(self, *, batch_id: str, worker_id: str) -> Path:
        """Return the worker-owned aggregate handoff manifest path."""
        return (
            self.worker_state_root(batch_id=batch_id, worker_id=worker_id)
            / "worker-aggregate-manifest.json"
        )

    def worker_publish_output_root(self, *, batch_id: str, worker_id: str) -> Path:
        """Return the publish-snapshot output root for one worker execution."""
        return (
            self.worker_state_root(batch_id=batch_id, worker_id=worker_id)
            / "publish_snapshot"
            / "output"
        )

    def worker_filtered_path(
        self, *, batch_id: str, worker_id: str, config_name: str
    ) -> Path:
        """Return the worker filtered-output path."""
        return (
            self.worker_publish_output_root(batch_id=batch_id, worker_id=worker_id)
            / "filtered"
            / f"{config_name}.txt"
        )

    def worker_unactionable_path(
        self, *, batch_id: str, worker_id: str, config_name: str
    ) -> Path:
        """Return the worker unactionable-output path."""
        return (
            self.worker_publish_output_root(batch_id=batch_id, worker_id=worker_id)
            / "unactionable"
            / f"{config_name}.txt"
        )

    def worker_review_path(
        self, *, batch_id: str, worker_id: str, config_name: str
    ) -> Path:
        """Return the worker review-output path."""
        return (
            self.worker_publish_output_root(batch_id=batch_id, worker_id=worker_id)
            / "review"
            / f"{config_name}.csv"
        )

    def worker_terminal_rows_path(
        self, *, batch_id: str, worker_id: str, config_name: str
    ) -> Path:
        """Return the worker workflow-internal terminal-row JSONL path."""
        return (
            self.worker_state_root(batch_id=batch_id, worker_id=worker_id)
            / "terminal_rows"
            / f"{config_name}.jsonl"
        )

    def worker_cache_path(self, *, batch_id: str, worker_id: str) -> Path:
        """Return the worker overlay cache path."""
        return (
            self.worker_state_root(batch_id=batch_id, worker_id=worker_id)
            / "cache"
            / "check-cache.sqlite3"
        )

    def aggregate_failed_marker_path(self, *, batch_id: str) -> Path:
        """Return the workflow-state aggregate failed-marker path."""
        return self.aggregate_marker_root(batch_id=batch_id) / "failed.json"


@dataclass(frozen=True)
class PathLayout:
    """Workspace-root owner for all pipeline path derivation."""

    workspace_root: Path

    @property
    def workflow(self) -> WorkflowPathLayout:
        """Return workflow-state path derivation."""
        return WorkflowPathLayout(self.workspace_root)

    @property
    def output(self) -> OutputPathLayout:
        """Return publish/debug path derivation."""
        return OutputPathLayout(self.workspace_root)

    def publish_worktree_root(self) -> Path:
        """Return the dedicated publish worktree root."""
        return self.output.publish_worktree_root()

    def workflow_state_root(self) -> Path:
        """Return the workflow-internal state root."""
        return self.workflow.workflow_state_root()

    def debug_artifacts_root(self) -> Path:
        """Return the debug-artifact root."""
        return self.output.debug_artifacts_root()

    def runtime_cache_path(self) -> Path:
        """Return the shared runtime cache path."""
        return self.workflow.runtime_cache_path()

    def batch_paths(self, *, batch_id: str) -> BatchPathSpec:
        """Return persisted prepare-owned handoff paths for one batch."""
        return BatchPathSpec(
            prepare_aggregate_manifest=self.workflow.prepare_aggregate_manifest_path(
                batch_id=batch_id
            ),
            prepare_worker_manifest_root=self.workflow.prepare_worker_manifest_root(
                batch_id=batch_id
            ),
        )

    def worker_paths(
        self, *, batch_id: str, worker_id: str, config_name: str
    ) -> WorkerPathSpec:
        """Return persisted worker path values for one worker."""
        return WorkerPathSpec(
            result_root=self.workflow.worker_state_root(
                batch_id=batch_id,
                worker_id=worker_id,
            ),
            output_directory=self.workflow.worker_publish_output_root(
                batch_id=batch_id,
                worker_id=worker_id,
            ),
            filtered=self.workflow.worker_filtered_path(
                batch_id=batch_id,
                worker_id=worker_id,
                config_name=config_name,
            ),
            unactionable=self.workflow.worker_unactionable_path(
                batch_id=batch_id,
                worker_id=worker_id,
                config_name=config_name,
            ),
            review=self.workflow.worker_review_path(
                batch_id=batch_id,
                worker_id=worker_id,
                config_name=config_name,
            ),
            terminal_rows=self.workflow.worker_terminal_rows_path(
                batch_id=batch_id,
                worker_id=worker_id,
                config_name=config_name,
            ),
            cache=self.workflow.worker_cache_path(
                batch_id=batch_id,
                worker_id=worker_id,
            ),
            debug_log=self.output.worker_log_path(
                batch_id=batch_id,
                worker_id=worker_id,
            ),
        )

    def aggregate_paths(
        self, *, config_name: str, output_directory: Path
    ) -> AggregatePathSpec:
        """Return persisted aggregate paths while preserving config-owned outputs."""
        return AggregatePathSpec(
            filtered=output_directory / "filtered" / f"{config_name}.txt",
            unactionable=output_directory / "unactionable" / f"{config_name}.txt",
            review=output_directory / "review" / f"{config_name}.csv",
            raw_audit=self.output.runtime_raw_audit_path(config_name=config_name),
            runtime_log=self.output.runtime_log_path(config_name=config_name),
            cache=self.workflow.runtime_cache_path(),
        )
