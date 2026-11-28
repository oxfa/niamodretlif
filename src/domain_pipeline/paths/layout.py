"""Object-owned path derivation for pipeline artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

PUBLISH_WORKTREE_DIR = Path(".publish_worktree")
WORKFLOW_STATE_DIR = Path(".workflow_state")
DEBUG_ARTIFACTS_DIR = Path(".debug_artifacts")


@dataclass(frozen=True)
class WorkerOutputPaths:
    """Publish-snapshot output paths for one worker execution."""

    output_directory: Path
    unactionable: Path
    review: Path


@dataclass(frozen=True)
class WorkerStatePaths:
    """Workflow-state and debug paths for one worker execution."""

    result_root: Path
    domain_results: Path
    cache: Path
    debug_log: Path


@dataclass(frozen=True)
class WorkerPathSpec:
    """Repo path locations used during one worker execution."""

    state: WorkerStatePaths
    output: WorkerOutputPaths

    @property
    def result_root(self) -> Path:
        """Return the worker workflow-state root."""
        return self.state.result_root

    @property
    def output_directory(self) -> Path:
        """Return the worker publish-snapshot output directory."""
        return self.output.output_directory

    @property
    def unactionable(self) -> Path:
        """Return the worker unactionable-output path."""
        return self.output.unactionable

    @property
    def review(self) -> Path:
        """Return the worker review-output path."""
        return self.output.review

    @property
    def domain_results(self) -> Path:
        """Return the worker domain-result JSONL path."""
        return self.state.domain_results

    @property
    def cache(self) -> Path:
        """Return the worker overlay cache path."""
        return self.state.cache

    @property
    def debug_log(self) -> Path:
        """Return the worker debug log path."""
        return self.state.debug_log


@dataclass(frozen=True)
class AggregatePathSpec:
    """Internal paths persisted into the prepare-to-aggregate manifest."""

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

    def worker_log_path(self, *, batch_id: str, worker_id: str) -> Path:
        """Return the worker debug log path."""
        return (
            self.debug_artifacts_root() / "workers" / batch_id / worker_id / "logs" / "worker.log"
        )

    def worker_cache_log_path(self, *, batch_id: str, worker_id: str) -> Path:
        """Return the worker cache diagnostic path."""
        return self.worker_log_path(batch_id=batch_id, worker_id=worker_id).with_name("cache.log")

    def prepare_log_path(self, *, stage: str, filename: str) -> Path:
        """Return a preparation diagnostic path."""
        return self.debug_artifacts_root() / "prepare" / stage / "logs" / filename


@dataclass(frozen=True)
class WorkflowStateBasePaths:
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

    def batch_source_items_path(self, *, batch_id: str) -> Path:
        """Return the JSONL path for prepare-owned source-item records."""
        return self.batch_root(batch_id=batch_id) / "source-items.jsonl"

    def batch_source_item_index_path(self, *, batch_id: str) -> Path:
        """Return the prepare-owned source-item collection index path."""
        return self.batch_root(batch_id=batch_id) / "source-item-index.json"

    def batch_source_item_diagnostics_path(self, *, batch_id: str) -> Path:
        """Return the prepare-owned source-item diagnostics path."""
        return self.batch_root(batch_id=batch_id) / "source-item-diagnostics.jsonl"

    def prepare_worker_manifest_root(self, *, batch_id: str) -> Path:
        """Return the workflow-state prepare-to-worker manifest root."""
        return self.batch_root(batch_id=batch_id) / "workers"


@dataclass(frozen=True)
class PrepareHandoffPaths(WorkflowStateBasePaths):
    """Derive prepare handoff paths."""

    def prepare_worker_config_path(self, *, batch_id: str, worker_id: str) -> Path:
        """Return the prepare worker config path."""
        return (
            self.prepare_worker_manifest_root(batch_id=batch_id) / worker_id / "runtime-config.json"
        )

    def prepare_worker_identity_path(self, *, batch_id: str, worker_id: str) -> Path:
        """Return the compact identity record for a hosted worker handoff."""
        return (
            self.prepare_worker_manifest_root(batch_id=batch_id)
            / worker_id
            / "worker-identity.json"
        )

    def prepare_aggregate_config_path(self, *, batch_id: str) -> Path:
        """Return the prepare aggregate config path."""
        return self.batch_root(batch_id=batch_id) / "output-config.yaml"

    def batch_worker_ids_path(self, *, batch_id: str) -> Path:
        """Return the batch worker ids path."""
        return self.batch_root(batch_id=batch_id) / "worker-ids.csv"

    def batch_manual_domains_path(self, *, batch_id: str) -> Path:
        """Return the batch manual domains path."""
        return self.batch_root(batch_id=batch_id) / "manual-domains.csv"

    def batch_preparation_terminal_path(self, *, batch_id: str) -> Path:
        """Return the batch preparation terminal path."""
        return self.batch_root(batch_id=batch_id) / "preparation-terminal.yaml"

    def worker_result_batch_root(self, *, batch_id: str) -> Path:
        """Return the worker result batch root."""
        return self.workflow_state_root() / "worker-results" / batch_id

    def worker_result_root(self, *, batch_id: str, worker_id: str) -> Path:
        """Return the worker result root."""
        return self.worker_result_batch_root(batch_id=batch_id) / worker_id

    def worker_handoff_unactionable_path(self, *, batch_id: str, worker_id: str) -> Path:
        """Return the worker handoff unactionable path."""
        return (
            self.worker_result_root(batch_id=batch_id, worker_id=worker_id)
            / "unactionable-input-domains.txt"
        )

    def worker_handoff_review_path(self, *, batch_id: str, worker_id: str) -> Path:
        """Return the worker handoff review path."""
        return (
            self.worker_result_root(batch_id=batch_id, worker_id=worker_id)
            / "review-results-by-input-domain.csv"
        )

    def worker_handoff_domain_results_path(
        self, *, batch_id: str, worker_id: str
    ) -> Path:
        """Return the worker handoff domain-result path."""
        return (
            self.worker_result_root(batch_id=batch_id, worker_id=worker_id)
            / "domain-results.jsonl"
        )

    def worker_handoff_cache_path(self, *, batch_id: str, worker_id: str) -> Path:
        """Return the worker handoff cache path."""
        return self.worker_result_root(batch_id=batch_id, worker_id=worker_id) / "cache.sqlite3"

@dataclass(frozen=True)
class WorkflowStatePathLayout(PrepareHandoffPaths):
    """Derive remaining workflow paths."""

    def worker_state_batch_root(self, *, batch_id: str) -> Path:
        """Return the workflow-state root for worker execution artifacts."""
        return self.workflow_state_root() / "workers" / batch_id

    def worker_status_batch_root(self, *, batch_id: str) -> Path:
        """Return the workflow-state root for worker status files."""
        return self.workflow_state_root() / "status" / batch_id

    def aggregate_marker_root(self, *, batch_id: str) -> Path:
        """Return the workflow-state root for aggregate markers."""
        return self.workflow_state_root() / "aggregate" / batch_id

    def worker_status_path(self, *, batch_id: str, worker_id: str) -> Path:
        """Return the workflow-state worker-status path."""
        return self.worker_status_batch_root(batch_id=batch_id) / f"{worker_id}.yaml"

    def worker_state_root(self, *, batch_id: str, worker_id: str) -> Path:
        """Return the workflow-state root for one worker execution."""
        return self.worker_state_batch_root(batch_id=batch_id) / worker_id

    def worker_aggregate_manifest_path(self, *, batch_id: str, worker_id: str) -> Path:
        """Return the worker-owned aggregate handoff manifest path."""
        return (
            self.worker_result_root(batch_id=batch_id, worker_id=worker_id) / "handoff-state.yaml"
        )

    def worker_publish_output_root(self, *, batch_id: str, worker_id: str) -> Path:
        """Return the publish-snapshot output root for one worker execution."""
        return (
            self.worker_state_root(batch_id=batch_id, worker_id=worker_id)
            / "publish_snapshot"
            / "output"
        )

    def worker_unactionable_path(self, *, batch_id: str, worker_id: str, config_name: str) -> Path:
        """Return the worker input-domain unactionable-output path."""
        return (
            self.worker_publish_output_root(batch_id=batch_id, worker_id=worker_id)
            / "unactionable-input-domains"
            / f"{config_name}.txt"
        )

    def worker_review_path(self, *, batch_id: str, worker_id: str, config_name: str) -> Path:
        """Return the worker input-domain review-output path."""
        return (
            self.worker_publish_output_root(batch_id=batch_id, worker_id=worker_id)
            / "review-results-by-input-domain"
            / f"{config_name}.csv"
        )

    def worker_domain_results_path(
        self, *, batch_id: str, worker_id: str, config_name: str
    ) -> Path:
        """Return the worker workflow-internal domain-result JSONL path."""
        return (
            self.worker_state_root(batch_id=batch_id, worker_id=worker_id)
            / "domain_results"
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
class HandoffMember:
    """A local source and its canonical archive-relative destination."""

    source: Path
    archive_path: Path
    required: bool = False


def _member(
    root: Path, source: Path, destination: Path | None = None, *, required: bool = False
) -> HandoffMember:
    return HandoffMember(source, (destination or source).relative_to(root), required)


@dataclass(frozen=True)
class PrepareToWorkerPathLayout:
    """Member paths for a single prepare-to-worker handoff."""

    workspace_root: Path

    def members(self, *, batch_id: str, worker_id: str) -> tuple[HandoffMember, ...]:
        """Return the manifest needed by the designated worker."""
        state = WorkflowStatePathLayout(self.workspace_root)
        paths = (
            state.prepare_worker_config_path(batch_id=batch_id, worker_id=worker_id),
            state.prepare_worker_identity_path(batch_id=batch_id, worker_id=worker_id),
        )
        return tuple(_member(self.workspace_root, path, required=True) for path in paths)


_PREPARE_DIAGNOSTICS = {
    "settings": ("validation", "settings.yaml"),
    "validation-log": ("validation", "validate-settings.log"),
    "batch": ("batch", "batch.yaml"),
    "batch-log": ("batch", "prepare-batch.log"),
}


@dataclass(frozen=True)
class PrepareToAggregatorPathLayout:
    """Member paths for the prepare-to-aggregator handoff."""

    workspace_root: Path

    def members(self, *, batch_id: str) -> tuple[HandoffMember, ...]:
        """Return the shared inputs and diagnostics needed by aggregation."""
        state = WorkflowStatePathLayout(self.workspace_root)
        output = OutputPathLayout(self.workspace_root)
        runtime = (
            state.prepare_aggregate_config_path(batch_id=batch_id),
            state.batch_worker_ids_path(batch_id=batch_id),
            state.batch_manual_domains_path(batch_id=batch_id),
            state.batch_preparation_terminal_path(batch_id=batch_id),
            state.batch_source_items_path(batch_id=batch_id),
            state.batch_source_item_index_path(batch_id=batch_id),
            state.batch_source_item_diagnostics_path(batch_id=batch_id),
        )
        diagnostics = _PREPARE_DIAGNOSTICS.values()
        return tuple(
            _member(
                self.workspace_root,
                path,
                required=True,
            )
            for path in runtime
        ) + tuple(
            _member(
                self.workspace_root,
                self.workspace_root
                / (
                    filename.removesuffix(".yaml") + ".json"
                    if filename.endswith(".yaml")
                    else filename
                ),
                output.prepare_log_path(stage=stage, filename=filename),
            )
            for stage, filename in diagnostics
        )

    def diagnostic_member(self, *, batch_id: str, kind: str) -> HandoffMember:
        """Return a declared prepare diagnostic archive member."""
        stage, filename = _PREPARE_DIAGNOSTICS[kind]
        archive_path = OutputPathLayout(self.workspace_root).prepare_log_path(
            stage=stage, filename=filename
        ).relative_to(self.workspace_root)
        return next(member for member in self.members(batch_id=batch_id)
                    if member.archive_path == archive_path)


@dataclass(frozen=True)
class WorkerToAggregatorPathLayout:
    """Member paths for a single worker-to-aggregator handoff."""

    workspace_root: Path

    def members(self, *, batch_id: str, worker_id: str) -> tuple[HandoffMember, ...]:
        """Return the designated worker's aggregation outputs and logs."""
        state = WorkflowStatePathLayout(self.workspace_root)
        output = OutputPathLayout(self.workspace_root)
        paths = (
            state.worker_handoff_unactionable_path(batch_id=batch_id, worker_id=worker_id),
            state.worker_handoff_review_path(batch_id=batch_id, worker_id=worker_id),
            state.worker_handoff_domain_results_path(
                batch_id=batch_id, worker_id=worker_id
            ),
            state.worker_handoff_cache_path(batch_id=batch_id, worker_id=worker_id),
            state.worker_aggregate_manifest_path(batch_id=batch_id, worker_id=worker_id),
            state.worker_status_path(batch_id=batch_id, worker_id=worker_id),
            output.worker_log_path(batch_id=batch_id, worker_id=worker_id),
            output.worker_cache_log_path(batch_id=batch_id, worker_id=worker_id),
        )
        return tuple(_member(self.workspace_root, path) for path in paths)

    def diagnostic_member(self, *, batch_id: str, worker_id: str, kind: str) -> HandoffMember:
        """Return a declared worker diagnostic archive member."""
        output = OutputPathLayout(self.workspace_root)
        paths = {"worker-log": output.worker_log_path, "cache-log": output.worker_cache_log_path}
        archive_path = paths[kind](batch_id=batch_id, worker_id=worker_id).relative_to(
            self.workspace_root
        )
        return next(member for member in self.members(batch_id=batch_id, worker_id=worker_id)
                    if member.archive_path == archive_path)


@dataclass(frozen=True)
class PathLayout:
    """Workspace-root owner for all pipeline path derivation."""

    workspace_root: Path

    @property
    def workflow_state(self) -> WorkflowStatePathLayout:
        """Return workflow-state path derivation."""
        return WorkflowStatePathLayout(self.workspace_root)

    @property
    def output(self) -> OutputPathLayout:
        """Return publish/debug path derivation."""
        return OutputPathLayout(self.workspace_root)

    @property
    def prepare_to_worker(self) -> PrepareToWorkerPathLayout:
        """Return prepare-to-worker handoff paths."""
        return PrepareToWorkerPathLayout(self.workspace_root)

    @property
    def prepare_to_aggregator(self) -> PrepareToAggregatorPathLayout:
        """Return prepare-to-aggregator handoff paths."""
        return PrepareToAggregatorPathLayout(self.workspace_root)

    @property
    def worker_to_aggregator(self) -> WorkerToAggregatorPathLayout:
        """Return worker-to-aggregator handoff paths."""
        return WorkerToAggregatorPathLayout(self.workspace_root)

    def worker_paths(self, *, batch_id: str, worker_id: str, config_name: str) -> WorkerPathSpec:
        """Return persisted worker path values for one worker."""
        return WorkerPathSpec(
            state=WorkerStatePaths(
                result_root=self.workflow_state.worker_state_root(
                    batch_id=batch_id,
                    worker_id=worker_id,
                ),
                domain_results=self.workflow_state.worker_domain_results_path(
                    batch_id=batch_id,
                    worker_id=worker_id,
                    config_name=config_name,
                ),
                cache=self.workflow_state.worker_cache_path(
                    batch_id=batch_id,
                    worker_id=worker_id,
                ),
                debug_log=self.output.worker_log_path(
                    batch_id=batch_id,
                    worker_id=worker_id,
                ),
            ),
            output=WorkerOutputPaths(
                output_directory=self.workflow_state.worker_publish_output_root(
                    batch_id=batch_id,
                    worker_id=worker_id,
                ),
                unactionable=self.workflow_state.worker_unactionable_path(
                    batch_id=batch_id,
                    worker_id=worker_id,
                    config_name=config_name,
                ),
                review=self.workflow_state.worker_review_path(
                    batch_id=batch_id,
                    worker_id=worker_id,
                    config_name=config_name,
                ),
            ),
        )

    def aggregate_paths(self, *, config_name: str) -> AggregatePathSpec:
        """Return aggregate-owned state paths; publish paths come from config."""
        return AggregatePathSpec(
            raw_audit=self.output.runtime_raw_audit_path(config_name=config_name),
            runtime_log=self.output.runtime_log_path(config_name=config_name),
            cache=self.workflow_state.runtime_cache_path(),
        )
