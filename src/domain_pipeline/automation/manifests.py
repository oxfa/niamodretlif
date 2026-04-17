"""Typed persisted manifests for automation batch, worker, and aggregate state."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from domain_pipeline.path_layout import publish_worktree_root


class AutomationModel(BaseModel):
    """Base automation manifest model that rejects unknown fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ConfigIdentity(AutomationModel):
    """Stable config identity captured during batch preparation."""

    config_name: str
    config_path: str
    config_file_name: str


class WorkerOutputSpec(AutomationModel):
    """Repo-relative per-worker publish-snapshot and internal-state paths."""

    result_root: str
    filtered: str
    dead: str
    review: str
    terminal_rows: str
    cache: str

    def resolve_paths(self, state_root: Path) -> dict[str, Path]:
        """Return resolved per-worker paths rooted at one automation workspace root."""
        return {
            "result_root": state_root / Path(self.result_root),
            "filtered": state_root / Path(self.filtered),
            "dead": state_root / Path(self.dead),
            "review": state_root / Path(self.review),
            "terminal_rows": state_root / Path(self.terminal_rows),
            "cache": state_root / Path(self.cache),
        }


class AggregateOutputSpec(AutomationModel):
    """Repo-relative aggregate output/cache/log paths."""

    filtered: str
    dead: str
    review: str
    audit: str
    log: str
    cache: str
    current: str

    def resolve_paths(self, state_root: Path) -> dict[str, Path]:
        """Return resolved aggregate paths rooted at one automation workspace root."""
        publish_root = publish_worktree_root(state_root)
        return {
            "filtered": publish_root / Path(self.filtered),
            "dead": publish_root / Path(self.dead),
            "review": publish_root / Path(self.review),
            "audit": state_root / Path(self.audit),
            "log": state_root / Path(self.log),
            "cache": state_root / Path(self.cache),
            "current": state_root / Path(self.current),
        }


class PreparedRuntimeMetadata(AutomationModel):
    """Prepared metadata consumed by the automation worker runtime fast path."""

    prepared_source_ids: list[str] = Field(default_factory=list)
    sources: dict[str, dict[str, Any]] = Field(default_factory=dict)
    rdap_roots: dict[str, dict[str, Any]] = Field(default_factory=dict)
    terminal_rows: list[dict[str, Any]] = Field(default_factory=list)

    def to_runtime_payload(self) -> dict[str, Any]:
        """Return a mutable runtime payload preserving the current metadata shape."""
        return copy.deepcopy(self.model_dump())


class WorkerRuntimeSpec(AutomationModel):
    """Manifest-owned runtime config for one worker execution."""

    config_identity: ConfigIdentity
    cache: dict[str, Any]
    sources: list[dict[str, Any]]
    output_spec: WorkerOutputSpec
    debug_log_path: str
    runtime_paths: dict[str, str] = Field(default_factory=dict)

    def to_runtime_payload(
        self,
        *,
        source_root: Path,
        state_root: Path,
    ) -> dict[str, Any]:
        """Return the runtime config payload with paths resolved for execution."""
        payload = {
            "version": 2,
            "config_name": self.config_identity.config_name,
            "config_path": self.config_identity.config_path,
            "config_file_name": self.config_identity.config_file_name,
            "cache": copy.deepcopy(self.cache),
            "sources": copy.deepcopy(self.sources),
            "runtime_paths": copy.deepcopy(self.runtime_paths),
        }
        cache_payload = payload["cache"]
        cache_file = str(cache_payload.get("cache_file", "")).strip()
        baseline_cache_file = str(cache_payload.get("baseline_cache_file", "")).strip()
        if cache_file:
            cache_payload["cache_file"] = str((state_root / Path(cache_file)).resolve())
        if baseline_cache_file:
            cache_payload["baseline_cache_file"] = str(
                (source_root / Path(baseline_cache_file)).resolve()
            )
        for source in payload["sources"]:
            output_payload = source.get("output", {})
            directory = str(output_payload.get("directory", "")).strip()
            if directory:
                output_payload["directory"] = str(
                    (state_root / Path(directory)).resolve()
                )
            output_payload["terminal_rows_file"] = str(
                (state_root / Path(self.output_spec.terminal_rows)).resolve()
            )
        for key, raw_value in payload["runtime_paths"].items():
            stripped = str(raw_value).strip()
            if not stripped:
                continue
            payload["runtime_paths"][key] = str((state_root / Path(stripped)).resolve())
        return payload


class WorkerBundleManifest(AutomationModel):
    """Persisted worker-owned automation manifest."""

    automation_format_version: int
    batch_id: str
    worker_id: str
    runtime_spec: WorkerRuntimeSpec
    prepared_metadata: PreparedRuntimeMetadata

    @classmethod
    def from_assignment(
        cls,
        *,
        automation_format_version: int,
        batch_id: str,
        worker_id: str,
        runtime_spec: WorkerRuntimeSpec,
        prepared_metadata: PreparedRuntimeMetadata,
    ) -> "WorkerBundleManifest":
        """Build one persisted worker bundle from prepared assignment state."""
        return cls(
            automation_format_version=automation_format_version,
            batch_id=batch_id,
            worker_id=worker_id,
            runtime_spec=runtime_spec,
            prepared_metadata=prepared_metadata,
        )

    def resolve_paths(self, state_root: Path) -> dict[str, Path]:
        """Return resolved worker output paths for this bundle."""
        return self.runtime_spec.output_spec.resolve_paths(state_root)


class BatchManifest(AutomationModel):
    """Persisted batch-wide aggregate manifest."""

    automation_format_version: int
    batch_id: str
    config_identity: ConfigIdentity
    aggregate_output_spec: AggregateOutputSpec
    worker_ids: list[str]
    aggregate_input_review_path: str
    aggregate_input_terminal_rows_path: str

    @classmethod
    def from_prepared_batch(
        cls,
        *,
        automation_format_version: int,
        batch_id: str,
        config_identity: ConfigIdentity,
        aggregate_output_spec: AggregateOutputSpec,
        worker_ids: list[str],
        aggregate_input_review_path: str,
        aggregate_input_terminal_rows_path: str,
    ) -> "BatchManifest":
        """Build one persisted batch manifest from prepared batch state."""
        return cls(
            automation_format_version=automation_format_version,
            batch_id=batch_id,
            config_identity=config_identity,
            aggregate_output_spec=aggregate_output_spec,
            worker_ids=list(worker_ids),
            aggregate_input_review_path=aggregate_input_review_path,
            aggregate_input_terminal_rows_path=aggregate_input_terminal_rows_path,
        )

    def resolve_paths(self, state_root: Path) -> dict[str, Path]:
        """Return resolved aggregate-managed paths for this batch."""
        resolved = self.aggregate_output_spec.resolve_paths(state_root)
        resolved["aggregate_input_review"] = state_root / Path(
            self.aggregate_input_review_path
        )
        resolved["aggregate_input_terminal_rows"] = state_root / Path(
            self.aggregate_input_terminal_rows_path
        )
        return resolved


def _load_json_object(path: Path) -> dict[str, Any]:
    """Load one manifest file and require a JSON object root."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read automation manifest {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"automation manifest {path} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError(f"automation manifest {path} must be a JSON object")
    return payload


def load_worker_bundle_manifest(path: Path) -> WorkerBundleManifest:
    """Load and validate one persisted worker bundle manifest."""
    payload = _load_json_object(path)
    try:
        return WorkerBundleManifest.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(f"invalid worker bundle manifest {path}: {exc}") from exc


def load_batch_manifest(path: Path) -> BatchManifest:
    """Load and validate one persisted batch manifest."""
    payload = _load_json_object(path)
    try:
        return BatchManifest.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(f"invalid batch manifest {path}: {exc}") from exc
