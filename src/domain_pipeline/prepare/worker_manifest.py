"""Prepare-owned manifests consumed by worker jobs."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from domain_pipeline.paths import PathLayout


class PrepareWorkerModel(BaseModel):
    """Base prepare-to-worker manifest model that rejects unknown fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ConfigIdentity(PrepareWorkerModel):
    """Stable config identity captured during batch preparation."""

    config_name: str
    config_path: str
    config_file_name: str


class WorkerOutputSpec(PrepareWorkerModel):
    """Repo-relative per-worker publish-snapshot and internal-state paths."""

    result_root: str
    filtered: str
    unactionable: str
    review: str
    terminal_rows: str
    cache: str

    def resolve_paths(self, state_root: Path) -> dict[str, Path]:
        """Return resolved per-worker paths rooted at one pipeline-run workspace root."""
        return {
            "result_root": state_root / Path(self.result_root),
            "filtered": state_root / Path(self.filtered),
            "unactionable": state_root / Path(self.unactionable),
            "review": state_root / Path(self.review),
            "terminal_rows": state_root / Path(self.terminal_rows),
            "cache": state_root / Path(self.cache),
        }


class PreparedHostEntryMetadata(PrepareWorkerModel):
    """Worker-local prepared host entry owned by one delegation root."""

    host: str
    input_name: str
    source_id: str
    input_kind: str = "exact_host"
    apex_scope: str = "exact_only"
    source_format: str = "plain"
    manual_filter_pass: bool = False
    manual_add: bool = False
    source_id_override: str | None = None
    source_input_label_override: str | None = None
    source_ids: list[str] = Field(default_factory=list)
    source_input_labels: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_host_entry_metadata(self) -> "PreparedHostEntryMetadata":
        if not self.host:
            raise ValueError("prepared host entry host is required")
        if not self.input_name:
            raise ValueError("prepared host entry input_name is required")
        if not self.source_id:
            raise ValueError("prepared host entry source_id is required")
        return self


class PreparedDelegationRootMetadata(PrepareWorkerModel):
    """Worker-local root metadata with root-owned prepared host entries."""

    public_suffix: str
    delegation_config_source_id: str
    delegation_behavior_fingerprint: str
    host_entries: list[PreparedHostEntryMetadata]

    @model_validator(mode="after")
    def _validate_root_metadata(self) -> "PreparedDelegationRootMetadata":
        if not self.public_suffix:
            raise ValueError("delegation root public_suffix is required")
        if not self.delegation_config_source_id:
            raise ValueError("delegation root delegation_config_source_id is required")
        if not self.delegation_behavior_fingerprint:
            raise ValueError(
                "delegation root delegation_behavior_fingerprint is required"
            )
        if not self.host_entries:
            raise ValueError("delegation root host_entries must not be empty")
        return self


class PreparedRuntimeMetadata(PrepareWorkerModel):
    """Root-owned prepared metadata consumed by the worker runtime fast path."""

    delegation_roots: dict[str, PreparedDelegationRootMetadata] = Field(
        default_factory=dict
    )

    @model_validator(mode="after")
    def _validate_delegation_root_keys(self) -> "PreparedRuntimeMetadata":
        for root_key in self.delegation_roots:
            if not root_key:
                raise ValueError(
                    "delegation_roots key must be a non-empty registrable domain"
                )
        return self

    def to_runtime_payload(self) -> dict[str, Any]:
        """Return a mutable runtime payload preserving the current metadata shape."""
        return copy.deepcopy(self.model_dump())


class WorkerRuntimeSpec(PrepareWorkerModel):
    """Prepare-owned runtime config for one worker execution."""

    config_identity: ConfigIdentity
    cache: dict[str, Any]
    runtime: dict[str, Any] = Field(default_factory=dict)
    sources: list[dict[str, Any]]
    output_spec: WorkerOutputSpec
    debug_log_path: str

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
            "runtime": copy.deepcopy(self.runtime),
            "sources": copy.deepcopy(self.sources),
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
        return payload


class PrepareWorkerManifest(PrepareWorkerModel):
    """Persisted prepare-to-worker runtime manifest."""

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
    ) -> "PrepareWorkerManifest":
        """Build one prepare-to-worker manifest from prepared assignment state."""
        return cls(
            automation_format_version=automation_format_version,
            batch_id=batch_id,
            worker_id=worker_id,
            runtime_spec=runtime_spec,
            prepared_metadata=prepared_metadata,
        )

    def resolve_paths(self, state_root: Path) -> dict[str, Path]:
        """Return resolved worker output paths for this manifest."""
        return self.runtime_spec.output_spec.resolve_paths(state_root)

    def resolve_log_path(self, state_root: Path) -> Path:
        """Return the resolved worker debug log path persisted in this manifest."""
        return state_root / Path(self.runtime_spec.debug_log_path)


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(
            f"unable to read prepare worker manifest {path}: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"prepare worker manifest {path} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError(f"prepare worker manifest {path} must be a JSON object")
    return payload


def load_prepare_worker_manifest(path: Path) -> PrepareWorkerManifest:
    """Load and validate one persisted prepare-to-worker manifest."""
    payload = _load_json_object(path)
    try:
        return PrepareWorkerManifest.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(f"invalid prepare worker manifest {path}: {exc}") from exc


def load_prepare_worker_manifest_for_worker(
    *,
    batch_id: str,
    worker_id: str,
    state_root: Path,
) -> PrepareWorkerManifest | None:
    """Load one prepare-to-worker manifest by workflow convention when it exists."""
    manifest_path = state_root / PathLayout(
        Path(".")
    ).workflow.prepare_worker_manifest_path(
        batch_id=batch_id,
        worker_id=worker_id,
    )
    if not manifest_path.is_file():
        return None
    return load_prepare_worker_manifest(manifest_path)
