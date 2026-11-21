"""Prepare-owned manifests consumed by aggregate jobs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from domain_pipeline.paths.layout import PathLayout


def _validate_publish_path(value: str, *, field_name: str) -> str:
    """Validate a repo-relative publish path stored in the aggregate manifest."""
    normalized_value = value.strip()
    path = Path(normalized_value)
    if (
        not normalized_value
        or normalized_value == "."
        or normalized_value.endswith("/")
        or "\\" in normalized_value
    ):
        raise ValueError(f"{field_name} must be a safe relative publish path")
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{field_name} must be a safe relative publish path")
    return path.as_posix()


class PrepareAggregateModel(BaseModel):
    """Base prepare-to-aggregate manifest model that rejects unknown fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class FilteredOutputSpec(PrepareAggregateModel):
    """One filtered output path and its rendered line format."""

    path: str
    format: Literal["plain", "hosts", "adblock"]

    @field_validator("path")
    @classmethod
    def _validate_path(cls, value: str) -> str:
        return _validate_publish_path(value, field_name="filtered[].path")


class AggregateOutputSpec(PrepareAggregateModel):
    """Repo-relative aggregate output/cache/log paths."""

    filtered: list[FilteredOutputSpec] = Field(min_length=1)
    unactionable: str
    review: str
    audit: str
    log: str
    cache: str

    @field_validator("unactionable", "review")
    @classmethod
    def _validate_publish_paths(cls, value: str, info: Any) -> str:
        return _validate_publish_path(
            value,
            field_name=f"output.{info.field_name}",
        )

    def resolve_paths(self, state_root: Path) -> dict[str, Path]:
        """Return resolved aggregate paths rooted at one pipeline-run workspace root."""
        publish_root = PathLayout(state_root).publish_worktree_root()
        return {
            "unactionable": publish_root / Path(self.unactionable),
            "review": publish_root / Path(self.review),
            "audit": state_root / Path(self.audit),
            "log": state_root / Path(self.log),
            "cache": state_root / Path(self.cache),
        }

    def resolve_filtered(self, state_root: Path) -> list[tuple[Path, str]]:
        """Resolve configured filtered outputs in the publish worktree."""
        publish_root = PathLayout(state_root).publish_worktree_root()
        return [(publish_root / Path(item.path), item.format) for item in self.filtered]


class PrepareAggregateManifest(PrepareAggregateModel):
    """Persisted prepare-to-aggregate JSON data handoff."""

    automation_format_version: int
    batch_id: str
    aggregate_output_spec: AggregateOutputSpec
    worker_ids: list[str]
    preparation_review_output_rows: list[dict[str, str]]
    preparation_terminal_rows: list[dict[str, Any]]
    preparation_filtered_output_values: list[str] = Field(default_factory=list)

    def resolve_paths(self, state_root: Path) -> dict[str, Path]:
        """Return resolved aggregate-managed paths for this batch."""
        return self.aggregate_output_spec.resolve_paths(state_root)


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(
            f"unable to read prepare aggregate manifest {path}: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"prepare aggregate manifest {path} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError(f"prepare aggregate manifest {path} must be a JSON object")
    return payload


def load_prepare_aggregate_manifest(path: Path) -> PrepareAggregateManifest:
    """Load and validate one persisted prepare-to-aggregate manifest."""
    payload = _load_json_object(path)
    try:
        return PrepareAggregateManifest.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(f"invalid prepare aggregate manifest {path}: {exc}") from exc


def load_prepare_aggregate_manifest_for_batch(
    *,
    batch_id: str,
    state_root: Path,
) -> PrepareAggregateManifest:
    """Load the prepare-to-aggregate manifest required by aggregate execution."""
    manifest_path = state_root / PathLayout(
        Path(".")
    ).workflow.prepare_aggregate_manifest_path(batch_id=batch_id)
    if not manifest_path.is_file():
        raise ValueError(
            f"prepare aggregate manifest {manifest_path} is required before aggregate execution"
        )
    return load_prepare_aggregate_manifest(manifest_path)
