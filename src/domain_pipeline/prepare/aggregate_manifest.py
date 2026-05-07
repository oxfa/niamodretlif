"""Prepare-owned manifests consumed by aggregate jobs."""

from __future__ import annotations

import json
from pathlib import Path
from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from domain_pipeline.paths import PathLayout


class PrepareAggregateModel(BaseModel):
    """Base prepare-to-aggregate manifest model that rejects unknown fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ConfigIdentity(PrepareAggregateModel):
    """Stable config identity captured during batch preparation."""

    config_name: str
    config_path: str
    config_file_name: str


class AggregateOutputSpec(PrepareAggregateModel):
    """Repo-relative aggregate output/cache/log paths."""

    filtered: str
    unactionable: str
    review: str
    audit: str
    log: str
    cache: str

    def resolve_paths(self, state_root: Path) -> dict[str, Path]:
        """Return resolved aggregate paths rooted at one pipeline-run workspace root."""
        publish_root = PathLayout(state_root).publish_worktree_root()
        return {
            "filtered": publish_root / Path(self.filtered),
            "unactionable": publish_root / Path(self.unactionable),
            "review": publish_root / Path(self.review),
            "audit": state_root / Path(self.audit),
            "log": state_root / Path(self.log),
            "cache": state_root / Path(self.cache),
        }


class PrepareAggregateManifest(PrepareAggregateModel):
    """Persisted prepare-to-aggregate JSON data handoff."""

    automation_format_version: int
    batch_id: str
    config_identity: ConfigIdentity
    aggregate_output_spec: AggregateOutputSpec
    worker_ids: list[str]
    preparation_review_output_rows: list[dict[str, str]]
    preparation_terminal_rows: list[dict[str, Any]]
    preparation_filtered_output_values: list[str] = Field(default_factory=list)

    @classmethod
    def from_prepared_batch(
        cls,
        *,
        automation_format_version: int,
        batch_id: str,
        config_identity: ConfigIdentity,
        aggregate_output_spec: AggregateOutputSpec,
        worker_ids: list[str],
        preparation_review_output_rows: Sequence[Mapping[str, Any]],
        preparation_terminal_rows: Sequence[Mapping[str, Any]],
        preparation_filtered_output_values: Sequence[str] = (),
    ) -> "PrepareAggregateManifest":
        """Build one prepare-to-aggregate manifest from prepared batch state."""
        return cls(
            automation_format_version=automation_format_version,
            batch_id=batch_id,
            config_identity=config_identity,
            aggregate_output_spec=aggregate_output_spec,
            worker_ids=list(worker_ids),
            preparation_filtered_output_values=[
                str(value) for value in preparation_filtered_output_values
            ],
            preparation_review_output_rows=[
                dict(row) for row in preparation_review_output_rows
            ],
            preparation_terminal_rows=[dict(row) for row in preparation_terminal_rows],
        )

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
