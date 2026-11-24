"""Prepare-owned manifests consumed by aggregate jobs."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from domain_pipeline.config_namespace import CONFIG_NAMESPACE_PATTERN
from domain_pipeline.handoff_io import read_csv, read_yaml, write_csv, write_yaml
from domain_pipeline.paths.layout import PathLayout
from domain_pipeline.pipeline_run.format_version import (
    PIPELINE_RUN_FORMAT_VERSION,
    has_current_pipeline_run_format,
)
from domain_pipeline.worker.output.rows import REVIEW_OUTPUT_COLUMNS


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


class ManuallyAddedDomain(PrepareAggregateModel):
    """Unmatched manual host emitted separately from configured source records."""

    host: str
    registrable_domain: str | None


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
        publish_root = PathLayout(state_root).output.publish_worktree_root()
        return {
            "unactionable": publish_root / Path(self.unactionable),
            "review": publish_root / Path(self.review),
            "audit": state_root / Path(self.audit),
            "log": state_root / Path(self.log),
            "cache": state_root / Path(self.cache),
        }

    def resolve_filtered(self, state_root: Path) -> list[tuple[Path, str]]:
        """Resolve configured filtered outputs in the publish worktree."""
        publish_root = PathLayout(state_root).output.publish_worktree_root()
        return [(publish_root / Path(item.path), item.format) for item in self.filtered]


class PrepareAggregateManifest(PrepareAggregateModel):
    """Persisted prepare-to-aggregate JSON data handoff."""

    automation_format_version: int
    batch_id: str
    config_name: str
    aggregate_output_spec: AggregateOutputSpec
    worker_ids: list[str]
    excluded_source_hosts: list[str]
    manually_added_domains: list[ManuallyAddedDomain]
    preparation_review_output_rows: list[dict[str, str]]
    preparation_terminal_rows: list[dict[str, Any]]

    @field_validator("automation_format_version", mode="before")
    @classmethod
    def _validate_format_version(cls, value: Any) -> int:
        if not has_current_pipeline_run_format(value):
            raise ValueError("unsupported prepare aggregate handoff format version")
        return value

    @field_validator("excluded_source_hosts")
    @classmethod
    def _validate_excluded_source_hosts(cls, values: list[str]) -> list[str]:
        if any(not value or value != value.strip() for value in values):
            raise ValueError("excluded source hosts must be non-empty trimmed values")
        if len(values) != len(set(values)):
            raise ValueError("excluded source hosts must not contain duplicates")
        return values

    def resolve_paths(self, state_root: Path) -> dict[str, Path]:
        """Return resolved aggregate-managed paths for this batch."""
        return self.aggregate_output_spec.resolve_paths(state_root)


def write_prepare_aggregate_handoff(
    manifest: PrepareAggregateManifest, *, state_root: Path
) -> list[Path]:
    """Write aggregate configuration and its separate input tables."""
    paths = PathLayout(state_root).workflow_state
    batch_id = manifest.batch_id
    config = paths.prepare_aggregate_config_path(batch_id=batch_id)
    workers = paths.batch_worker_ids_path(batch_id=batch_id)
    manual = paths.batch_manual_domains_path(batch_id=batch_id)
    review = paths.batch_preparation_review_path(batch_id=batch_id)
    terminal = paths.batch_preparation_terminal_path(batch_id=batch_id)
    output = manifest.aggregate_output_spec.model_dump(mode="json")
    for key in ("audit", "log", "cache"):
        output.pop(key)
    write_yaml(
        config,
        {
            "automation_format_version": manifest.automation_format_version,
            "batch_id": batch_id,
            "config_name": manifest.config_name,
            "excluded_source_hosts": manifest.excluded_source_hosts,
            "output": output,
        },
    )
    write_csv(
        workers, ("worker_id",), [{"worker_id": value} for value in manifest.worker_ids]
    )
    write_csv(
        manual,
        ("host", "registrable_domain_present", "registrable_domain"),
        [
            {
                "host": item.host,
                "registrable_domain_present": "1"
                if item.registrable_domain is not None
                else "0",
                "registrable_domain": item.registrable_domain or "",
            }
            for item in manifest.manually_added_domains
        ],
    )
    write_csv(review, REVIEW_OUTPUT_COLUMNS, manifest.preparation_review_output_rows)
    write_yaml(terminal, manifest.preparation_terminal_rows)
    return [config, workers, manual, review, terminal]


def load_prepare_aggregate_manifest_for_batch(
    *, batch_id: str, state_root: Path
) -> PrepareAggregateManifest:
    """Load and validate the separate prepare-to-aggregate handoff files."""
    paths = PathLayout(state_root).workflow_state
    config_path = paths.prepare_aggregate_config_path(batch_id=batch_id)
    payload = read_yaml(config_path)
    if not isinstance(payload, dict) or set(payload) != {
        "automation_format_version",
        "batch_id",
        "config_name",
        "excluded_source_hosts",
        "output",
    }:
        raise ValueError(f"invalid prepare aggregate configuration {config_path}")
    if payload["batch_id"] != batch_id:
        raise ValueError("prepare aggregate configuration batch_id mismatch")
    config_name = payload["config_name"]
    if not isinstance(config_name, str) or not CONFIG_NAMESPACE_PATTERN.fullmatch(
        config_name
    ):
        raise ValueError("prepare aggregate config_name is required")
    output = payload["output"]
    if not isinstance(output, dict) or set(output) != {
        "filtered",
        "unactionable",
        "review",
    }:
        raise ValueError("invalid aggregate output configuration")
    derived = PathLayout(Path(".")).aggregate_paths(config_name=config_name)
    output.update(
        {
            "audit": derived.raw_audit.as_posix(),
            "log": derived.runtime_log.as_posix(),
            "cache": derived.cache.as_posix(),
        }
    )
    workers = [
        row["worker_id"]
        for row in read_csv(
            paths.batch_worker_ids_path(batch_id=batch_id), ("worker_id",)
        )
    ]
    if any(not worker for worker in workers) or len(workers) != len(set(workers)):
        raise ValueError("invalid or duplicate aggregate worker id")
    manual = _load_manual_domains(paths.batch_manual_domains_path(batch_id=batch_id))
    review = read_csv(
        paths.batch_preparation_review_path(batch_id=batch_id), REVIEW_OUTPUT_COLUMNS
    )
    terminal = read_yaml(paths.batch_preparation_terminal_path(batch_id=batch_id))
    if not isinstance(terminal, list):
        raise ValueError("preparation terminal rows must be a YAML sequence")
    try:
        return PrepareAggregateManifest.model_validate(
            {
                "automation_format_version": payload["automation_format_version"],
                "batch_id": batch_id,
                "config_name": config_name,
                "aggregate_output_spec": output,
                "worker_ids": workers,
                "excluded_source_hosts": payload["excluded_source_hosts"],
                "manually_added_domains": manual,
                "preparation_review_output_rows": review,
                "preparation_terminal_rows": terminal,
            }
        )
    except ValidationError as exc:
        raise ValueError(
            f"invalid prepare aggregate handoff {config_path}: {exc}"
        ) from exc


def _load_manual_domains(path: Path) -> list[dict[str, str | None]]:
    """Read manual domains while retaining nullable domain values."""
    manual = []
    for row in read_csv(
        path,
        ("host", "registrable_domain_present", "registrable_domain"),
    ):
        present = row["registrable_domain_present"]
        if present not in {"0", "1"} or (present == "0" and row["registrable_domain"]):
            raise ValueError("invalid manual domain presence flag")
        manual.append(
            {
                "host": row["host"],
                "registrable_domain": row["registrable_domain"]
                if present == "1"
                else None,
            }
        )
    return manual
