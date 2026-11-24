"""Worker-owned direct data handoffs consumed by aggregate jobs."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from domain_pipeline.handoff_io import (
    read_csv,
    read_yaml,
    write_csv,
    write_yaml,
)
from domain_pipeline.paths.layout import PathLayout
from domain_pipeline.pipeline_run.format_version import PIPELINE_RUN_FORMAT_VERSION
from domain_pipeline.prepare.prepare_to_worker_manifest import (
    PrepareWorkerManifest,
    load_prepare_worker_manifest_for_worker,
)
from domain_pipeline.worker.output.rows import REVIEW_OUTPUT_COLUMNS

CacheSnapshotMode = Literal["sqlite_backup", "raw_file", "missing"]


class WorkerAggregateModel(BaseModel):
    """Base worker-to-aggregate data model that rejects unknown fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class WorkerAggregateManifest(WorkerAggregateModel):
    """In-memory view of a worker-to-aggregate handoff."""

    automation_format_version: int
    batch_id: str
    worker_id: str
    handoff_finalized: bool
    unactionable_registrable_domains: list[str]
    review_output_rows: list[dict[str, str]]
    terminal_rows: list[dict[str, Any]]
    log_text: str
    cache_path: Path | None
    cache_sha256: str | None

    @classmethod
    def empty(
        cls,
        automation_format_version: int,
        batch_id: str,
        worker_id: str,
        *,
        finalized: bool = False,
    ) -> "WorkerAggregateManifest":
        """Build an empty handoff for a worker."""
        return cls(
            automation_format_version=automation_format_version,
            batch_id=batch_id,
            worker_id=worker_id,
            handoff_finalized=finalized,
            unactionable_registrable_domains=[],
            review_output_rows=[],
            terminal_rows=[],
            log_text="",
            cache_path=None,
            cache_sha256=None,
        )

    @classmethod
    def initialized_from_prepare_worker_manifest(
        cls,
        manifest: PrepareWorkerManifest,
    ) -> "WorkerAggregateManifest":
        """Build an initialized worker-to-aggregate handoff stub."""
        return cls.empty(
            manifest.automation_format_version, manifest.batch_id, manifest.worker_id
        )


def _manifest_path(*, batch_id: str, worker_id: str, state_root: Path) -> Path:
    return state_root / PathLayout(
        Path(".")
    ).workflow_state.worker_aggregate_manifest_path(
        batch_id=batch_id,
        worker_id=worker_id,
    )


def _read_text_values(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _read_review_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    return read_csv(path, tuple(REVIEW_OUTPUT_COLUMNS))


def _read_jsonl_rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if line.strip():
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError(
                        f"terminal JSONL row at {path}:{line_number} must be a mapping"
                    )
                rows.append(row)
    return rows


def _validate_worker_domain_outputs(
    *,
    assigned_roots: set[str],
    unactionable_domains: list[str],
    review_rows: list[dict[str, str]],
    terminal_rows: list[dict[str, Any]],
) -> None:
    """Require every returned domain result to belong to this worker."""
    if len(unactionable_domains) != len(set(unactionable_domains)):
        raise ValueError("worker unactionable registrable domains contain duplicates")
    values = list(unactionable_domains)
    values.extend(row.get("registrable_domain", "").strip() for row in review_rows)
    values.extend(str(row.get("registrable_domain", "")).strip() for row in terminal_rows)
    if any(not value for value in values):
        raise ValueError("worker domain result is missing registrable_domain")
    unexpected = sorted(set(values) - assigned_roots)
    if unexpected:
        raise ValueError(
            "worker returned registrable domains outside its assigned roots: "
            f"{unexpected}"
        )


def _read_optional_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def _snapshot_cache(cache_path: Path, destination: Path) -> CacheSnapshotMode:
    if destination.exists():
        destination.unlink()
    if not cache_path.is_file():
        return "missing"
    try:
        source = sqlite3.connect(f"file:{cache_path}?mode=ro", uri=True)
        try:
            target = sqlite3.connect(destination)
            try:
                source.backup(target)
            finally:
                target.close()
        finally:
            source.close()
        return "sqlite_backup"
    except (OSError, sqlite3.DatabaseError):
        destination.write_bytes(cache_path.read_bytes())
        return "raw_file"


def validate_worker_handoff_state(
    value: Any, *, batch_id: str, worker_id: str
) -> dict[str, Any]:
    """Validate the shared worker state fields, identity, and cache declaration."""
    expected = {
        "automation_format_version",
        "batch_id",
        "worker_id",
        "handoff_finalized",
        "cache_present",
        "cache_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("invalid handoff state fields")
    if (value["batch_id"], value["worker_id"]) != (batch_id, worker_id):
        raise ValueError("worker aggregate handoff identity mismatch")
    version = value["automation_format_version"]
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != PIPELINE_RUN_FORMAT_VERSION
    ):
        raise ValueError("unsupported worker aggregate handoff format version")
    if not isinstance(value["handoff_finalized"], bool) or not isinstance(
        value["cache_present"], bool
    ):
        raise ValueError("invalid handoff flags")
    if value["cache_present"]:
        if not isinstance(value["cache_sha256"], str):
            raise ValueError("invalid cache checksum")
    elif value["cache_sha256"] is not None:
        raise ValueError("unexpected cache checksum")
    return value


def load_worker_aggregate_manifest(
    path: Path, *, state_root: Path, batch_id: str, worker_id: str
) -> WorkerAggregateManifest:
    """Load state and direct data files for one worker."""
    try:
        state = validate_worker_handoff_state(
            read_yaml(path), batch_id=batch_id, worker_id=worker_id
        )
        layout = PathLayout(state_root)
        state_paths = layout.workflow_state
        if path != state_paths.worker_aggregate_manifest_path(
            batch_id=batch_id, worker_id=worker_id
        ):
            raise ValueError("worker aggregate handoff path mismatch")
        cache = state_paths.worker_handoff_cache_path(
            batch_id=batch_id, worker_id=worker_id
        )
        if not state["cache_present"] and state["handoff_finalized"] and cache.exists():
            raise ValueError("unexpected cache")
        terminal = []
        if state["handoff_finalized"]:
            for data_path in (
                state_paths.worker_handoff_unactionable_path(
                    batch_id=batch_id, worker_id=worker_id
                ),
                state_paths.worker_handoff_review_path(
                    batch_id=batch_id, worker_id=worker_id
                ),
                state_paths.worker_handoff_terminal_path(
                    batch_id=batch_id, worker_id=worker_id
                ),
            ):
                if not data_path.is_file():
                    raise ValueError(f"missing {data_path}")
            terminal = read_yaml(
                state_paths.worker_handoff_terminal_path(
                    batch_id=batch_id, worker_id=worker_id
                )
            )
            if not isinstance(terminal, list) or any(
                not isinstance(row, dict) for row in terminal
            ):
                raise ValueError("terminal rows must be a sequence of mappings")
        log_path = layout.output.worker_log_path(batch_id=batch_id, worker_id=worker_id)
        return WorkerAggregateManifest(
            automation_format_version=state["automation_format_version"],
            batch_id=state["batch_id"],
            worker_id=state["worker_id"],
            handoff_finalized=state["handoff_finalized"],
            unactionable_registrable_domains=_read_text_values(
                state_paths.worker_handoff_unactionable_path(
                    batch_id=batch_id, worker_id=worker_id
                )
            )
            if state["handoff_finalized"]
            else [],
            review_output_rows=read_csv(
                state_paths.worker_handoff_review_path(
                    batch_id=batch_id, worker_id=worker_id
                ),
                tuple(REVIEW_OUTPUT_COLUMNS),
            )
            if state["handoff_finalized"]
            else [],
            terminal_rows=terminal,
            log_text=_read_optional_text(log_path),
            cache_path=cache if state["cache_present"] else None,
            cache_sha256=state["cache_sha256"],
        )
    except (OSError, UnicodeError, ValidationError, ValueError, KeyError) as exc:
        raise ValueError(f"invalid worker aggregate handoff {path}: {exc}") from exc


def load_worker_aggregate_manifest_for_worker(
    *, batch_id: str, worker_id: str, state_root: Path
) -> WorkerAggregateManifest | None:
    """Load one worker handoff when its state exists."""
    path = _manifest_path(batch_id=batch_id, worker_id=worker_id, state_root=state_root)
    if not path.is_file():
        return None
    manifest = load_worker_aggregate_manifest(
        path, state_root=state_root, batch_id=batch_id, worker_id=worker_id
    )
    if (manifest.batch_id, manifest.worker_id) != (batch_id, worker_id):
        raise ValueError(f"worker aggregate handoff identity mismatch: {path}")
    return manifest


def worker_aggregate_manifest_paths(*, batch_id: str, state_root: Path) -> list[Path]:
    """Discover worker handoff state paths for a batch."""
    root = PathLayout(state_root).workflow_state.worker_result_batch_root(
        batch_id=batch_id
    )
    state_name = _manifest_path(
        batch_id=batch_id, worker_id="_", state_root=state_root
    ).name
    return sorted(root.glob(f"*/{state_name}")) if root.is_dir() else []


def write_worker_aggregate_manifest(
    manifest: WorkerAggregateManifest, *, state_root: Path
) -> Path:
    """Write the worker handoff state at its canonical path."""
    path = _manifest_path(
        batch_id=manifest.batch_id, worker_id=manifest.worker_id, state_root=state_root
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    state = {
        "automation_format_version": manifest.automation_format_version,
        "batch_id": manifest.batch_id,
        "worker_id": manifest.worker_id,
        "handoff_finalized": manifest.handoff_finalized,
        "cache_present": manifest.cache_path is not None,
        "cache_sha256": manifest.cache_sha256,
    }
    write_yaml(path, state)
    return path


def finalize_worker_aggregate_handoff(
    *,
    batch_id: str,
    worker_id: str,
    state_root: Path,
) -> dict[str, Any]:
    """Finalize one worker-to-aggregate handoff from worker-local sidecars."""
    prepare_manifest, failure_reason = load_prepare_worker_manifest_or_error(
        batch_id=batch_id,
        worker_id=worker_id,
        state_root=state_root,
    )
    if failure_reason:
        return {
            "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
            "batch_id": batch_id,
            "worker_id": worker_id,
            "handoff_finalized": False,
            "error_reason": failure_reason,
        }
    if prepare_manifest is None:
        raise RuntimeError("prepare worker manifest loader returned no manifest")
    paths = prepare_manifest.resolve_paths(state_root)
    assigned_roots = set(prepare_manifest.prepared_metadata.delegation_roots)
    unactionable_domains = _read_text_values(paths["unactionable"])
    review_rows = _read_review_rows(paths["review"])
    terminal_rows = _read_jsonl_rows(paths["terminal_rows"])
    _validate_worker_domain_outputs(
        assigned_roots=assigned_roots,
        unactionable_domains=unactionable_domains,
        review_rows=review_rows,
        terminal_rows=terminal_rows,
    )
    path = _manifest_path(batch_id=batch_id, worker_id=worker_id, state_root=state_root)
    root = path.parent
    root.mkdir(parents=True, exist_ok=True)
    # Mark the handoff incomplete before replacing any data.
    write_worker_aggregate_manifest(
        WorkerAggregateManifest.empty(
            prepare_manifest.automation_format_version, batch_id, worker_id
        ),
        state_root=state_root,
    )
    state_paths = PathLayout(state_root).workflow_state
    state_paths.worker_handoff_unactionable_path(
        batch_id=batch_id, worker_id=worker_id
    ).write_text(
        "".join(f"{value}\n" for value in unactionable_domains),
        encoding="utf-8",
    )
    write_csv(
        state_paths.worker_handoff_review_path(batch_id=batch_id, worker_id=worker_id),
        tuple(REVIEW_OUTPUT_COLUMNS),
        review_rows,
    )
    write_yaml(
        state_paths.worker_handoff_terminal_path(
            batch_id=batch_id, worker_id=worker_id
        ),
        terminal_rows,
    )
    cache = state_paths.worker_handoff_cache_path(
        batch_id=batch_id, worker_id=worker_id
    )
    mode = _snapshot_cache(paths["cache"], cache)
    checksum = (
        hashlib.sha256(cache.read_bytes()).hexdigest() if mode != "missing" else None
    )
    manifest = WorkerAggregateManifest.empty(
        prepare_manifest.automation_format_version, batch_id, worker_id, finalized=True
    ).model_copy(
        update={"cache_path": cache if checksum else None, "cache_sha256": checksum}
    )
    write_worker_aggregate_manifest(manifest, state_root=state_root)
    return {
        "automation_format_version": manifest.automation_format_version,
        "batch_id": batch_id,
        "worker_id": worker_id,
        "handoff_finalized": True,
        "worker_aggregate_manifest_path": path.relative_to(state_root).as_posix(),
        "cache_snapshot_mode": mode,
        "cache_size_bytes": cache.stat().st_size if checksum else 0,
    }


def load_prepare_worker_manifest_or_error(
    *,
    batch_id: str,
    worker_id: str,
    state_root: Path,
) -> tuple[PrepareWorkerManifest | None, str]:
    """Load one prepare-worker manifest, returning validation failures as text."""
    try:
        return (
            load_prepare_worker_manifest_for_worker(
                batch_id=batch_id,
                worker_id=worker_id,
                state_root=state_root,
            ),
            "",
        )
    except (FileNotFoundError, ValueError) as exc:
        return None, str(exc)
