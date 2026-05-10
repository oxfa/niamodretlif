"""Worker-owned JSON data handoffs consumed by aggregate jobs."""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from domain_pipeline.paths.layout import PathLayout
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
    """Persisted worker-to-aggregate JSON data handoff."""

    automation_format_version: int
    batch_id: str
    worker_id: str
    handoff_finalized: bool
    filtered_output_values: list[str]
    unactionable_output_values: list[str]
    review_output_rows: list[dict[str, str]]
    terminal_rows: list[dict[str, Any]]
    log_text: str
    cache_sqlite_base64: str | None
    cache_sha256: str | None
    cache_size_bytes: int
    cache_snapshot_mode: CacheSnapshotMode

    @classmethod
    def initialized_from_prepare_worker_manifest(
        cls,
        manifest: PrepareWorkerManifest,
    ) -> "WorkerAggregateManifest":
        """Build an initialized worker-to-aggregate handoff stub."""
        return cls(
            automation_format_version=manifest.automation_format_version,
            batch_id=manifest.batch_id,
            worker_id=manifest.worker_id,
            handoff_finalized=False,
            filtered_output_values=[],
            unactionable_output_values=[],
            review_output_rows=[],
            terminal_rows=[],
            log_text="",
            cache_sqlite_base64=None,
            cache_sha256=None,
            cache_size_bytes=0,
            cache_snapshot_mode="missing",
        )

    @classmethod
    def finalized_from_prepare_worker_manifest(
        cls,
        manifest: PrepareWorkerManifest,
        *,
        state_root: Path,
    ) -> "WorkerAggregateManifest":
        """Build a finalized worker-to-aggregate handoff from local worker outputs."""
        resolved = manifest.resolve_paths(state_root)
        cache_payload = _snapshot_cache_payload(resolved["cache"])
        return cls(
            automation_format_version=manifest.automation_format_version,
            batch_id=manifest.batch_id,
            worker_id=manifest.worker_id,
            handoff_finalized=True,
            filtered_output_values=_read_text_values(resolved["filtered"]),
            unactionable_output_values=_read_text_values(resolved["unactionable"]),
            review_output_rows=_read_review_rows(resolved["review"]),
            terminal_rows=_read_jsonl_rows(resolved["terminal_rows"]),
            log_text=_read_optional_text(manifest.resolve_log_path(state_root)),
            cache_sqlite_base64=cache_payload["cache_sqlite_base64"],
            cache_sha256=cache_payload["cache_sha256"],
            cache_size_bytes=cache_payload["cache_size_bytes"],
            cache_snapshot_mode=cache_payload["cache_snapshot_mode"],
        )


def _manifest_path(*, batch_id: str, worker_id: str, state_root: Path) -> Path:
    return state_root / PathLayout(Path(".")).workflow.worker_aggregate_manifest_path(
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
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [
            {column: str(row.get(column, "")) for column in REVIEW_OUTPUT_COLUMNS}
            for row in csv.DictReader(handle)
        ]


def _read_jsonl_rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                if isinstance(row, dict):
                    rows.append(row)
    return rows


def _read_optional_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def _payload_from_bytes(payload: bytes, mode: CacheSnapshotMode) -> dict[str, Any]:
    return {
        "cache_sqlite_base64": base64.b64encode(payload).decode("ascii"),
        "cache_sha256": hashlib.sha256(payload).hexdigest(),
        "cache_size_bytes": len(payload),
        "cache_snapshot_mode": mode,
    }


def _missing_cache_payload() -> dict[str, Any]:
    return {
        "cache_sqlite_base64": None,
        "cache_sha256": None,
        "cache_size_bytes": 0,
        "cache_snapshot_mode": "missing",
    }


def _snapshot_cache_payload(cache_path: Path) -> dict[str, Any]:
    if not cache_path.is_file():
        return _missing_cache_payload()
    snapshot_path = cache_path.with_name(f"{cache_path.name}.handoff-snapshot")
    try:
        if snapshot_path.exists():
            snapshot_path.unlink()
        source = sqlite3.connect(f"file:{cache_path}?mode=ro", uri=True)
        try:
            target = sqlite3.connect(snapshot_path)
            try:
                source.backup(target)
            finally:
                target.close()
        finally:
            source.close()
        payload = snapshot_path.read_bytes()
        return _payload_from_bytes(payload, "sqlite_backup")
    except (OSError, sqlite3.DatabaseError):
        return _payload_from_bytes(cache_path.read_bytes(), "raw_file")
    finally:
        if snapshot_path.exists():
            snapshot_path.unlink()


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(
            f"unable to read worker aggregate manifest {path}: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"worker aggregate manifest {path} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError(f"worker aggregate manifest {path} must be a JSON object")
    return payload


def load_worker_aggregate_manifest(path: Path) -> WorkerAggregateManifest:
    """Load and validate one persisted worker-to-aggregate handoff."""
    payload = _load_json_object(path)
    try:
        return WorkerAggregateManifest.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(f"invalid worker aggregate manifest {path}: {exc}") from exc


def load_worker_aggregate_manifest_for_worker(
    *,
    batch_id: str,
    worker_id: str,
    state_root: Path,
) -> WorkerAggregateManifest | None:
    """Load one worker-to-aggregate handoff by workflow convention when it exists."""
    path = _manifest_path(batch_id=batch_id, worker_id=worker_id, state_root=state_root)
    if not path.is_file():
        return None
    return load_worker_aggregate_manifest(path)


def worker_aggregate_manifest_paths(*, batch_id: str, state_root: Path) -> list[Path]:
    """Return all restored worker-to-aggregate JSON handoff paths for one batch."""
    worker_root = PathLayout(state_root).workflow.worker_state_batch_root(
        batch_id=batch_id
    )
    if not worker_root.is_dir():
        return []
    return sorted(worker_root.glob("*/worker-aggregate-manifest.json"))


def write_worker_aggregate_manifest(
    manifest: WorkerAggregateManifest,
    *,
    state_root: Path,
) -> Path:
    """Persist one worker-to-aggregate JSON handoff under worker-owned state."""
    path = _manifest_path(
        batch_id=manifest.batch_id,
        worker_id=manifest.worker_id,
        state_root=state_root,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
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
            "automation_format_version": 2,
            "batch_id": batch_id,
            "worker_id": worker_id,
            "participates": True,
            "handoff_finalized": False,
            "error_reason": failure_reason,
        }
    if prepare_manifest is None:
        return {
            "automation_format_version": 2,
            "batch_id": batch_id,
            "worker_id": worker_id,
            "participates": False,
        }
    manifest = WorkerAggregateManifest.finalized_from_prepare_worker_manifest(
        prepare_manifest,
        state_root=state_root,
    )
    path = write_worker_aggregate_manifest(manifest, state_root=state_root)
    return {
        "automation_format_version": manifest.automation_format_version,
        "batch_id": batch_id,
        "worker_id": worker_id,
        "participates": True,
        "handoff_finalized": manifest.handoff_finalized,
        "worker_aggregate_manifest_path": path.relative_to(state_root).as_posix(),
        "cache_snapshot_mode": manifest.cache_snapshot_mode,
        "cache_size_bytes": manifest.cache_size_bytes,
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
    except ValueError as exc:
        return None, str(exc)
