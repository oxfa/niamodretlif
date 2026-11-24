"""Stage declared inter-job handoffs without reconstructing their paths."""

from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

from domain_pipeline.handoff_io import read_json, read_yaml
from domain_pipeline.pipeline_run.format_version import (
    PIPELINE_RUN_FORMAT_VERSION,
    has_current_pipeline_run_format,
)
from domain_pipeline.prepare.source_line_index import load_source_line_index
from domain_pipeline.prepare.source_items import SourceItemHandoff

from domain_pipeline.paths import HandoffMember, PathLayout


def _identity(value: str) -> str:
    if not value or value in {".", ".."} or Path(value).name != value:
        raise ValueError(f"invalid handoff identity: {value!r}")
    return value


def _check_source_path(root: Path, path: Path) -> None:
    """Reject paths outside the state root and symlinks before accessing their targets."""
    root = root.resolve()
    try:
        relative = path.absolute().relative_to(root)
    except ValueError as exc:
        raise ValueError(f"source path outside state root: {path}") from exc
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError(f"symlink in source path: {cursor}")
    if not path.resolve().is_relative_to(root):
        raise ValueError(f"source path outside state root: {path}")


def _check_source_file(root: Path, path: Path) -> None:
    _check_source_path(root, path)
    if not path.is_file():
        raise ValueError(f"source is not a regular file: {path}")


def stage_worker_inputs(
    *, state_root: Path, batch_id: str, worker_ids_json: str, destination: Path
) -> None:
    """Stage every worker's complete input under a separate archive root."""
    _identity(batch_id)
    worker_ids = json.loads(worker_ids_json)
    if (
        not isinstance(worker_ids, list)
        or not worker_ids
        or any(not isinstance(w, str) for w in worker_ids)
        or len(set(worker_ids)) != len(worker_ids)
    ):
        raise ValueError("worker IDs must be a nonempty list of distinct strings")
    layout = PathLayout(state_root)
    for worker in worker_ids:
        _identity(worker)
        members = layout.prepare_to_worker.members(batch_id=batch_id, worker_id=worker)
        for member in members:
            _check_source_file(state_root, member.source)
    if destination.exists() and any(destination.iterdir()):
        raise ValueError(f"handoff staging directory is not empty: {destination}")
    for worker in worker_ids:
        for member in layout.prepare_to_worker.members(batch_id=batch_id, worker_id=worker):
            _stage_member(member, destination / worker)


def validate_worker_inputs(
    *, state_root: Path, batch_id: str, worker_ids_json: str, destination: Path
) -> None:
    """Validate the complete staged worker set against class-declared paths."""
    worker_ids = json.loads(worker_ids_json)
    if (
        not isinstance(worker_ids, list)
        or not worker_ids
        or any(not isinstance(w, str) for w in worker_ids)
        or len(set(worker_ids)) != len(worker_ids)
    ):
        raise ValueError("invalid worker IDs")
    _identity(batch_id)
    if {p.name for p in destination.iterdir()} != set(worker_ids):
        raise ValueError("staged worker set differs from configured workers")
    layout = PathLayout(state_root)
    for worker in worker_ids:
        _identity(worker)
        root = destination / worker
        expected = {
            m.archive_path
            for m in layout.prepare_to_worker.members(batch_id=batch_id, worker_id=worker)
        }
        actual = {p.relative_to(root) for p in root.rglob("*") if p.is_file()}
        if actual != expected or any(p.is_symlink() for p in root.rglob("*")):
            raise ValueError(f"invalid staged worker files: {worker}")


def _validate_identity(
    path: Path,
    *,
    batch_id: str,
    worker_id: str | None = None,
    config_name: str | None = None,
) -> None:
    payload = read_yaml(path)
    if not isinstance(payload, dict):
        raise ValueError(f"handoff identity mismatch: {path}")
    format_version = payload.get("automation_format_version")
    if (
        payload.get("batch_id") != batch_id
        or (worker_id is not None and payload.get("worker_id") != worker_id)
        or (config_name is not None and payload.get("config_name") != config_name)
        or (
            not isinstance(format_version, int)
            or isinstance(format_version, bool)
            or format_version != PIPELINE_RUN_FORMAT_VERSION
        )
    ):
        raise ValueError(f"handoff identity mismatch: {path}")


def _validate_sources(root: Path, *, batch_id: str) -> tuple[Path, ...]:
    paths = PathLayout(root).workflow_state
    index_path = paths.batch_source_line_index_path(batch_id=batch_id)
    formats_path = paths.batch_source_formats_path(batch_id=batch_id)
    _check_source_file(root, index_path)
    _check_source_file(root, formats_path)
    index = load_source_line_index(index_path, formats_path)
    item_paths = (
        paths.batch_source_items_path(batch_id=batch_id),
        paths.batch_source_item_index_path(batch_id=batch_id),
        paths.batch_source_item_diagnostics_path(batch_id=batch_id),
    )
    for item_path in item_paths:
        _check_source_file(root, item_path)
    SourceItemHandoff.load(
        batch_id=batch_id,
        items_path=item_paths[0],
        index_path=item_paths[1],
        diagnostics_path=item_paths[2],
    )
    source_root = paths.batch_source_inputs_root(batch_id=batch_id)
    _check_source_path(root, source_root)
    expected = {
        paths.batch_source_input_path(batch_id=batch_id, source_ordinal=ordinal).name
        for ordinal in range(len(index.source_formats))
    }
    if not source_root.exists() and not source_root.is_symlink() and not expected:
        return ()
    if source_root.is_symlink():
        raise ValueError("prepared source input root must not be a symlink")
    if not source_root.is_dir() or {p.name for p in source_root.iterdir()} != expected:
        raise ValueError("prepared source input set does not match source formats")
    if any(p.is_symlink() or not p.is_file() for p in source_root.iterdir()):
        raise ValueError("prepared source inputs must be regular files")
    return tuple(
        paths.batch_source_input_path(batch_id=batch_id, source_ordinal=ordinal)
        for ordinal in range(len(index.source_formats))
    )


@dataclass(frozen=True)
class HandoffRequest:
    """Identify a handoff and the runtime members it requires."""

    handoff: str
    batch_id: str
    worker_id: str | None = None
    require_runtime: bool = False
    config_name: str | None = None



def _validate_archive(source: Path, *, handoff: str, members: tuple[HandoffMember, ...]) -> None:
    if handoff in {"prepare-worker", "prepare-aggregate"}:
        for member in members:
            item = source / member.archive_path
            if item.is_symlink():
                raise ValueError(f"symlink in handoff: {item}")
            if item.exists():
                if member.archive_path.suffix and not item.is_file():
                    raise ValueError(f"handoff file is not a regular file: {item}")
                if not member.archive_path.suffix and not item.is_dir():
                    raise ValueError(f"handoff directory is not a directory: {item}")
        declared = {member.archive_path for member in members if member.archive_path.suffix}
        directories = {member.archive_path for member in members if not member.archive_path.suffix}
        for item in source.rglob("*"):
            if item.is_symlink():
                raise ValueError(f"symlink in handoff: {item}")
            if item.is_file():
                relative = item.relative_to(source)
                if relative not in declared and not any(
                    directory in relative.parents for directory in directories
                ):
                    raise ValueError(f"unexpected handoff file: {relative}")
            elif not item.is_dir():
                raise ValueError(f"invalid handoff entry: {item}")


def _validate_restored_identity(
    source: Path, *, state_root: Path, layout: PathLayout, request: HandoffRequest
) -> None:
    state = layout.workflow_state
    handoff, batch_id, worker_id = request.handoff, request.batch_id, request.worker_id
    if handoff == "prepare-worker":
        if worker_id is None:
            raise ValueError("worker ID is required for worker handoff")
        identity_path = state.prepare_worker_config_path(batch_id=batch_id, worker_id=worker_id)
        _validate_identity(
            source / identity_path.relative_to(state_root),
            batch_id=batch_id,
            worker_id=worker_id,
        )
        identity_json_path = state.prepare_worker_identity_path(
            batch_id=batch_id, worker_id=worker_id
        )
        archived_identity_json = source / identity_json_path.relative_to(state_root)
        try:
            identity = read_json(archived_identity_json)
        except (OSError, UnicodeError, ValueError) as exc:
            raise ValueError(
                f"handoff identity mismatch: {identity_json_path}"
            ) from exc
        if (
            not isinstance(identity, dict)
            or not has_current_pipeline_run_format(
                identity.get("automation_format_version")
            )
            or identity
            != {
                "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
                "batch_id": batch_id,
                "worker_id": worker_id,
            }
        ):
            raise ValueError(f"handoff identity mismatch: {identity_json_path}")
    elif handoff == "prepare-aggregate":
        if request.config_name is None:
            raise ValueError("aggregate config name is required")
        identity_path = state.prepare_aggregate_config_path(batch_id=batch_id)
        _validate_identity(
            source / identity_path.relative_to(state_root),
            batch_id=batch_id,
            config_name=request.config_name,
        )
        _validate_sources(source, batch_id=batch_id)
    else:
        if handoff != "worker-aggregate" or worker_id is None:
            raise ValueError("invalid worker handoff or missing worker ID")
        for identity_path in (
            state.worker_aggregate_manifest_path(batch_id=batch_id, worker_id=worker_id),
            state.worker_status_path(batch_id=batch_id, worker_id=worker_id),
        ):
            archived = source / identity_path.relative_to(state_root)
            if archived.exists():
                _validate_identity(archived, batch_id=batch_id, worker_id=worker_id)


def restore_handoff(
    *,
    state_root: Path,
    source: Path,
    request: HandoffRequest,
) -> None:
    """Restore declared members from an extracted archive into canonical locations."""
    handoff, batch_id, worker_id = request.handoff, request.batch_id, request.worker_id
    _identity(batch_id)
    layout = PathLayout(state_root)
    if handoff == "prepare-worker" and worker_id is not None:
        _identity(worker_id)
        members = layout.prepare_to_worker.members(batch_id=batch_id, worker_id=worker_id)
        required = members
    elif handoff == "prepare-aggregate":
        members = layout.prepare_to_aggregator.members(batch_id=batch_id)
        required = tuple(member for member in members if member.required)
    elif handoff == "worker-aggregate" and worker_id is not None:
        _identity(worker_id)
        members = layout.worker_to_aggregator.members(batch_id=batch_id, worker_id=worker_id)
        required = ()
    else:
        raise ValueError("invalid handoff")
    for member in required:
        if not (source / member.archive_path).exists():
            raise FileNotFoundError(f"required handoff member missing: {member.archive_path}")
    _validate_archive(source, handoff=handoff, members=members)
    _validate_restored_identity(source, state_root=state_root, layout=layout, request=request)
    for member in members:
        archived = source / member.archive_path
        if archived.exists():
            _stage_member(HandoffMember(archived, member.archive_path), state_root)


def worker_diagnostic_path(*, state_root: Path, batch_id: str, worker_id: str, kind: str) -> Path:
    """Return a declared worker diagnostic producer path."""
    _identity(batch_id)
    _identity(worker_id)
    return PathLayout(state_root).worker_to_aggregator.diagnostic_member(
        batch_id=batch_id, worker_id=worker_id, kind=kind
    ).source


def export_diagnostic(
    *, archive: Path, destination: Path, request: HandoffRequest, kind: str
) -> None:
    """Copy a declared diagnostic from a handoff, rendering YAML as JSON when needed."""
    _identity(request.batch_id)
    layout = PathLayout(Path("."))
    if request.handoff == "prepare-aggregate":
        member = layout.prepare_to_aggregator.diagnostic_member(
            batch_id=request.batch_id, kind=kind
        )
    elif request.handoff == "worker-aggregate" and request.worker_id is not None:
        _identity(request.worker_id)
        member = layout.worker_to_aggregator.diagnostic_member(
            batch_id=request.batch_id, worker_id=request.worker_id, kind=kind
        )
    else:
        raise ValueError("invalid diagnostic handoff or missing worker ID")
    source = archive / member.archive_path
    if not source.is_file():
        print(f"aggregate artifact optional file missing: {source}")
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.suffix == ".yaml":
        destination.write_text(
            json.dumps(read_yaml(source), indent=2, sort_keys=True)
            + "\n", encoding="utf-8"
        )
    else:
        shutil.copy2(source, destination)


def _source_members(
    state_root: Path, *, source_root: Path, request: HandoffRequest
) -> tuple[HandoffMember, ...]:
    try:
        _check_source_path(state_root, source_root)
        if not request.require_runtime and not source_root.exists():
            return ()
        sources = _validate_sources(state_root, batch_id=request.batch_id)
    except (ValueError, OSError, UnicodeError) as exc:
        if request.require_runtime:
            raise
        print(f"Skipping unverified source inputs {source_root}: {exc}", file=sys.stderr)
        return ()
    return tuple(HandoffMember(path, path.relative_to(state_root)) for path in sources)


def stage_handoff(
    *,
    state_root: Path,
    destination: Path,
    request: HandoffRequest,
) -> list[str]:
    """Copy available declared members into an empty archive staging root."""
    _identity(request.batch_id)
    layout = PathLayout(state_root)
    if request.handoff == "prepare-aggregate":
        members = layout.prepare_to_aggregator.members(batch_id=request.batch_id)
        required = (
            tuple(member for member in members if member.required)
            if request.require_runtime
            else ()
        )
    elif request.handoff == "worker-aggregate" and request.worker_id is not None:
        _identity(request.worker_id)
        members = layout.worker_to_aggregator.members(
            batch_id=request.batch_id, worker_id=request.worker_id
        )
        required = ()
    else:
        raise ValueError(f"invalid handoff or missing worker ID: {request.handoff!r}")
    for member in required:
        _check_source_path(state_root, member.source)
        if not member.source.exists():
            raise FileNotFoundError(f"required handoff member missing: {member.source}")
        _check_source_file(state_root, member.source)
    if request.handoff == "prepare-aggregate":
        source_root = layout.workflow_state.batch_source_inputs_root(batch_id=request.batch_id)
        members = tuple(member for member in members if member.source != source_root)
        members += _source_members(state_root, source_root=source_root, request=request)
    if destination.exists() and any(destination.iterdir()):
        raise ValueError(f"handoff staging directory is not empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    staged: list[str] = []
    for member in members:
        try:
            _check_source_path(state_root, member.source)
            if not member.source.exists():
                continue
            _check_source_file(state_root, member.source)
        except (ValueError, OSError) as exc:
            if member in required:
                raise
            print(
                f"Skipping invalid optional handoff member {member.source}: {exc}",
                file=sys.stderr,
            )
            continue
        if _stage_member(member, destination):
            staged.append(str(member.archive_path))
    return staged


def _stage_member(member: HandoffMember, destination: Path) -> bool:
    target = destination / member.archive_path
    target.parent.mkdir(parents=True, exist_ok=True)
    if member.source.suffix == ".json" and target.suffix == ".yaml":
        try:
            payload = json.loads(member.source.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            print(f"Skipping invalid optional diagnostic {member.source}: {exc}", file=sys.stderr)
            return False
        target.write_text(
            yaml.safe_dump(payload, sort_keys=True, default_flow_style=False, explicit_start=True),
            encoding="utf-8",
        )
    elif member.source.is_dir():
        shutil.copytree(member.source, target, dirs_exist_ok=True)
    else:
        shutil.copy2(member.source, target)
    return True
