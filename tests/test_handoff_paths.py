"""Contract tests for canonical inter-job archive paths."""

import json
from pathlib import Path

import pytest

from domain_pipeline.paths import PathLayout
from domain_pipeline.pipeline_run.handoffs import (
    HandoffRequest,
    _identity,
    restore_handoff,
    stage_handoff,
    stage_worker_inputs,
    validate_worker_inputs,
)
from domain_pipeline.pipeline_run.settings import default_worker_ids

BATCH = "batch-123-attempt-1"


def _write(root: Path, relative: str, data: bytes) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _prepare_files(root: Path) -> dict[str, bytes]:
    base = f".workflow_state/batches/{BATCH}"
    files = {
        f"{base}/output-config.yaml": (
            f"batch_id: {BATCH}\nconfig_name: block\nexcluded_source_hosts: []\n"
        ).encode(),
        f"{base}/worker-ids.csv": b"worker_id\nworker-01\nworker-02\n",
        f"{base}/manual-domains.csv": b"host,registrable_domain_present,registrable_domain\n",
        f"{base}/preparation-review.csv": b"fixture\n",
        f"{base}/preparation-terminal.yaml": b"---\n[]\n",
        f"{base}/source-formats.csv": b"source_ordinal,source_format\n",
        f"{base}/source-line-index.csv": (
            b"registrable_domain,source_ordinal,line_number\n"
        ),
        f"{base}/source-items.jsonl": b"",
        f"{base}/source-item-index.json": json.dumps(
            {
                "batch_id": BATCH,
                "sources": [],
                "valid_source_items_by_registrable_domain": {},
                "valid_source_items_without_extractable_registrable_domain": [],
                "adblock_metadata": [],
            }
        ).encode(),
        f"{base}/source-item-diagnostics.jsonl": b"",
    }
    for path, data in files.items():
        _write(root, path, data)
    return files


def _worker_files(
    root: Path, worker: str, *, batch_id: str = BATCH
) -> dict[str, bytes]:
    state = PathLayout(root).workflow_state
    runtime_path = state.prepare_worker_config_path(batch_id=BATCH, worker_id=worker)
    identity_path = state.prepare_worker_identity_path(batch_id=BATCH, worker_id=worker)
    files = {
        runtime_path.relative_to(root).as_posix(): json.dumps(
            {
                "batch_id": batch_id,
                "worker_id": worker,
                "config_name": "block",
                "runtime_spec": {},
                "prepared_metadata": {},
            }
        ).encode(),
        identity_path.relative_to(root).as_posix(): json.dumps(
            {
                "batch_id": batch_id,
                "worker_id": worker,
            }
        ).encode(),
    }
    for path, data in files.items():
        _write(root, path, data)
    return files


def _files(root: Path) -> dict[str, bytes]:
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in root.rglob("*")
        if p.is_file()
    }


def test_prepare_handoffs_preserve_canonical_members() -> None:
    """Prepare handoffs preserve canonical members."""
    root = Path("/workspace")
    layout = PathLayout(root)
    base = f".workflow_state/batches/{BATCH}"
    worker_paths = [
        f"{base}/workers/worker-01/runtime-config.json",
        f"{base}/workers/worker-01/worker-identity.json",
    ]
    worker = layout.prepare_to_worker.members(batch_id=BATCH, worker_id="worker-01")
    assert [(m.source, m.archive_path, m.required) for m in worker] == [
        (root / name, Path(name), True) for name in worker_paths
    ]
    runtime = [
        f"{base}/output-config.yaml",
        f"{base}/worker-ids.csv",
        f"{base}/manual-domains.csv",
        f"{base}/preparation-review.csv",
        f"{base}/preparation-terminal.yaml",
        f"{base}/source-formats.csv",
        f"{base}/source-line-index.csv",
        f"{base}/source-items.jsonl",
        f"{base}/source-item-index.json",
        f"{base}/source-item-diagnostics.jsonl",
        f"{base}/source_inputs",
    ]
    diagnostics = [
        ("settings.json", ".debug_artifacts/prepare/validation/logs/settings.yaml"),
        (
            "validate-settings.log",
            ".debug_artifacts/prepare/validation/logs/validate-settings.log",
        ),
        ("batch.json", ".debug_artifacts/prepare/batch/logs/batch.yaml"),
        ("prepare-batch.log", ".debug_artifacts/prepare/batch/logs/prepare-batch.log"),
    ]
    aggregate = layout.prepare_to_aggregator.members(batch_id=BATCH)
    assert [(m.source, m.archive_path, m.required) for m in aggregate] == [
        (root / name, Path(name), index != 10) for index, name in enumerate(runtime)
    ] + [(root / source, Path(dest), False) for source, dest in diagnostics]


def test_worker_handoff_contains_only_its_own_members() -> None:
    """Worker handoff contains only its own members."""
    root = Path("/workspace")
    members = PathLayout(root).worker_to_aggregator.members(
        batch_id=BATCH, worker_id="worker-02"
    )
    base = f".workflow_state/worker-results/{BATCH}/worker-02"
    names = [
        f"{base}/unactionable-input-domains.txt",
        f"{base}/review-results-by-input-domain.csv",
        f"{base}/domain-results.jsonl",
        f"{base}/cache.sqlite3",
        f"{base}/handoff-state.yaml",
        f".workflow_state/status/{BATCH}/worker-02.yaml",
        f".debug_artifacts/workers/{BATCH}/worker-02/logs/worker.log",
        f".debug_artifacts/workers/{BATCH}/worker-02/logs/cache.log",
    ]
    assert [(m.source, m.archive_path, m.required) for m in members] == [
        (root / name, Path(name), False) for name in names
    ]


@pytest.mark.parametrize("value", ["", ".", "..", "../worker", "a/b"])
def test_handoff_identity_rejects_paths(value: str) -> None:
    """Handoff identity rejects paths."""
    with pytest.raises(ValueError):
        _identity(value)


def test_worker_count_respects_matrix_bound() -> None:
    """Worker count respects matrix bound."""
    assert len(default_worker_ids(1)) == 1
    assert len(default_worker_ids(18)) == 18
    assert len(default_worker_ids(20)) == 20
    for value in (21, 0, 256, 257):
        with pytest.raises(ValueError, match="between 1 and 20"):
            default_worker_ids(value)


@pytest.mark.parametrize("count", [1, 18])
def test_worker_staging_contains_one_isolated_bundle_per_worker(
    tmp_path: Path, count: int
) -> None:
    """Worker staging contains one isolated bundle per worker."""
    root, destination = tmp_path / "source", tmp_path / "staged"
    ids = default_worker_ids(count)
    expected = {worker: _worker_files(root, worker) for worker in ids}
    stage_worker_inputs(
        state_root=root,
        batch_id=BATCH,
        worker_ids_json=json.dumps(ids),
        destination=destination,
    )
    validate_worker_inputs(
        state_root=root,
        batch_id=BATCH,
        worker_ids_json=json.dumps(ids),
        destination=destination,
    )
    assert {p.name for p in destination.iterdir()} == set(ids)
    for worker in ids:
        assert _files(destination / worker) == expected[worker]


@pytest.mark.parametrize("missing_index", [0, 1])
def test_worker_staging_validator_rejects_missing_declared_member(
    tmp_path: Path, missing_index: int
) -> None:
    """A worker tree missing a layout member cannot pass pre-upload validation."""
    root, destination = tmp_path / "source", tmp_path / "staged"
    worker = "worker-01"
    _worker_files(root, worker)
    args = {
        "state_root": root,
        "batch_id": BATCH,
        "worker_ids_json": json.dumps([worker]),
        "destination": destination,
    }
    stage_worker_inputs(**args)
    validate_worker_inputs(**args)
    members = PathLayout(root).prepare_to_worker.members(batch_id=BATCH, worker_id=worker)
    (destination / worker / members[missing_index].archive_path).unlink()
    with pytest.raises(ValueError, match="invalid staged worker files"):
        validate_worker_inputs(**args)


def test_failure_staging_keeps_available_diagnostic_subset(tmp_path: Path) -> None:
    """Failure staging keeps available diagnostic subset."""
    root, destination = tmp_path / "source", tmp_path / "staged"
    _write(root, "validate-settings.log", b"validation log\n")
    staged = stage_handoff(
        state_root=root,
        destination=destination,
        request=HandoffRequest("prepare-aggregate", BATCH),
    )
    name = ".debug_artifacts/prepare/validation/logs/validate-settings.log"
    assert staged == [name]
    assert _files(destination) == {name: b"validation log\n"}


def test_success_staging_rejects_missing_runtime_member(tmp_path: Path) -> None:
    """Success staging rejects missing runtime member."""
    with pytest.raises(FileNotFoundError, match="required handoff member missing"):
        stage_handoff(
            state_root=tmp_path / "source",
            destination=tmp_path / "destination",
            request=HandoffRequest("prepare-aggregate", BATCH, require_runtime=True),
        )


def test_prepare_staging_copies_expected_files_without_worker_inputs(
    tmp_path: Path,
) -> None:
    """Prepare staging copies expected files without worker inputs."""
    root, destination = tmp_path / "source", tmp_path / "staged"
    expected = _prepare_files(root)
    _worker_files(root, "worker-01")
    _worker_files(root, "worker-02")
    _write(root, "validate-settings.log", b"validation log\n")
    name = ".debug_artifacts/prepare/validation/logs/validate-settings.log"
    expected[name] = b"validation log\n"
    stage_handoff(
        state_root=root,
        destination=destination,
        request=HandoffRequest("prepare-aggregate", BATCH, require_runtime=True),
    )
    assert _files(destination) == expected
    restored = tmp_path / "restored"
    restore_handoff(
        state_root=restored,
        source=destination,
        request=HandoffRequest("prepare-aggregate", BATCH, config_name="block"),
    )
    assert _files(restored) == expected


def test_failed_worker_stages_only_available_members(tmp_path: Path) -> None:
    """Failed worker stages only available members."""
    root, destination = tmp_path / "source", tmp_path / "staged"
    status = f".workflow_state/status/{BATCH}/worker-01.yaml"
    log = f".debug_artifacts/workers/{BATCH}/worker-01/logs/worker.log"
    values = {
        status: (
            f"batch_id: {BATCH}\nworker_id: worker-01\n"
        ).encode(),
        log: b"partial log\n",
    }
    for path, data in values.items():
        _write(root, path, data)
    stage_handoff(
        state_root=root,
        destination=destination,
        request=HandoffRequest("worker-aggregate", BATCH, worker_id="worker-01"),
    )
    assert _files(destination) == values
    restored = tmp_path / "restored"
    restore_handoff(
        state_root=restored,
        source=destination,
        request=HandoffRequest("worker-aggregate", BATCH, worker_id="worker-01"),
    )
    assert _files(restored) == values


def test_restore_rejects_producer_identity_mismatch(tmp_path: Path) -> None:
    """Restore rejects producer identity mismatch."""
    source = tmp_path / "source"
    _worker_files(source, "worker-01", batch_id="other-batch")
    with pytest.raises(ValueError, match="identity mismatch"):
        restore_handoff(
            state_root=tmp_path / "restored",
            source=source,
            request=HandoffRequest(
                "prepare-worker", BATCH, worker_id="worker-01", config_name="block"
            ),
        )


def test_restore_requires_worker_config_identity(tmp_path: Path) -> None:
    """Worker restore fails closed when the expected config is not supplied."""
    source = tmp_path / "source"
    _worker_files(source, "worker-01")
    restored = tmp_path / "restored"

    with pytest.raises(ValueError, match="worker config name is required"):
        restore_handoff(
            state_root=restored,
            source=source,
            request=HandoffRequest(
                "prepare-worker", BATCH, worker_id="worker-01"
            ),
        )

    assert not restored.exists()


@pytest.mark.parametrize(
    "runtime_identity",
    [
        {"batch_id": "other-batch", "worker_id": "worker-01", "config_name": "block"},
        {"batch_id": BATCH, "worker_id": "worker-02", "config_name": "block"},
        {"worker_id": "worker-01", "config_name": "block"},
    ],
)
def test_restore_rejects_invalid_runtime_identity_before_copy(
    tmp_path: Path, runtime_identity: dict[str, str]
) -> None:
    """Restore validates the JSON runtime identity before writing either member."""
    source = tmp_path / "source"
    _worker_files(source, "worker-01")
    runtime_path = PathLayout(source).workflow_state.prepare_worker_config_path(
        batch_id=BATCH, worker_id="worker-01"
    )
    runtime_path.write_text(json.dumps(runtime_identity), encoding="utf-8")
    restored = tmp_path / "restored"
    with pytest.raises(ValueError, match="identity mismatch"):
        restore_handoff(
            state_root=restored,
            source=source,
            request=HandoffRequest(
                "prepare-worker", BATCH, worker_id="worker-01", config_name="block"
            ),
        )
    assert not restored.exists()


def test_restore_rejects_legacy_worker_member_before_copy(tmp_path: Path) -> None:
    """A bundle containing only the former runtime file and identity fails restore."""
    source = tmp_path / "source"
    _worker_files(source, "worker-01")
    runtime_path = PathLayout(source).workflow_state.prepare_worker_config_path(
        batch_id=BATCH, worker_id="worker-01"
    )
    runtime_path.unlink()
    runtime_path.with_name("runtime-config.yaml").write_text(
        f"batch_id: {BATCH}\nworker_id: worker-01\nconfig_name: block\n",
        encoding="utf-8",
    )
    restored = tmp_path / "restored"
    with pytest.raises(
        FileNotFoundError, match=r"required handoff member missing: .*runtime-config\.json"
    ):
        restore_handoff(
            state_root=restored,
            source=source,
            request=HandoffRequest(
                "prepare-worker", BATCH, worker_id="worker-01", config_name="block"
            ),
        )
    assert not restored.exists()


@pytest.mark.parametrize(
    "runtime_config",
    [
        pytest.param(
            f"batch_id: {BATCH}\nworker_id: worker-01\nconfig_name: block\n",
            id="yaml",
        ),
        pytest.param(
            f'{{"batch_id":"other-batch","batch_id":"{BATCH}",'
            '"worker_id":"worker-01","config_name":"block"}',
            id="duplicate-identity-key",
        ),
        pytest.param(
            f'{{"batch_id":"{BATCH}","worker_id":"worker-01","config_name":"block",'
            '"runtime_spec":{"cache":{"ttl":1,"ttl":2}}}',
            id="nested-duplicate-key",
        ),
        *[
            pytest.param(
                f'{{"batch_id":"{BATCH}","worker_id":"worker-01","config_name":"block",'
                f'"runtime_spec":{{"cache":{{"ttl":{value}}}}}}}',
                id=value,
            )
            for value in ("NaN", "Infinity", "-Infinity", "1e999", "-1e999")
        ],
    ],
)
def test_restore_rejects_invalid_worker_runtime_json_before_copy(
    tmp_path: Path, runtime_config: str
) -> None:
    """Decode the runtime document strictly before writing either member."""
    source = tmp_path / "source"
    _worker_files(source, "worker-01")
    runtime_path = PathLayout(source).workflow_state.prepare_worker_config_path(
        batch_id=BATCH, worker_id="worker-01"
    )
    runtime_path.write_text(runtime_config, encoding="utf-8")
    restored = tmp_path / "restored"
    with pytest.raises(ValueError, match="identity mismatch"):
        restore_handoff(
            state_root=restored,
            source=source,
            request=HandoffRequest(
                "prepare-worker", BATCH, worker_id="worker-01", config_name="block"
            ),
        )
    assert not restored.exists()


@pytest.mark.parametrize(
    "identity_payload",
    [
        b"not-json\n",
        pytest.param(
            f'{{"batch_id":"other-batch","batch_id":"{BATCH}","worker_id":"worker-01"}}'.encode(),
            id="duplicate-key",
        ),
        json.dumps(
            {
                "batch_id": BATCH,
                "worker_id": "worker-01",
                "extra": "not part of the identity",
            }
        ).encode(),
        json.dumps(
            {
                "batch_id": BATCH,
                "worker_id": "worker-02",
            }
        ).encode(),
        json.dumps(
            {
                "batch_id": BATCH,
                "worker_id": "",
            }
        ).encode(),
    ],
)
def test_restore_rejects_invalid_worker_identity_before_copy(
    tmp_path: Path, identity_payload: bytes
) -> None:
    """Restore validates the JSON identity before writing canonical members."""
    source = tmp_path / "source"
    files = _worker_files(source, "worker-01")
    identity_path = next(
        name for name in files if name.endswith("/worker-identity.json")
    )
    _write(source, identity_path, identity_payload)
    restored = tmp_path / "restored"
    with pytest.raises(ValueError, match="identity mismatch"):
        restore_handoff(
            state_root=restored,
            source=source,
            request=HandoffRequest(
                "prepare-worker", BATCH, worker_id="worker-01", config_name="block"
            ),
        )
    assert not restored.exists()


def test_restore_rejects_unexpected_member(tmp_path: Path) -> None:
    """Restore rejects unexpected member."""
    source = tmp_path / "source"
    _worker_files(source, "worker-01")
    _write(source, "unexpected.txt", b"unexpected")
    with pytest.raises(ValueError, match="unexpected handoff file"):
        restore_handoff(
            state_root=tmp_path / "restored",
            source=source,
            request=HandoffRequest(
                "prepare-worker", BATCH, worker_id="worker-01", config_name="block"
            ),
        )


def test_restore_rejects_aggregate_config_identity_mismatch(tmp_path: Path) -> None:
    """Restore rejects aggregate config identity mismatch."""
    source = tmp_path / "source"
    _prepare_files(source)
    with pytest.raises(ValueError, match="identity mismatch"):
        restore_handoff(
            state_root=tmp_path / "restored",
            source=source,
            request=HandoffRequest("prepare-aggregate", BATCH, config_name="other"),
        )


def test_restore_rejects_worker_status_identity_mismatch_before_copy(
    tmp_path: Path,
) -> None:
    """Reject a worker status for another batch before restoring members."""
    source = tmp_path / "source"
    status_path = PathLayout(source).workflow_state.worker_status_path(
        batch_id=BATCH, worker_id="worker-01"
    )
    status_path.parent.mkdir(parents=True)
    status_path.write_text(
        f"batch_id: other-batch\nworker_id: worker-01\n",
        encoding="utf-8",
    )
    restored = tmp_path / "restored"

    with pytest.raises(ValueError, match="identity mismatch"):
        restore_handoff(
            state_root=restored,
            source=source,
            request=HandoffRequest("worker-aggregate", BATCH, worker_id="worker-01"),
        )

    assert not restored.exists()


def test_staging_rejects_unindexed_source_member(tmp_path: Path) -> None:
    """Staging rejects unindexed source member."""
    source = tmp_path / "source"
    _prepare_files(source)
    _write(
        source,
        f".workflow_state/batches/{BATCH}/source_inputs/source-0001.txt",
        b"extra\n",
    )
    with pytest.raises(ValueError, match="source input set"):
        stage_handoff(
            state_root=source,
            destination=tmp_path / "staged",
            request=HandoffRequest("prepare-aggregate", BATCH, require_runtime=True),
        )
