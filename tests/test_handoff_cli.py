"""Check workflow handoff restore identity through the actual CLI."""

from pathlib import Path
import subprocess

import pytest

from domain_pipeline.handoff_io import write_csv, write_json, write_yaml
from domain_pipeline.paths import PathLayout


def _write_prepare_aggregate_fixture(archive: Path, batch_id: str) -> None:
    """Write a minimal valid prepare-to-aggregate archive."""
    state = PathLayout(archive).workflow_state
    write_yaml(
        state.prepare_aggregate_config_path(batch_id=batch_id),
        {
            "batch_id": batch_id,
            "config_name": "block",
            "excluded_source_hosts": [],
            "output": {
                "filtered": [
                    {"path": "output/filtered/block.txt", "format": "plain"}
                ],
                "unactionable": "output/unactionable/block.txt",
                "review": "output/review/block.csv",
            },
        },
    )
    write_csv(state.batch_worker_ids_path(batch_id=batch_id), ("worker_id",), [])
    write_csv(
        state.batch_manual_domains_path(batch_id=batch_id),
        ("host", "registrable_domain_present", "registrable_domain"),
        [],
    )
    write_yaml(state.batch_preparation_terminal_path(batch_id=batch_id), [])
    source_items = state.batch_source_items_path(batch_id=batch_id)
    source_items.parent.mkdir(parents=True, exist_ok=True)
    source_items.write_text("", encoding="utf-8")
    write_json(
        state.batch_source_item_index_path(batch_id=batch_id),
        {
            "batch_id": batch_id,
            "sources": [],
            "valid_source_items_by_input_domain": {},
            "valid_source_items_without_extractable_registrable_domain": [],
            "adblock_metadata": [],
        },
    )
    source_item_diagnostics = state.batch_source_item_diagnostics_path(
        batch_id=batch_id
    )
    source_item_diagnostics.write_text("", encoding="utf-8")


def _write_prepare_worker_fixture(
    archive: Path, *, batch_id: str, worker_id: str
) -> None:
    """Write a minimal prepare-to-worker archive with a known config name."""
    state = PathLayout(archive).workflow_state
    write_json(
        state.prepare_worker_config_path(batch_id=batch_id, worker_id=worker_id),
        {
            "batch_id": batch_id,
            "worker_id": worker_id,
            "config_name": "block",
            "runtime_spec": {},
            "prepared_metadata": {},
        },
    )
    write_json(
        state.prepare_worker_identity_path(batch_id=batch_id, worker_id=worker_id),
        {"batch_id": batch_id, "worker_id": worker_id},
    )


@pytest.mark.parametrize(("config_name", "succeeds"), [("block", True), ("other", False)])
def test_aggregate_restore_cli_checks_configuration_identity(
    tmp_path: Path, config_name: str, succeeds: bool
) -> None:
    """Pass the workflow's expected configuration through the actual CLI."""
    project = Path(__file__).resolve().parents[1]
    archive = tmp_path / "archive"
    state_root = tmp_path / "restored"
    batch_id = "batch-123-attempt-1"
    _write_prepare_aggregate_fixture(archive, batch_id)
    invocation = [
        str(project / "src/pipeline_run.py"),
        "handoff-restore",
        "--state-root", str(state_root),
        "--handoff", "prepare-aggregate",
        "--batch-id", batch_id,
        "--config-name", config_name,
        "--archive", str(archive),
    ]
    result = subprocess.run(invocation, cwd=project, capture_output=True, text=True, check=False)
    restored = PathLayout(state_root).workflow_state.prepare_aggregate_config_path(
        batch_id=batch_id
    )
    assert (result.returncode == 0) is succeeds, result.stderr
    assert restored.is_file() is succeeds
    if not succeeds:
        assert "handoff identity mismatch" in result.stderr
    workflow = (project / ".github/workflows/_pipeline-run-batch.yml").read_text(encoding="utf-8")
    assert '--config-name "${{ inputs.config_name }}"' in workflow


@pytest.mark.parametrize(("config_name", "succeeds"), [("block", True), ("other", False)])
def test_worker_restore_cli_checks_configuration_identity(
    tmp_path: Path, config_name: str, succeeds: bool
) -> None:
    """Worker restore rejects a prepared bundle from a different config."""
    project = Path(__file__).resolve().parents[1]
    archive = tmp_path / "archive"
    state_root = tmp_path / "restored"
    batch_id = "batch-123-attempt-1"
    worker_id = "worker-1"
    _write_prepare_worker_fixture(
        archive, batch_id=batch_id, worker_id=worker_id
    )
    invocation = [
        str(project / "src/pipeline_run.py"),
        "handoff-restore",
        "--state-root", str(state_root),
        "--handoff", "prepare-worker",
        "--batch-id", batch_id,
        "--worker-id", worker_id,
        "--config-name", config_name,
        "--archive", str(archive),
    ]
    result = subprocess.run(
        invocation, cwd=project, capture_output=True, text=True, check=False
    )
    worker_path = Path(".workflow_state") / "batches" / batch_id / "workers" / worker_id
    assert (result.returncode == 0) is succeeds, result.stderr
    if succeeds:
        restored = state_root / worker_path
        assert {member.name for member in restored.iterdir()} == {
            "runtime-config.json",
            "worker-identity.json",
        }
        for member in restored.iterdir():
            assert member.read_bytes() == (archive / worker_path / member.name).read_bytes()
    else:
        assert "handoff identity mismatch" in result.stderr
        assert not state_root.exists()

    workflow = (
        project / ".github/workflows/_pipeline-run-batch.yml"
    ).read_text(encoding="utf-8")
    worker_restore = (
        "--state-root . --handoff prepare-worker \\\n"
        "            --batch-id \"${{ needs.prepare_run.outputs.batch_id }}\" \\\n"
        "            --worker-id \"${{ matrix.worker_id }}\" --config-name \"${{ inputs.config_name }}\" \\\n"
        "            --archive \".tmp/combined-worker-inputs/${{ matrix.worker_id }}\""
    )
    assert worker_restore in workflow
