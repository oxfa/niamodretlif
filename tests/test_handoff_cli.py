"""Check the workflow's aggregate handoff restore command."""

from pathlib import Path
import subprocess

import pytest

from domain_pipeline.handoff_io import write_csv, write_json, write_yaml
from domain_pipeline.paths import PathLayout
from domain_pipeline.pipeline_run.format_version import PIPELINE_RUN_FORMAT_VERSION
from domain_pipeline.worker.output.rows import REVIEW_OUTPUT_COLUMNS


def _write_prepare_aggregate_fixture(archive: Path, batch_id: str) -> None:
    """Write a minimal valid prepare-to-aggregate archive."""
    state = PathLayout(archive).workflow_state
    write_yaml(
        state.prepare_aggregate_config_path(batch_id=batch_id),
        {
            "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
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
    write_csv(
        state.batch_preparation_review_path(batch_id=batch_id),
        REVIEW_OUTPUT_COLUMNS,
        [],
    )
    write_yaml(state.batch_preparation_terminal_path(batch_id=batch_id), [])
    write_csv(
        state.batch_source_formats_path(batch_id=batch_id),
        ("source_ordinal", "source_format"),
        [],
    )
    write_csv(
        state.batch_source_line_index_path(batch_id=batch_id),
        ("registrable_domain", "source_ordinal", "line_number"),
        [],
    )
    source_items = state.batch_source_items_path(batch_id=batch_id)
    source_items.parent.mkdir(parents=True, exist_ok=True)
    source_items.write_text("", encoding="utf-8")
    write_json(
        state.batch_source_item_index_path(batch_id=batch_id),
        {
            "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
            "batch_id": batch_id,
            "sources": [],
            "valid_source_items_by_registrable_domain": {},
            "valid_source_items_without_extractable_registrable_domain": [],
            "adblock_metadata": [],
        },
    )
    source_item_diagnostics = state.batch_source_item_diagnostics_path(
        batch_id=batch_id
    )
    source_item_diagnostics.write_text("", encoding="utf-8")


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
