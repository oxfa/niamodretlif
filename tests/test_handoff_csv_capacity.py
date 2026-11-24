"""Regression coverage for producer-supplied long review fields."""

from __future__ import annotations

import csv
import hashlib
import io
import zipfile
from pathlib import Path

import yaml

from domain_pipeline.paths import PathLayout
from domain_pipeline.pipeline_run.format_version import PIPELINE_RUN_FORMAT_VERSION
from domain_pipeline.prepare.batch_writer import PreparedBatchWriter
from domain_pipeline.prepare.config.loader import load_config_without_runtime_credentials
from domain_pipeline.prepare.config.models import InputConfig
from domain_pipeline.prepare.planner import PreparationPlanner
from domain_pipeline.prepare.prepare_to_aggregate_manifest import (
    load_prepare_aggregate_manifest_for_batch,
)
from domain_pipeline.worker.output.rows import REVIEW_OUTPUT_COLUMNS
from domain_pipeline.worker.worker_to_aggregate_manifest import _read_review_rows
from worker_artifact_correlation import validate_archive


def test_prepare_review_label_round_trips_beyond_csv_default(tmp_path: Path) -> None:
    """A valid source label survives prepare production and aggregate loading."""
    original_limit = csv.field_size_limit()
    try:
        csv.field_size_limit(131072)
        label = "x" * 131073
        source = tmp_path / "source.txt"
        source.write_text("com\n", encoding="utf-8")
        config = load_config_without_runtime_credentials(Path("config/block.yaml"))
        config["sources"] = config["sources"][:1]
        config["sources"][0]["input"] = InputConfig(
            type="file", location=str(source), format="plain", label=label
        ).model_dump()
        prepared = PreparationPlanner(source_root=Path.cwd()).prepare_config(config)
        writer = PreparedBatchWriter()
        batch = writer.from_prepared_inputs(
            prepared_inputs=prepared, worker_ids=["worker-1"], batch_id="batch"
        )
        writer.write(batch, state_root=tmp_path)
        result = load_prepare_aggregate_manifest_for_batch(
            batch_id="batch", state_root=tmp_path
        )
        assert result.preparation_review_output_rows[0]["source_input_label"] == label
    finally:
        csv.field_size_limit(original_limit)


def test_worker_review_accepts_long_source_label(tmp_path: Path) -> None:
    """Worker review reading accepts producer-sized labels."""
    original_limit = csv.field_size_limit()
    try:
        csv.field_size_limit(131072)
        label = "x" * 131073
        review = tmp_path / "review.csv"
        with review.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=REVIEW_OUTPUT_COLUMNS)
            writer.writeheader()
            writer.writerow({"host": "example.com", "source_input_label": label})
        assert _read_review_rows(review)[0]["source_input_label"] == label
    finally:
        csv.field_size_limit(original_limit)


def test_worker_archive_accepts_long_source_label() -> None:
    """Archive validation accepts producer-sized review fields."""
    original_limit = csv.field_size_limit()
    try:
        csv.field_size_limit(131072)
        label = "x" * 131073
        review = io.StringIO(newline="")
        writer = csv.DictWriter(review, fieldnames=REVIEW_OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerow({"host": "example.com", "source_input_label": label})
        paths = PathLayout(Path(".")).workflow_state
        state = {
            "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
            "batch_id": "batch",
            "worker_id": "worker-1",
            "handoff_finalized": True,
            "cache_present": False,
            "cache_sha256": None,
        }
        members = {
            paths.worker_aggregate_manifest_path(
                batch_id="batch", worker_id="worker-1"
            ): yaml.safe_dump(state),
            paths.worker_handoff_unactionable_path(
                batch_id="batch", worker_id="worker-1"
            ): "",
            paths.worker_handoff_review_path(
                batch_id="batch", worker_id="worker-1"
            ): review.getvalue(),
            paths.worker_handoff_terminal_path(
                batch_id="batch", worker_id="worker-1"
            ): "---\n[]\n",
            paths.worker_status_path(batch_id="batch", worker_id="worker-1"): yaml.safe_dump(
                {
                    "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
                    "batch_id": "batch",
                    "worker_id": "worker-1",
                    "conclusion": "success",
                }
            ),
        }
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for path, content in members.items():
                archive.writestr(path.as_posix(), content)
        payload = stream.getvalue()
        digest = f"sha256:{hashlib.sha256(payload).hexdigest()}"
        assert validate_archive(payload, digest, "batch", "worker-1")
    finally:
        csv.field_size_limit(original_limit)
