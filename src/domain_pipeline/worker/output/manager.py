"""Worker-level result output path and review projection helpers."""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Any, cast

from domain_pipeline.worker.output.rows import (
    REVIEW_OUTPUT_COLUMNS,
    ReviewOutputRow,
    ReviewRowProjector,
)

log = logging.getLogger(__name__)
TEXT_OUTPUT_EXTENSION = "txt"
REVIEW_OUTPUT_EXTENSION = "csv"
RAW_AUDIT_OUTPUT_EXTENSION = "jsonl"


def _output_path(output_spec: dict[str, Any], key: str) -> Path:
    """Return one required worker-owned output path."""
    value = str(output_spec.get(key, "")).strip()
    if not value:
        raise ValueError(f"worker output_spec.{key} is required")
    return Path(value)


def review_output_path(output_spec: dict[str, Any]) -> Path:
    """Return the source-blind worker review CSV path."""
    return _output_path(output_spec, "review")


def unactionable_output_path(output_spec: dict[str, Any]) -> Path:
    """Return the input-domain unactionable TXT path."""
    return _output_path(output_spec, "unactionable")


def result_collections_path(output_spec: dict[str, Any]) -> Path:
    """Return the internal JSONL path for both closed result collections."""
    return _output_path(output_spec, "domain_results")


def output_paths(output_spec: dict[str, Any]) -> dict[str, Path]:
    """Return every concrete result output path for this worker."""
    return {
        "unactionable": unactionable_output_path(output_spec),
        "review": review_output_path(output_spec),
        "results": result_collections_path(output_spec),
    }


def write_review_rows(review_path: Path, review_rows: list[dict[str, Any]]) -> None:
    """Replace the CSV review output with source-blind input-domain rows."""
    projector = ReviewRowProjector()
    projected_rows: list[ReviewOutputRow] = [
        projector.project(row) for row in review_rows
    ]
    write_projected_review_rows(review_path, projected_rows)


def write_projected_review_rows(
    review_path: Path, review_rows: list[ReviewOutputRow]
) -> None:
    """Replace the CSV review output with already-projected rows."""
    review_path.parent.mkdir(parents=True, exist_ok=True)
    with review_path.open("w", encoding="utf-8", newline="") as review_handle:
        writer = csv.DictWriter(
            review_handle,
            fieldnames=REVIEW_OUTPUT_COLUMNS,
            extrasaction="ignore",
            quoting=csv.QUOTE_ALL,
        )
        writer.writeheader()
        for row in sorted(review_rows, key=lambda current: str(current["host"])):
            writer.writerow(cast(Any, row))


def input_domain_output_value(input_domain: str) -> str:
    """Return one nonempty normalized input-domain value for TXT output."""
    value = input_domain.strip()
    if not value:
        raise ValueError("worker input-domain output requires a value")
    return value


def review_row_signature(row: ReviewOutputRow) -> str:
    """Return a deterministic signature for one CSV row."""
    return repr(tuple(row[column] for column in REVIEW_OUTPUT_COLUMNS))
