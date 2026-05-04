"""Output file lifecycle helpers for pipeline runs."""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from domain_pipeline.paths.layout import DEBUG_ARTIFACTS_DIR
from domain_pipeline.worker.output.review_labels import PUBLIC_REVIEW_LABELS
from domain_pipeline.worker.output.rows import (
    REVIEW_OUTPUT_COLUMNS,
    ReviewOutputRow,
    build_review_output_row,
)

if TYPE_CHECKING:
    from domain_pipeline.worker.runtime.contracts import WorkerSourceContext

log = logging.getLogger(__name__)
RAW_OUTPUT_DIR = DEBUG_ARTIFACTS_DIR / "runtime" / "raw"
TEXT_OUTPUT_EXTENSION = "txt"
REVIEW_OUTPUT_EXTENSION = "csv"
RAW_AUDIT_OUTPUT_EXTENSION = "jsonl"


def review_basename_for_source(source_context: WorkerSourceContext) -> str:
    """Return the output basename used for all generated files for a source."""
    return source_context.output_stem


def review_output_path_for_source(source_context: WorkerSourceContext) -> Path:
    """Return the review-output path for one worker source context."""
    output_dir = Path(source_context.config["output"].get("directory", "."))
    review_name = (
        f"{review_basename_for_source(source_context)}.{REVIEW_OUTPUT_EXTENSION}"
    )
    return output_dir / "review" / review_name


def filtered_output_path_for_source(source_context: WorkerSourceContext) -> Path:
    """Return the filtered-output text path for one worker source context."""
    output_dir = Path(source_context.config["output"].get("directory", "."))
    return (
        output_dir
        / "filtered"
        / f"{source_context.output_stem}.{TEXT_OUTPUT_EXTENSION}"
    )


def unactionable_output_path_for_source(source_context: WorkerSourceContext) -> Path:
    """Return the unactionable-output text path for one worker source context."""
    output_dir = Path(source_context.config["output"].get("directory", "."))
    return (
        output_dir
        / "unactionable"
        / f"{source_context.output_stem}.{TEXT_OUTPUT_EXTENSION}"
    )


def audit_output_path_for_source(source_context: WorkerSourceContext) -> Path:
    """Return the terminal-row path for one source, honoring runtime-only overrides."""
    output_payload = source_context.config.get("output", {})
    terminal_rows_file = str(output_payload.get("terminal_rows_file", "")).strip()
    if terminal_rows_file:
        return Path(terminal_rows_file)
    return RAW_OUTPUT_DIR / f"{source_context.output_stem}.{RAW_AUDIT_OUTPUT_EXTENSION}"


def write_review_rows(review_path: Path, review_rows: list[dict[str, Any]]) -> None:
    """Replace the CSV review output with review rows in deterministic order."""
    if not review_rows:
        return

    review_path.parent.mkdir(parents=True, exist_ok=True)
    with review_path.open("w", encoding="utf-8", newline="") as review_handle:
        writer = csv.DictWriter(
            review_handle,
            fieldnames=REVIEW_OUTPUT_COLUMNS,
            extrasaction="ignore",
        )
        writer.writeheader()
        for row in sorted(
            review_rows,
            key=lambda current: (
                str(current.get("input_name") or current["host"]),
                str(current["host"]),
            ),
        ):
            review_row: ReviewOutputRow = build_review_output_row(row)
            input_review_label = str(row.get("classification", ""))
            input_reason = str(row.get("classification_reason", ""))
            if (
                input_review_label in PUBLIC_REVIEW_LABELS
                and input_reason
                and input_reason != review_row["classification_reason"]
            ):
                log.debug(
                    "Review row rewrite changed existing reason for host=%s path=%s "
                    "classification=%s input_reason=%s output_reason=%s",
                    str(row.get("host", "")),
                    review_path,
                    input_review_label,
                    input_reason,
                    review_row["classification_reason"],
                )
            writer.writerow(cast(Any, review_row))


def output_paths_for_source(source_context: WorkerSourceContext) -> dict[str, Path]:
    """Return concrete output paths for one worker source context."""
    return {
        "filtered": filtered_output_path_for_source(source_context),
        "unactionable": unactionable_output_path_for_source(source_context),
        "audit": audit_output_path_for_source(source_context),
    }


def csv_row_signature(row: ReviewOutputRow) -> str:
    """Return a deterministic signature for one CSV row."""
    return repr(tuple(row[column] for column in REVIEW_OUTPUT_COLUMNS))
