"""Output file lifecycle helpers for pipeline runs."""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Any, cast

from ..shared import OUTPUT_SUFFIXES, REVIEW_OUTPUT_FORMAT, SourceJob
from ..path_layout import DEBUG_ARTIFACTS_DIR
from ..runtime.pure_helpers import (
    REVIEW_CLASSIFICATION_DNS_FILTERED_OUT,
    REVIEW_CLASSIFICATION_GEO_FILTERED_OUT,
    REVIEW_CLASSIFICATION_MANUAL_FILTERED_OUT,
    REVIEW_OUTPUT_COLUMNS,
    ReviewOutputRow,
    build_review_output_row,
)

log = logging.getLogger(__name__)
RAW_OUTPUT_DIR = DEBUG_ARTIFACTS_DIR / "runtime" / "raw"


def review_basename_for_job(job: SourceJob) -> str:
    """Return the output basename used for all generated files for a job."""
    return job.output_stem


def review_output_path_for_job(job: SourceJob) -> Path:
    """Return the review-output path for one source job."""
    output_dir = Path(job.config["output"].get("directory", "."))
    review_name = f"{review_basename_for_job(job)}.{REVIEW_OUTPUT_FORMAT}"
    return output_dir / "review" / review_name


def filtered_output_path_for_job(job: SourceJob) -> Path:
    """Return the filtered-output text path for one source job."""
    output_dir = Path(job.config["output"].get("directory", "."))
    return output_dir / "filtered" / f"{job.output_stem}.{OUTPUT_SUFFIXES['txt']}"


def dead_output_path_for_job(job: SourceJob) -> Path:
    """Return the dead-output text path for one source job."""
    output_dir = Path(job.config["output"].get("directory", "."))
    return output_dir / "dead" / f"{job.output_stem}.{OUTPUT_SUFFIXES['txt']}"


def audit_output_path_for_job(job: SourceJob) -> Path:
    """Return the terminal-row path for one job, honoring runtime-only overrides."""
    output_payload = job.config.get("output", {})
    terminal_rows_file = str(output_payload.get("terminal_rows_file", "")).strip()
    if terminal_rows_file:
        return Path(terminal_rows_file)
    return RAW_OUTPUT_DIR / f"{job.output_stem}.{OUTPUT_SUFFIXES['audit']}"


def write_review_rows(review_path: Path, review_rows: list[dict[str, Any]]) -> None:
    """Write review rows to the CSV review output in deterministic order."""
    if not review_rows:
        return

    review_path.parent.mkdir(parents=True, exist_ok=True)
    should_write_header = not review_path.exists() or review_path.stat().st_size == 0
    with review_path.open("a", encoding="utf-8", newline="") as review_handle:
        writer = csv.DictWriter(
            review_handle,
            fieldnames=REVIEW_OUTPUT_COLUMNS,
            extrasaction="ignore",
        )
        if should_write_header:
            writer.writeheader()
        for row in sorted(
            review_rows,
            key=lambda current: (
                str(current.get("input_name") or current["host"]),
                str(current["host"]),
            ),
        ):
            review_row: ReviewOutputRow = build_review_output_row(row)
            input_classification = str(row.get("classification", ""))
            input_reason = str(row.get("classification_reason", ""))
            if (
                input_classification
                in {
                    REVIEW_CLASSIFICATION_DNS_FILTERED_OUT,
                    REVIEW_CLASSIFICATION_GEO_FILTERED_OUT,
                    REVIEW_CLASSIFICATION_MANUAL_FILTERED_OUT,
                }
                and input_reason
                and input_reason != review_row["classification_reason"]
            ):
                log.debug(
                    "Review row rewrite changed existing reason for host=%s path=%s "
                    "classification=%s input_reason=%s output_reason=%s",
                    str(row.get("host", "")),
                    review_path,
                    input_classification,
                    input_reason,
                    review_row["classification_reason"],
                )
            writer.writerow(cast(Any, review_row))


def output_paths_for_job(job: SourceJob) -> dict[str, Path]:
    """Return concrete output paths for one source job."""
    return {
        "filtered": filtered_output_path_for_job(job),
        "dead": dead_output_path_for_job(job),
        "audit": audit_output_path_for_job(job),
    }


def open_output_files(job: SourceJob) -> dict[str, Any]:
    """Open output files for one source job."""
    output_paths = output_paths_for_job(job)
    output_dir = Path(job.config["output"]["directory"])
    output_dir.mkdir(parents=True, exist_ok=True)
    log.debug(
        "Opening output files for source=%s stem=%s directory=%s",
        job.source_id,
        job.output_stem,
        output_dir,
    )
    output_files: dict[str, Any] = {}
    for format_name in ["filtered", "dead", "audit"]:
        output_path = output_paths[format_name]
        output_path.parent.mkdir(parents=True, exist_ok=True)
        log.debug("Opening %s output file %s", format_name, output_path)
        output_files[format_name] = output_path.open(
            "a",
            encoding="utf-8",
            newline="",
        )
    return output_files


def close_output_files(output_files: dict[str, Any]) -> None:
    """Close all opened output files."""
    for handle in output_files.values():
        handle.close()
    log.debug("Closed %d output files", len(output_files))


def csv_row_signature(row: ReviewOutputRow) -> str:
    """Return a deterministic signature for one CSV row."""
    return repr(tuple(row[column] for column in REVIEW_OUTPUT_COLUMNS))
