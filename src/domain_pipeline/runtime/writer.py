"""Terminal result collector and final deterministic writer."""

from __future__ import annotations

import json
import shutil
from collections import Counter
from dataclasses import dataclass
import logging
from pathlib import Path
from typing import Any

from ..io.output_manager import (
    csv_row_signature,
    output_paths_for_job,
    review_output_path_for_job,
    write_review_rows,
)
from ..output_invariants import DuplicateOutputInvariantError
from .pure_helpers import build_review_output_row
from .contracts import CompletedHostResult
from ..shared import SourceJob

logger = logging.getLogger(__name__)


def _json_row_signature(row: dict[str, Any]) -> str:
    return json.dumps(row, sort_keys=True, separators=(",", ":"))


def _incomplete_run_relative_path(path: Path) -> Path:
    """Return one stable relative artifact path under an incomplete-run root."""
    if path.is_absolute():
        return Path("absolute", *[part for part in path.parts if part != path.anchor])
    return Path("relative", *path.parts)


@dataclass
class WriterResult:
    """Collected counts and concrete output paths for one runtime run."""

    counts: Counter
    output_paths: list[Path]


GroupKey = tuple[Path, Path, Path, Path]


@dataclass
class _BufferedOutputGroup:  # pylint: disable=too-many-instance-attributes
    """In-memory rows accepted for one output-path group."""

    job: SourceJob
    filtered_rows: list[dict[str, Any]]
    dead_rows: list[dict[str, Any]]
    audit_rows: list[dict[str, Any]]
    review_rows: list[dict[str, Any]]
    seen_host_outputs: dict[str, set[str]]
    seen_audit_rows: set[str]
    seen_review_rows: set[str]


class ResultCollectorWriter:
    """Collect terminal results and write outputs only after the full run completes."""

    def __init__(self) -> None:
        self.groups: dict[GroupKey, _BufferedOutputGroup] = {}
        self.counts: Counter = Counter()
        self._seen_paths: set[Path] = set()
        self._output_paths: list[Path] = []

    def _group_for_job(self, job: SourceJob) -> _BufferedOutputGroup:
        """Return the buffered output group for one source job."""
        output_paths = output_paths_for_job(job)
        group_key = (
            output_paths["filtered"],
            output_paths["dead"],
            output_paths["audit"],
            review_output_path_for_job(job),
        )
        group = self.groups.get(group_key)
        if group is None:
            logger.debug(
                "Creating writer output group for source=%s filtered=%s dead=%s audit=%s "
                "review=%s",
                job.source_id,
                group_key[0],
                group_key[1],
                group_key[2],
                group_key[3],
            )
            group = _BufferedOutputGroup(
                job=job,
                filtered_rows=[],
                dead_rows=[],
                audit_rows=[],
                review_rows=[],
                seen_host_outputs={"filtered": set(), "dead": set()},
                seen_audit_rows=set(),
                seen_review_rows=set(),
            )
            self.groups[group_key] = group
        for path in group_key:
            if path in self._seen_paths:
                continue
            self._seen_paths.add(path)
            self._output_paths.append(path)
        return group

    def _queue_review_row(
        self,
        *,
        group: _BufferedOutputGroup,
        row: dict[str, Any],
    ) -> None:
        review_signature = csv_row_signature(build_review_output_row(row))
        if review_signature in group.seen_review_rows:
            raise DuplicateOutputInvariantError(
                "review_row",
                str(row["host"]),
                context={
                    "source": group.job.source_id,
                    "signature": review_signature,
                },
            )
        group.seen_review_rows.add(review_signature)
        group.review_rows.append(row)
        logger.debug("Queued host=%s for review output", row["host"])

    def add(self, result: CompletedHostResult) -> None:
        """Record one completed terminal result."""
        group = self._group_for_job(result.job)
        logger.debug(
            "Collecting terminal result for source=%s host=%s classification=%s route=%s",
            result.job.source_id,
            result.row["host"],
            result.classification,
            result.route,
        )
        self.counts[result.classification] += 1
        self.counts[f"route_{result.route}"] += 1
        if result.route == "drop":
            self.counts["filtered_dead_root"] += 1
            host = result.row["host"]
            if host in group.seen_host_outputs["dead"]:
                raise DuplicateOutputInvariantError(
                    "dead_host",
                    str(host),
                    context={"source": group.job.source_id},
                )
            group.seen_host_outputs["dead"].add(host)
            group.dead_rows.append(result.row)
            logger.debug("Queued host=%s for dead output", host)
            logger.debug(
                "Dropped host=%s after terminal routing decision",
                result.row["host"],
            )
            return

        if result.route == "normal_output":
            host = result.row["host"]
            if host in group.seen_host_outputs["filtered"]:
                raise DuplicateOutputInvariantError(
                    "filtered_host",
                    str(host),
                    context={"source": group.job.source_id},
                )
            group.seen_host_outputs["filtered"].add(host)
            group.filtered_rows.append(result.row)
            logger.debug("Queued host=%s for filtered output", host)
        if result.route == "review":
            self._queue_review_row(group=group, row=result.row)

        audit_signature = _json_row_signature(result.row)
        if audit_signature in group.seen_audit_rows:
            raise DuplicateOutputInvariantError(
                "audit_row",
                str(result.row["host"]),
                context={
                    "source": group.job.source_id,
                    "signature": audit_signature,
                },
            )
        group.seen_audit_rows.add(audit_signature)
        group.audit_rows.append(result.row)
        logger.debug("Queued host=%s for audit output", result.row["host"])

    def add_terminal_row(
        self,
        *,
        job: SourceJob,
        row: dict[str, Any],
        route: str = "review",
    ) -> None:
        """Record one preparation-owned terminal row without synthetic runtime objects."""
        group = self._group_for_job(job)
        classification = str(row.get("classification", ""))
        self.counts[classification] += 1
        self.counts[f"route_{route}"] += 1
        if route == "review":
            self._queue_review_row(group=group, row=row)
        elif route == "normal_output":
            host = str(row["host"])
            if host in group.seen_host_outputs["filtered"]:
                raise DuplicateOutputInvariantError(
                    "filtered_host",
                    host,
                    context={"source": group.job.source_id},
                )
            group.seen_host_outputs["filtered"].add(host)
            group.filtered_rows.append(row)
        elif route == "drop":
            host = str(row["host"])
            self.counts["filtered_dead_root"] += 1
            if host in group.seen_host_outputs["dead"]:
                raise DuplicateOutputInvariantError(
                    "dead_host",
                    host,
                    context={"source": group.job.source_id},
                )
            group.seen_host_outputs["dead"].add(host)
            group.dead_rows.append(row)
        audit_signature = _json_row_signature(row)
        if audit_signature in group.seen_audit_rows:
            raise DuplicateOutputInvariantError(
                "audit_row",
                str(row["host"]),
                context={
                    "source": group.job.source_id,
                    "signature": audit_signature,
                },
            )
        group.seen_audit_rows.add(audit_signature)
        group.audit_rows.append(row)

    def _write_group_files(
        self,
        filtered_path: Path,
        dead_path: Path,
        audit_path: Path,
        review_path: Path,
        group: _BufferedOutputGroup,
    ) -> None:
        """Write one buffered group to explicit target paths."""
        filtered_path.parent.mkdir(parents=True, exist_ok=True)
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        with (
            filtered_path.open("w", encoding="utf-8", newline="") as filtered_handle,
            audit_path.open("w", encoding="utf-8", newline="") as audit_handle,
        ):
            for row in sorted(group.filtered_rows, key=lambda current: current["host"]):
                filtered_handle.write(f"{row['host']}\n")
            for row in sorted(group.audit_rows, key=lambda current: current["host"]):
                json.dump(row, audit_handle)
                audit_handle.write("\n")
        if group.dead_rows:
            dead_path.parent.mkdir(parents=True, exist_ok=True)
            with dead_path.open("w", encoding="utf-8", newline="") as dead_handle:
                for row in sorted(group.dead_rows, key=lambda current: current["host"]):
                    dead_handle.write(f"{row['host']}\n")
        if group.review_rows:
            write_review_rows(review_path, group.review_rows)
            logger.debug(
                "Wrote %d review rows to %s",
                len(group.review_rows),
                review_path,
            )

    def write(self) -> WriterResult:
        """Write collected results to their final output files."""
        for (
            filtered_path,
            dead_path,
            audit_path,
            review_path,
        ), group in self.groups.items():
            dead_hosts = {str(row["host"]) for row in group.dead_rows}
            audited_hosts = {str(row["host"]) for row in group.audit_rows}
            missing_dead_audit_hosts = sorted(dead_hosts - audited_hosts)
            if missing_dead_audit_hosts:
                logger.debug(
                    "Writer output group for source=%s has %d dead/drop hosts "
                    "omitted from audit output: %s",
                    group.job.source_id,
                    len(missing_dead_audit_hosts),
                    missing_dead_audit_hosts,
                )
            logger.debug(
                "Writing output group for source=%s filtered_rows=%d dead_rows=%d "
                "audit_rows=%d review_rows=%d",
                group.job.source_id,
                len(group.filtered_rows),
                len(group.dead_rows),
                len(group.audit_rows),
                len(group.review_rows),
            )
            self._write_group_files(
                filtered_path,
                dead_path,
                audit_path,
                review_path,
                group,
            )

        return WriterResult(
            counts=self.counts,
            output_paths=[path for path in self._output_paths if path.is_file()],
        )

    def write_incomplete_run(self, root_dir: Path) -> WriterResult:
        """Write buffered results under one incomplete-run root directory."""
        if root_dir.exists():
            shutil.rmtree(root_dir)
        root_dir.mkdir(parents=True, exist_ok=True)
        incomplete_paths: list[Path] = []
        for (
            filtered_path,
            dead_path,
            audit_path,
            review_path,
        ), group in self.groups.items():
            target_filtered = root_dir / _incomplete_run_relative_path(filtered_path)
            target_dead = root_dir / _incomplete_run_relative_path(dead_path)
            target_audit = root_dir / _incomplete_run_relative_path(audit_path)
            target_review = root_dir / _incomplete_run_relative_path(review_path)
            self._write_group_files(
                target_filtered,
                target_dead,
                target_audit,
                target_review,
                group,
            )
            incomplete_paths.extend(
                [
                    path
                    for path in [
                        target_filtered,
                        target_dead,
                        target_audit,
                        target_review,
                    ]
                    if path.is_file()
                ]
            )
        return WriterResult(
            counts=Counter(self.counts),
            output_paths=incomplete_paths,
        )
