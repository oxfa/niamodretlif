"""Terminal result collector and deterministic worker-local sidecar writer."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from domain_pipeline.worker.output.manager import (
    csv_row_signature,
    output_paths_for_source,
    review_output_path_for_source,
    txt_output_value,
    write_review_rows,
)
from domain_pipeline.worker.output.invariants import DuplicateOutputInvariantError
from domain_pipeline.worker.output.rows import build_review_output_row

if TYPE_CHECKING:
    from domain_pipeline.worker.runtime.contracts import (
        CompletedHostResult,
        WorkerSourceContext,
    )

logger = logging.getLogger(__name__)


def _json_row_signature(row: dict[str, Any]) -> str:
    return json.dumps(row, sort_keys=True, separators=(",", ":"))


def _audit_row(row: dict[str, Any], *, route: str) -> dict[str, Any]:
    """Return the serialized raw-audit row for one terminal result."""
    audit_row = dict(row)
    audit_row["route"] = route
    return audit_row


@dataclass
class WriterResult:
    """Collected counts and concrete output paths for one runtime run."""

    counts: Counter
    output_paths: list[Path]


GroupKey = tuple[Path, Path, Path, Path]


@dataclass
class OutputGroupRows:
    """Buffered output rows accepted for one output-path group."""

    filtered: list[dict[str, Any]]
    unactionable: list[dict[str, Any]]
    audit: list[dict[str, Any]]
    review: list[dict[str, Any]]


@dataclass
class OutputGroupSeen:
    """Duplicate-detection state for one output-path group."""

    host_outputs: dict[str, set[str]]
    audit_rows: set[str]
    review_rows: set[str]


@dataclass
class OutputGroupBuffer:
    """In-memory rows accepted for one output-path group."""

    source_context: WorkerSourceContext
    rows: OutputGroupRows
    seen: OutputGroupSeen


@dataclass(frozen=True)
class OutputGroupWriteRequest:
    """Concrete output targets and buffered rows for one output group write."""

    filtered_path: Path
    unactionable_path: Path
    audit_path: Path
    review_path: Path
    group: OutputGroupBuffer


class ResultOutputWriter:
    """Collect terminal results and write outputs only after the full run completes."""

    def __init__(self) -> None:
        self.groups: dict[GroupKey, OutputGroupBuffer] = {}
        self.counts: Counter = Counter()
        self._seen_paths: set[Path] = set()
        self._output_paths: list[Path] = []

    def _group_for_source(
        self, source_context: WorkerSourceContext
    ) -> OutputGroupBuffer:
        """Return the buffered output group for one worker source context."""
        output_paths = output_paths_for_source(source_context)
        group_key = (
            output_paths["filtered"],
            output_paths["unactionable"],
            output_paths["audit"],
            review_output_path_for_source(source_context),
        )
        group = self.groups.get(group_key)
        if group is None:
            logger.debug(
                "Creating writer output group for source=%s filtered=%s unactionable=%s audit=%s "
                "review=%s",
                source_context.source_id,
                group_key[0],
                group_key[1],
                group_key[2],
                group_key[3],
            )
            group = OutputGroupBuffer(
                source_context=source_context,
                rows=OutputGroupRows(
                    filtered=[],
                    unactionable=[],
                    audit=[],
                    review=[],
                ),
                seen=OutputGroupSeen(
                    host_outputs={"filtered": set(), "unactionable": set()},
                    audit_rows=set(),
                    review_rows=set(),
                ),
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
        group: OutputGroupBuffer,
        row: dict[str, Any],
    ) -> None:
        review_signature = csv_row_signature(build_review_output_row(row))
        if review_signature in group.seen.review_rows:
            raise DuplicateOutputInvariantError(
                "review_row",
                str(row["host"]),
                context={
                    "source": group.source_context.source_id,
                    "signature": review_signature,
                },
            )
        group.seen.review_rows.add(review_signature)
        group.rows.review.append(row)

    def add(self, result: CompletedHostResult) -> None:
        """Record one completed terminal result."""
        group = self._group_for_source(result.source_context)
        self.counts[result.pipeline_result_code] += 1
        self.counts[f"route_{result.route}"] += 1
        if result.route == "unactionable":
            host = result.row["host"]
            if host in group.seen.host_outputs["unactionable"]:
                raise DuplicateOutputInvariantError(
                    "unactionable_host",
                    str(host),
                    context={"source": group.source_context.source_id},
                )
            group.seen.host_outputs["unactionable"].add(host)
            group.rows.unactionable.append(result.row)
        elif result.route == "filtered":
            host = result.row["host"]
            if host in group.seen.host_outputs["filtered"]:
                raise DuplicateOutputInvariantError(
                    "filtered_host",
                    str(host),
                    context={"source": group.source_context.source_id},
                )
            group.seen.host_outputs["filtered"].add(host)
            group.rows.filtered.append(result.row)
        elif result.route == "review":
            self._queue_review_row(group=group, row=result.row)

        audit_row = _audit_row(result.row, route=result.route)
        audit_signature = _json_row_signature(audit_row)
        if audit_signature in group.seen.audit_rows:
            raise DuplicateOutputInvariantError(
                "audit_row",
                str(result.row["host"]),
                context={
                    "source": group.source_context.source_id,
                    "signature": audit_signature,
                },
            )
        group.seen.audit_rows.add(audit_signature)
        group.rows.audit.append(audit_row)

    def _write_group_files(self, request: OutputGroupWriteRequest) -> None:
        """Write one buffered group to explicit target paths."""
        filtered_path = request.filtered_path
        unactionable_path = request.unactionable_path
        audit_path = request.audit_path
        review_path = request.review_path
        group = request.group
        filtered_path.parent.mkdir(parents=True, exist_ok=True)
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        with (
            filtered_path.open("w", encoding="utf-8", newline="") as filtered_handle,
            audit_path.open("w", encoding="utf-8", newline="") as audit_handle,
        ):
            for row in sorted(
                group.rows.filtered,
                key=lambda current: (txt_output_value(current), current["host"]),
            ):
                filtered_handle.write(f"{txt_output_value(row)}\n")
            for row in sorted(group.rows.audit, key=lambda current: current["host"]):
                json.dump(row, audit_handle)
                audit_handle.write("\n")
        if group.rows.unactionable:
            unactionable_path.parent.mkdir(parents=True, exist_ok=True)
            with unactionable_path.open(
                "w", encoding="utf-8", newline=""
            ) as unactionable_handle:
                for row in sorted(
                    group.rows.unactionable,
                    key=lambda current: (txt_output_value(current), current["host"]),
                ):
                    unactionable_handle.write(f"{txt_output_value(row)}\n")
        elif unactionable_path.exists():
            unactionable_path.unlink()
        if group.rows.review:
            write_review_rows(review_path, group.rows.review)
            logger.debug(
                "Wrote %d review rows to %s",
                len(group.rows.review),
                review_path,
            )
        elif review_path.exists():
            review_path.unlink()

    def write(self) -> WriterResult:
        """Write collected results to their worker-local output sidecar files."""
        for (
            filtered_path,
            unactionable_path,
            audit_path,
            review_path,
        ), group in self.groups.items():
            logger.debug(
                "Writing output group for source=%s filtered_rows=%d unactionable_rows=%d "
                "audit_rows=%d review_rows=%d",
                group.source_context.source_id,
                len(group.rows.filtered),
                len(group.rows.unactionable),
                len(group.rows.audit),
                len(group.rows.review),
            )
            self._write_group_files(
                OutputGroupWriteRequest(
                    filtered_path=filtered_path,
                    unactionable_path=unactionable_path,
                    audit_path=audit_path,
                    review_path=review_path,
                    group=group,
                )
            )

        return WriterResult(
            counts=self.counts,
            output_paths=[path for path in self._output_paths if path.is_file()],
        )
