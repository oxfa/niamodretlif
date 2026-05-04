"""Aggregate output merge owner."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterable, cast

from domain_pipeline.worker.output.manager import csv_row_signature
from domain_pipeline.worker.output.rows import REVIEW_OUTPUT_COLUMNS, ReviewOutputRow
from domain_pipeline.worker.output.invariants import DuplicateOutputInvariantError


class AggregateOutputMerger:
    """Merge worker and prepare-owned output fragments into final outputs."""

    def merge_host_value_payloads(
        self,
        source_payloads: Iterable[tuple[str, Iterable[str]]],
        target_path: Path,
    ) -> None:
        """Merge embedded host TXT values and reject duplicate output values."""
        seen_hosts: dict[str, str] = {}
        ordered_hosts: list[str] = []
        for source_label, values in source_payloads:
            for value in values:
                host = value.strip()
                if not host:
                    continue
                previous_source = seen_hosts.get(host)
                if previous_source is not None:
                    raise DuplicateOutputInvariantError(
                        "aggregate_host",
                        host,
                        context={
                            "first_source": previous_source,
                            "duplicate_source": source_label,
                        },
                    )
                seen_hosts[host] = source_label
                ordered_hosts.append(host)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(
            "".join(f"{host}\n" for host in sorted(ordered_hosts)),
            encoding="utf-8",
        )

    def merge_audit_payloads(
        self,
        source_payloads: Iterable[tuple[str, Iterable[dict[str, Any]]]],
        target_path: Path,
    ) -> None:
        """Merge embedded audit rows and reject duplicate canonical rows."""
        seen_rows: dict[str, tuple[dict[str, Any], str]] = {}
        for source_label, rows in source_payloads:
            for row in rows:
                signature = self._canonical_row_signature(row)
                existing = seen_rows.get(signature)
                if existing is not None:
                    raise DuplicateOutputInvariantError(
                        "aggregate_audit_row",
                        str(row.get("host", "")),
                        context={
                            "signature": signature,
                            "first_source": existing[1],
                            "duplicate_source": source_label,
                        },
                    )
                seen_rows[signature] = (row, source_label)
        ordered_rows = sorted(
            [item[0] for item in seen_rows.values()],
            key=lambda current: (
                str(current.get("host", "")),
                self._canonical_row_signature(current),
            ),
        )
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with target_path.open("w", encoding="utf-8") as handle:
            for row in ordered_rows:
                json.dump(row, handle, sort_keys=True)
                handle.write("\n")

    def merge_review_payloads(
        self,
        source_payloads: Iterable[tuple[str, Iterable[dict[str, Any]]]],
        target_path: Path,
    ) -> None:
        """Merge embedded projected review rows in deterministic order."""
        review_rows: list[ReviewOutputRow] = []
        seen_review_rows: dict[str, str] = {}
        for source_label, rows in source_payloads:
            for row in rows:
                normalized_row = self._normalize_projected_review_row(row)
                signature = csv_row_signature(normalized_row)
                existing = seen_review_rows.get(signature)
                if existing is not None:
                    raise DuplicateOutputInvariantError(
                        "aggregate_review_row",
                        str(row.get("host", "")),
                        context={
                            "signature": signature,
                            "first_source": existing,
                            "duplicate_source": source_label,
                        },
                    )
                seen_review_rows[signature] = source_label
                review_rows.append(normalized_row)
        if target_path.exists():
            target_path.unlink()
        if review_rows:
            self._write_projected_review_rows(target_path, review_rows)

    def _canonical_row_signature(self, row: dict[str, Any]) -> str:
        return json.dumps(row, sort_keys=True, separators=(",", ":"))

    def _normalize_projected_review_row(self, row: dict[str, Any]) -> ReviewOutputRow:
        """Normalize one aggregate review CSV row without reprojecting values."""
        return cast(
            ReviewOutputRow,
            {column: str(row.get(column, "")) for column in REVIEW_OUTPUT_COLUMNS},
        )

    def _write_projected_review_rows(
        self, review_path: Path, review_rows: list[ReviewOutputRow]
    ) -> None:
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
                    current.get("input_name") or current.get("host", ""),
                    current.get("host", ""),
                ),
            ):
                writer.writerow(cast(Any, row))
