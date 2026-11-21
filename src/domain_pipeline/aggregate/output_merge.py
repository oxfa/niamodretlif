"""Aggregate output merge owner."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, cast

from domain_pipeline.worker.output.manager import (
    csv_row_signature,
    write_projected_review_rows,
)
from domain_pipeline.worker.output.rows import REVIEW_OUTPUT_COLUMNS, ReviewOutputRow
from domain_pipeline.worker.output.invariants import DuplicateOutputInvariantError
from domain_pipeline.prepare.prepare_to_aggregate_manifest import (
    ManuallyAddedDomain,
)
from domain_pipeline.prepare.source_line_index import SourceLineIndex
from domain_pipeline.prepare.sources.parser import (
    DomainListParser,
    InputFileFormat,
)


class AggregateOutputMerger:
    """Merge worker and prepare-owned output fragments into final outputs."""

    def collect_host_value_payloads(
        self,
        source_payloads: Iterable[tuple[str, Iterable[str]]],
    ) -> list[str]:
        """Merge host values and reject duplicates, returning sorted values."""
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
        return sorted(ordered_hosts)

    def write_filtered_source_content(
        self,
        source_contents: list[str],
        source_line_index: SourceLineIndex,
        unactionable_registrable_domains: Iterable[str],
        manually_added_domains: Iterable[ManuallyAddedDomain],
        target_path: Path,
        *,
        output_format: str,
    ) -> None:
        """Render retained sources and actionable manual additions in one format."""
        formatters = {
            "plain": lambda host: host,
            "hosts": lambda host: f"0.0.0.0 {host}",
            "adblock": lambda host: f"||{host}^",
        }
        try:
            format_host = formatters[output_format]
        except KeyError as exc:
            raise ValueError(
                f"unsupported filtered output format {output_format!r}"
            ) from exc

        if len(source_contents) != len(source_line_index.source_formats):
            raise ValueError(
                "source archive count does not match source line index formats"
            )

        unactionable = set(unactionable_registrable_domains)
        roots_by_source_line: dict[tuple[int, int], set[str]] = {}
        for root, references in source_line_index.registrable_domain_lines.items():
            for reference in references:
                roots_by_source_line.setdefault(
                    (reference.source_ordinal, reference.line_number), set()
                ).add(root)

        source_lines = [
            content.splitlines(keepends=True) for content in source_contents
        ]
        for source_ordinal, line_number in roots_by_source_line:
            if source_ordinal >= len(source_lines) or line_number > len(
                source_lines[source_ordinal]
            ):
                raise ValueError(
                    "source line index references a missing archived source line "
                    f"{source_ordinal}:{line_number}"
                )

        parser = DomainListParser()
        rendered_lines: list[str] = []
        for source_ordinal, (lines, source_format) in enumerate(
            zip(source_lines, source_line_index.source_formats, strict=True)
        ):
            try:
                input_format = InputFileFormat(source_format)
            except ValueError as exc:
                raise ValueError(
                    f"source line index has unsupported format {source_format!r}"
                ) from exc
            for line_number, line in enumerate(lines, start=1):
                entries = parser.parse_source_line_entries(
                    line, file_format=input_format
                )
                indexed_roots = roots_by_source_line.get(
                    (source_ordinal, line_number), set()
                )
                parsed_roots = {
                    entry.registrable_domain
                    for entry in entries
                    if entry.registrable_domain is not None
                }
                if indexed_roots != parsed_roots:
                    raise ValueError(
                        "source line index does not match archived source line "
                        f"{source_ordinal}:{line_number}"
                    )

                excluded_roots = indexed_roots & unactionable
                retained_entries = [
                    entry
                    for entry in entries
                    if entry.registrable_domain not in excluded_roots
                ]
                if output_format == "adblock" and input_format is InputFileFormat.ADBLOCK:
                    if entries and not retained_entries:
                        continue
                    rendered_lines.append(
                        line if line.endswith(("\n", "\r")) else f"{line}\n"
                    )
                    continue
                rendered_lines.extend(
                    f"{format_host(entry.host)}\n"
                    for entry in retained_entries
                )

        for manual_domain in sorted(manually_added_domains, key=lambda item: item.host):
            if (
                manual_domain.registrable_domain is not None
                and manual_domain.registrable_domain in unactionable
            ):
                continue
            rendered_lines.append(f"{format_host(manual_domain.host)}\n")

        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text("".join(rendered_lines), encoding="utf-8")

    def merge_host_value_payloads(
        self,
        source_payloads: Iterable[tuple[str, Iterable[str]]],
        target_path: Path,
    ) -> None:
        """Merge embedded host TXT values and reject duplicate output values."""
        ordered_hosts = self.collect_host_value_payloads(source_payloads)
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
        write_projected_review_rows(review_path, review_rows)
