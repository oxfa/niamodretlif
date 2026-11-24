"""Aggregate output merge owner."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Iterable, cast

from domain_pipeline.worker.output.manager import (
    csv_row_signature,
    write_projected_review_rows,
)
from domain_pipeline.worker.output.rows import REVIEW_OUTPUT_COLUMNS, ReviewOutputRow
from domain_pipeline.worker.output.invariants import DuplicateOutputInvariantError
from domain_pipeline.prepare.prepare_to_aggregate_manifest import (
    ManuallyAddedDomain,
)
from domain_pipeline.prepare.source_items import SourceItemHandoff
from domain_pipeline.prepare.sources.parser import InputFileFormat


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

    def write_filtered_source_items(
        self,
        source_items: SourceItemHandoff,
        unactionable_registrable_domains: Iterable[str],
        manually_added_domains: Iterable[ManuallyAddedDomain],
        filtered_output: tuple[Path, str],
    ) -> None:
        """Render prepare-owned valid items according to the configured output format."""
        source_items.validate()
        target_path, output_format = filtered_output
        formatters: dict[str, Callable[[str], str]] = {
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

        unactionable = set(unactionable_registrable_domains)
        index = source_items.index_payload
        eligible_associations: set[str] = set()
        for domain, references in index[
            "valid_source_items_by_registrable_domain"
        ].items():
            if domain in unactionable:
                continue
            eligible_associations.update(
                reference["association_id"] for reference in references
            )
        eligible_associations.update(
            reference["association_id"]
            for reference in index[
                "valid_source_items_without_extractable_registrable_domain"
            ]
            if reference["association_id"] is not None
        )
        valid_no_target_items = {
            reference["item_id"]
            for reference in index[
                "valid_source_items_without_extractable_registrable_domain"
            ]
            if reference["association_id"] is None
        }
        metadata_items = {
            reference["item_id"] for reference in index["adblock_metadata"]
        }

        rendered_lines: list[str] = []
        seen_lines: set[str] = set()

        def append_rendered(line: str) -> None:
            normalized_line = line if line.endswith(("\n", "\r")) else f"{line}\n"
            if normalized_line not in seen_lines:
                seen_lines.add(normalized_line)
                rendered_lines.append(normalized_line)

        for item in source_items.item_records:
            item_id = item["item_id"]
            is_adblock_item = item["input_format"] == InputFileFormat.ADBLOCK.value
            if item_id in metadata_items:
                if output_format == "adblock":
                    append_rendered(item["original_text"])
                continue

            associations = [
                association
                for association in item["target_associations"]
                if association["association_id"] in eligible_associations
            ]
            if not item["target_associations"]:
                if (
                    output_format == "adblock"
                    and is_adblock_item
                    and item_id in valid_no_target_items
                ):
                    append_rendered(item["original_text"])
                continue
            if not associations:
                continue

            if is_adblock_item:
                if output_format == "adblock":
                    if len(associations) == len(item["target_associations"]):
                        append_rendered(item["original_text"])
                    continue
                if item["item_kind"].startswith("exception_"):
                    continue
            for association in associations:
                append_rendered(format_host(association["host"]))

        for item in sorted(manually_added_domains, key=lambda item: item.host):
            if (
                item.registrable_domain is None
                or item.registrable_domain not in unactionable
            ):
                append_rendered(format_host(item.host))

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
