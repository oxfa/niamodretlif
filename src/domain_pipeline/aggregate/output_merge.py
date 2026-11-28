"""Aggregate output merge owner."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Callable, Iterable, cast

from pydantic import BaseModel

from domain_pipeline.worker.output.manager import (
    review_row_signature,
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
        input_domain_routes: Mapping[tuple[str, str], str],
        manually_added_domains: Iterable[ManuallyAddedDomain],
        filtered_output: tuple[Path, str],
    ) -> None:
        """Render prepare-owned valid items according to the configured output format."""
        source_items.validate()
        if not isinstance(input_domain_routes, Mapping):
            raise TypeError("input-domain routes must be keyed by root and input domain")
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

        index = source_items.index_payload
        eligible_associations: set[str] = set()
        association_lookup = self._association_lookup(source_items)
        for domain, references in index[
            "valid_source_items_by_registrable_domain"
        ].items():
            for reference in references:
                association = self._association_for_reference(
                    association_lookup, reference
                )
                route = input_domain_routes.get((domain, association["host"]))
                if route == "filtered":
                    eligible_associations.add(reference["association_id"])
        eligible_associations.update(
            reference["association_id"]
            for reference in index[
                "valid_source_items_without_extractable_registrable_domain"
            ]
            if reference["association_id"] is not None
            and reference["reason"] == "public_suffix_only"
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
                or input_domain_routes.get((item.registrable_domain, item.host))
                == "filtered"
            ):
                append_rendered(format_host(item.host))

        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text("".join(rendered_lines), encoding="utf-8")

    def expected_input_domains(
        self,
        source_items: SourceItemHandoff,
        manually_added_domains: Iterable[ManuallyAddedDomain],
    ) -> dict[str, set[str]]:
        """Derive root and input-domain coverage from prepare-owned valid data."""
        source_items.validate()
        expected: dict[str, set[str]] = {}
        association_lookup = self._association_lookup(source_items)
        for registrable_domain, references in source_items.index_payload[
            "valid_source_items_by_registrable_domain"
        ].items():
            inputs = expected.setdefault(registrable_domain, set())
            for reference in references:
                association = self._association_for_reference(
                    association_lookup, reference
                )
                if association["registrable_domain"] != registrable_domain:
                    raise ValueError(
                        "source-item association registrable domain does not match its index"
                    )
                inputs.add(association["host"])
        for item in manually_added_domains:
            if item.registrable_domain is not None:
                expected.setdefault(item.registrable_domain, set()).add(item.host)
        return expected

    def validate_worker_results(
        self,
        source_items: SourceItemHandoff,
        manually_added_domains: Iterable[ManuallyAddedDomain],
        worker_manifests: Sequence[Any],
    ) -> dict[tuple[str, str], str]:
        """Require exact global root and input-domain result coverage."""
        expected_by_root = self.expected_input_domains(
            source_items, manually_added_domains
        )
        expected_roots = set(expected_by_root)
        expected_inputs = {
            (registrable_domain, input_domain)
            for registrable_domain, input_domains in expected_by_root.items()
            for input_domain in input_domains
        }
        root_results: dict[str, str] = {}
        input_routes: dict[tuple[str, str], str] = {}
        for manifest in worker_manifests:
            if not manifest.handoff_finalized:
                raise ValueError(
                    f"worker aggregate handoff is not finalized: {manifest.worker_id}"
                )
            for result in manifest.registrable_domain_results:
                row = self._result_row(result)
                self._validate_result_fields(
                    row,
                    {
                        "registrable_domain",
                        "disposition",
                        "delegation_result",
                    },
                    "registrable-domain",
                )
                registrable_domain = row["registrable_domain"]
                disposition = row["disposition"]
                if registrable_domain not in expected_roots:
                    raise ValueError(
                        "worker returned an unexpected registrable-domain result: "
                        f"{registrable_domain}"
                    )
                if registrable_domain in root_results:
                    raise ValueError(
                        "duplicate registrable-domain result across workers: "
                        f"{registrable_domain}"
                    )
                if disposition not in {"actionable", "review", "unactionable"}:
                    raise ValueError(
                        f"invalid registrable-domain disposition: {disposition!r}"
                    )
                root_results[registrable_domain] = disposition
            for result in manifest.input_domain_results:
                row = self._result_row(result)
                self._validate_result_fields(
                    row,
                    {
                        "input_domain",
                        "registrable_domain",
                        "route",
                        "route_code",
                        "route_reason",
                        "host_resolution_results",
                        "ip_location_results",
                        "ip_location_policy",
                    },
                    "input-domain",
                )
                key = (row["registrable_domain"], row["input_domain"])
                if key not in expected_inputs:
                    raise ValueError(
                        "worker returned an unexpected input-domain result: "
                        f"{key[1]} under {key[0]}"
                    )
                if key in input_routes:
                    raise ValueError(
                        "duplicate input-domain result across workers: "
                        f"{key[1]} under {key[0]}"
                    )
                route = row["route"]
                if route not in {"filtered", "review", "unactionable"}:
                    raise ValueError(f"invalid input-domain route: {route!r}")
                input_routes[key] = route

        missing_roots = sorted(expected_roots - set(root_results))
        if missing_roots:
            raise ValueError(
                f"worker results are missing registrable-domain outcomes: {missing_roots}"
            )
        missing_inputs = sorted(expected_inputs - set(input_routes))
        if missing_inputs:
            raise ValueError(
                "worker results are missing input-domain outcomes: "
                f"{missing_inputs}"
            )
        for registrable_domain, disposition in root_results.items():
            if disposition not in {"review", "unactionable"}:
                continue
            for input_domain in expected_by_root[registrable_domain]:
                route = input_routes[(registrable_domain, input_domain)]
                if route != disposition:
                    raise ValueError(
                        "input-domain route does not match its terminal root outcome: "
                        f"{input_domain} under {registrable_domain}"
                    )
        return input_routes

    def unactionable_input_domains(
        self, input_domain_routes: Mapping[tuple[str, str], str]
    ) -> list[str]:
        """Return the unique input-domain values routed unactionable."""
        return sorted(
            {
                input_domain
                for (_registrable_domain, input_domain), route in input_domain_routes.items()
                if route == "unactionable"
            }
        )

    def _association_lookup(
        self, source_items: SourceItemHandoff
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Index associations by their item and association IDs."""
        return {
            (item["item_id"], association["association_id"]): association
            for item in source_items.item_records
            for association in item["target_associations"]
        }

    def _association_for_reference(
        self,
        association_lookup: Mapping[tuple[str, str], dict[str, Any]],
        reference: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Resolve one indexed association while preserving its source-item owner."""
        association = association_lookup.get(
            (reference["item_id"], reference["association_id"])
        )
        if association is not None:
            return association
        raise ValueError(
            "source-item index references an unknown target association: "
            f"{reference['association_id']}"
        )

    def _validate_result_fields(
        self, row: Mapping[str, Any], expected_fields: set[str], row_kind: str
    ) -> None:
        """Reject unknown or missing fields at the aggregate result boundary."""
        if set(row) != expected_fields:
            raise ValueError(
                f"invalid {row_kind} result fields: "
                f"missing={sorted(expected_fields - set(row))} "
                f"unknown={sorted(set(row) - expected_fields)}"
            )

    def _result_row(self, result: Any) -> dict[str, Any]:
        """Expose one already-schema-validated result row as JSON-compatible data."""
        if isinstance(result, Mapping):
            return dict(result)
        model_dump = getattr(result, "model_dump", None)
        if callable(model_dump):
            row = model_dump(mode="json")
            if isinstance(row, dict):
                return row
        raise ValueError("worker result row is not a validated mapping")

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
        source_payloads: Iterable[
            tuple[str, Iterable[Mapping[str, Any] | BaseModel]]
        ],
        target_path: Path,
    ) -> None:
        """Merge embedded audit rows and reject duplicate canonical rows."""
        seen_rows: dict[str, tuple[dict[str, Any], str]] = {}
        for source_label, rows in source_payloads:
            for source_row in rows:
                row = self._result_row(source_row)
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
                signature = review_row_signature(normalized_row)
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
