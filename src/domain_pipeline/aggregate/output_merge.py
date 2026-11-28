"""Aggregate output merge owner."""

from __future__ import annotations

import dataclasses
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


_HOST_FORMATTERS: dict[str, Callable[[str], str]] = {
    "plain": lambda host: host,
    "hosts": lambda host: f"0.0.0.0 {host}",
    "adblock": lambda host: f"||{host}^",
}


@dataclasses.dataclass(frozen=True)
class EligibleSourceItem:
    record: Mapping[str, Any]
    hosts: tuple[str, ...]
    simple_positive_adblock_rule: bool


def render_source_item(item: EligibleSourceItem, output_format: str) -> tuple[str, ...]:
    """Render a verified source occurrence according to the destination syntax."""
    record = item.record
    if record["input_format"] == InputFileFormat.ADBLOCK.value:
        if output_format == "adblock":
            if len(item.hosts) == len(record["target_associations"]):
                return (record["original_text"],)
            return ()
        if not item.simple_positive_adblock_rule:
            return ()
    format_host = _HOST_FORMATTERS[output_format]
    return tuple(format_host(host) for host in item.hosts)


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

    def eligible_source_items(
        self, source_items: SourceItemHandoff, input_domain_routes: Mapping[str, str]
    ) -> list[EligibleSourceItem]:
        """Resolve eligibility from verified references, preserving corpus order."""
        index = source_items.index_payload
        eligible_associations = {
            reference["association_id"]
            for host, references in index["valid_source_items_by_input_domain"].items()
            if input_domain_routes.get(host) == "filtered"
            for reference in references
        }
        eligible_without_targets = {
            reference["item_id"] for reference in index["adblock_metadata"]
        }
        for reference in index[
            "valid_source_items_without_extractable_registrable_domain"
        ]:
            association_id = reference["association_id"]
            if association_id is None:
                eligible_without_targets.add(reference["item_id"])
            else:
                eligible_associations.add(association_id)
        return [
            EligibleSourceItem(
                record=record,
                hosts=tuple(
                    association["host"]
                    for association in record["target_associations"]
                    if association["association_id"] in eligible_associations
                ),
                simple_positive_adblock_rule=source_items.parsed_items_by_id[
                    record["item_id"]
                ].is_simple_positive_adblock_rule,
            )
            for record in source_items.item_records
            if record["target_associations"]
            or record["item_id"] in eligible_without_targets
        ]

    def eligible_manual_hosts(
        self,
        manually_added_domains: Iterable[ManuallyAddedDomain],
        input_domain_routes: Mapping[str, str],
    ) -> list[str]:
        return sorted(
            item.host
            for item in manually_added_domains
            if item.registrable_domain is None
            or input_domain_routes.get(item.host) == "filtered"
        )

    def write_filtered_source_items(
        self,
        items: Iterable[EligibleSourceItem],
        manual_hosts: Iterable[str],
        filtered_output: tuple[Path, str],
    ) -> None:
        """Write the first occurrence of each rendered UTF-8 line."""
        target_path, output_format = filtered_output
        try:
            format_host = _HOST_FORMATTERS[output_format]
        except KeyError as exc:
            raise ValueError(
                f"unsupported filtered output format {output_format!r}"
            ) from exc
        lines = dict.fromkeys(
            line for item in items for line in render_source_item(item, output_format)
        )
        for host in manual_hosts:
            lines.setdefault(format_host(host), None)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")

    def expected_input_domains(
        self,
        source_items: SourceItemHandoff,
        manually_added_domains: Iterable[ManuallyAddedDomain],
    ) -> dict[str, set[str]]:
        """Derive coverage from verified source associations and standalone hosts."""
        domain_index = source_items.index_payload["valid_source_items_by_input_domain"]
        association_lookup = {
            association["association_id"]: association
            for record in source_items.item_records
            for association in record["target_associations"]
        }
        expected: dict[str, set[str]] = {}
        for host, references in domain_index.items():
            root = association_lookup[references[0]["association_id"]][
                "registrable_domain"
            ]
            expected.setdefault(root, set()).add(host)

        for item in manually_added_domains:
            if item.registrable_domain is not None:
                expected.setdefault(item.registrable_domain, set()).add(item.host)
        return expected

    def validate_worker_results(
        self,
        source_items: SourceItemHandoff,
        manually_added_domains: Iterable[ManuallyAddedDomain],
        worker_manifests: Sequence[Any],
    ) -> dict[str, str]:
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
        return {host: route for (_, host), route in input_routes.items()}

    def unactionable_input_domains(self, input_domain_routes: Mapping[str, str]) -> list[str]:
        """Return the input domains routed unactionable in sorted order."""
        return sorted(host for host, route in input_domain_routes.items() if route == "unactionable")

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
        source_payloads: Iterable[tuple[str, Iterable[Mapping[str, Any]]]],
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

    def _normalize_projected_review_row(
        self, row: Mapping[str, Any]
    ) -> ReviewOutputRow:
        """Normalize one aggregate review CSV row without reprojecting values."""
        return cast(
            ReviewOutputRow,
            {column: str(row.get(column, "")) for column in REVIEW_OUTPUT_COLUMNS},
        )

    def _write_projected_review_rows(
        self, review_path: Path, review_rows: list[ReviewOutputRow]
    ) -> None:
        write_projected_review_rows(review_path, review_rows)
