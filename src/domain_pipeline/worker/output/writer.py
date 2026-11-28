"""Collect and write source-blind root and input-domain worker results."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from domain_pipeline.worker.output.invariants import DuplicateOutputInvariantError
from domain_pipeline.worker.output.manager import (
    input_domain_output_value,
    output_paths,
    review_row_signature,
    write_review_rows,
)
from domain_pipeline.worker.output.rows import ReviewRowProjector

if TYPE_CHECKING:
    from domain_pipeline.worker.runtime.contracts import (
        CompletedInputDomainResult,
        RegistrableDomainResult,
    )


def _json_value(value: Any) -> Any:
    """Return JSON-compatible values from nested runtime evidence dataclasses."""
    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


@dataclass
class WriterResult:
    """Collected worker counts and concrete output paths."""

    counts: Counter
    output_paths: list[Path]


class ResultOutputWriter:
    """Collect one root result and one route per input domain, then write once."""

    def __init__(
        self,
        *,
        output_spec: dict[str, Any],
        expected_input_domains_by_root: dict[str, set[str]],
    ) -> None:
        self.paths = output_paths(output_spec)
        self.expected_input_domains_by_root = {
            root: set(domains)
            for root, domains in expected_input_domains_by_root.items()
        }
        self.root_results: dict[str, RegistrableDomainResult] = {}
        self.input_domain_results: dict[tuple[str, str], CompletedInputDomainResult] = {}
        self.counts: Counter = Counter()
        self._review_rows: dict[str, dict[str, Any]] = {}
        self._review_signatures: set[str] = set()

    def add_root_result(self, result: RegistrableDomainResult) -> None:
        """Record one registrable-domain DNS disposition."""
        if result.registrable_domain in self.root_results:
            raise DuplicateOutputInvariantError(
                "registrable_domain_result", result.registrable_domain
            )
        if result.disposition not in {"actionable", "review", "unactionable"}:
            raise ValueError(
                f"unsupported root disposition {result.disposition!r}"
            )
        self.root_results[result.registrable_domain] = result
        self.counts[f"registrable_domain_disposition_{result.disposition}"] += 1

    def add(self, result: CompletedInputDomainResult) -> None:
        """Record one final route for an assigned input domain."""
        input_domain = input_domain_output_value(result.entry.host)
        registrable_domain = result.entry.registrable_domain
        if not registrable_domain:
            raise ValueError(
                f"worker input-domain result requires a registrable root: {input_domain!r}"
            )
        key = (registrable_domain, input_domain)
        if key in self.input_domain_results:
            raise DuplicateOutputInvariantError("input_domain_result", input_domain)
        self.input_domain_results[key] = result
        self.counts[f"route_code_{result.route_code.value}"] += 1
        self.counts[f"route_{result.route}"] += 1
        if result.route == "review":
            signature = review_row_signature(ReviewRowProjector().project(result.row))
            if signature in self._review_signatures:
                raise DuplicateOutputInvariantError("review_row", input_domain)
            self._review_signatures.add(signature)
            self._review_rows[input_domain] = result.row

    def _validate_exact_coverage(self) -> None:
        expected_roots = set(self.expected_input_domains_by_root)
        actual_roots = set(self.root_results)
        if actual_roots != expected_roots:
            missing = sorted(expected_roots - actual_roots)
            unexpected = sorted(actual_roots - expected_roots)
            raise ValueError(
                "worker root-result coverage mismatch: "
                f"missing={missing} unexpected={unexpected}"
            )

        expected_pairs = {
            (root, input_domain)
            for root, input_domains in self.expected_input_domains_by_root.items()
            for input_domain in input_domains
        }
        actual_pairs = set(self.input_domain_results)
        if actual_pairs != expected_pairs:
            missing = sorted(expected_pairs - actual_pairs)
            unexpected = sorted(actual_pairs - expected_pairs)
            raise ValueError(
                "worker input-domain result coverage mismatch: "
                f"missing={missing} unexpected={unexpected}"
            )

        for root, result in self.root_results.items():
            if result.delegation_result.domain != root:
                raise ValueError(
                    f"worker delegation evidence root mismatch for {root!r}"
                )
            if result.disposition in {"review", "unactionable"}:
                for input_domain in self.expected_input_domains_by_root[root]:
                    route = self.input_domain_results[(root, input_domain)].route
                    if route != result.disposition:
                        raise ValueError(
                            "worker input-domain route does not follow terminal root "
                            f"outcome for {input_domain!r}"
                        )

    def _result_envelope(self) -> dict[str, Any]:
        """Return the canonical two-collection worker result payload."""
        root_rows = [
            {
                "registrable_domain": result.registrable_domain,
                "disposition": result.disposition,
                "delegation_result": _json_value(result.delegation_result),
            }
            for result in sorted(
                self.root_results.values(), key=lambda row: row.registrable_domain
            )
        ]
        input_rows = []
        for result in sorted(
            self.input_domain_results.values(),
            key=lambda row: (row.entry.registrable_domain or "", row.entry.host),
        ):
            evidence = result.evidence
            input_rows.append(
                {
                    "input_domain": result.entry.host,
                    "registrable_domain": result.entry.registrable_domain,
                    "route": result.route,
                    "route_code": result.route_code.value,
                    "route_reason": result.route_reason,
                    "host_resolution_results": [
                        _json_value(host_result)
                        for host_result in evidence.host_resolution_results
                    ],
                    "ip_location_results": [
                        _json_value(location_result)
                        for location_result in evidence.ip_location_results
                    ],
                    "ip_location_policy": (
                        _json_value(evidence.ip_location_policy)
                        if evidence.ip_location_policy is not None
                        else None
                    ),
                }
            )
        return {
            "registrable_domain_results": root_rows,
            "input_domain_results": input_rows,
        }

    def write(self) -> WriterResult:
        """Validate exact local coverage and replace the three worker outputs."""
        self._validate_exact_coverage()
        envelope = self._result_envelope()
        results_path = self.paths["results"]
        results_path.parent.mkdir(parents=True, exist_ok=True)
        with results_path.open("w", encoding="utf-8", newline="") as handle:
            json.dump(envelope, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")

        unactionable_domains = sorted(
            result.entry.host
            for result in self.input_domain_results.values()
            if result.route == "unactionable"
        )
        unactionable_path = self.paths["unactionable"]
        unactionable_path.parent.mkdir(parents=True, exist_ok=True)
        unactionable_path.write_text(
            "".join(f"{domain}\n" for domain in unactionable_domains),
            encoding="utf-8",
        )

        review_rows = [
            self._review_rows[input_domain]
            for input_domain in sorted(self._review_rows)
        ]
        write_review_rows(self.paths["review"], review_rows)
        self.counts["emitted_unactionable_input_domains"] = len(
            unactionable_domains
        )
        return WriterResult(
            counts=self.counts,
            output_paths=[self.paths[key] for key in ("unactionable", "review", "results")],
        )
