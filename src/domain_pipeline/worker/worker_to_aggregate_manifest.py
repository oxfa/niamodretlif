"""Worker-owned direct data handoffs consumed by aggregate jobs."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    StrictBool,
    StrictStr,
    ValidationError,
    model_validator,
)

from domain_pipeline.handoff_io import (
    read_csv,
    read_yaml,
    write_csv,
    write_yaml,
)
from domain_pipeline.paths.layout import PathLayout
from domain_pipeline.prepare.prepare_to_worker_manifest import (
    PrepareWorkerManifest,
    load_prepare_worker_manifest_for_worker,
)
from domain_pipeline.prepare.sources.parser import DomainListParser, InputFileFormat
from domain_pipeline.routing.policies import DelegationRoutingPolicy, ROUTE_REASON_TEXT
from domain_pipeline.routing.route_codes import RouteCode, TerminalRouteTransition
from domain_pipeline.worker.delegation.lookup import (
    DelegationDnsEvidence,
    DelegationResult,
    DelegationSoaEvidence,
)
from domain_pipeline.worker.output.rows import REVIEW_OUTPUT_COLUMNS

CacheSnapshotMode = Literal["sqlite_backup", "raw_file", "missing"]


class WorkerAggregateModel(BaseModel):
    """Base worker-to-aggregate data model that rejects unknown fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class DelegationDnsEvidenceRow(WorkerAggregateModel):
    """Closed DNS evidence carried by one registrable-domain result."""

    ns_records_exist: StrictBool
    ns_nodata: StrictBool
    ns_nxdomain: StrictBool
    ns_retry_exhausted: StrictBool
    ns_lookup_error: StrictBool


class DelegationSoaEvidenceRow(WorkerAggregateModel):
    """Closed SOA fallback evidence carried by one registrable-domain result."""

    soa_exists: StrictBool
    soa_absent: StrictBool
    soa_retry_exhausted: StrictBool
    soa_source: StrictStr


class DelegationResultRow(WorkerAggregateModel):
    """Existing typed delegation evidence serialized without source identity."""

    domain: StrictStr
    dns: DelegationDnsEvidenceRow
    soa: DelegationSoaEvidenceRow
    no_nameservers: StrictBool
    nameservers: list[StrictStr]
    from_cache: StrictBool


class RegistrableDomainResultRow(WorkerAggregateModel):
    """One root-level delegation disposition and its typed evidence."""

    registrable_domain: StrictStr
    disposition: Literal["actionable", "review", "unactionable"]
    delegation_result: DelegationResultRow

    @model_validator(mode="after")
    def _validate_disposition(self) -> "RegistrableDomainResultRow":
        if self.delegation_result.domain != self.registrable_domain:
            raise ValueError("delegation result domain must equal its registrable root")
        evidence = self.delegation_result
        result = DelegationResult(
            domain=evidence.domain,
            dns=DelegationDnsEvidence(**evidence.dns.model_dump()),
            soa=DelegationSoaEvidence(**evidence.soa.model_dump()),
            no_nameservers=evidence.no_nameservers,
            nameservers=list(evidence.nameservers),
            from_cache=evidence.from_cache,
        )
        transition = DelegationRoutingPolicy().for_result(result)
        expected = (
            "actionable"
            if not isinstance(transition, TerminalRouteTransition)
            else transition.route
        )
        if self.disposition != expected:
            raise ValueError("root disposition does not match delegation evidence")
        return self


class HostResolutionDnsEvidenceRow(WorkerAggregateModel):
    """Closed DNS flags for one exact host-resolution query."""

    a_exists: StrictBool
    a_nodata: StrictBool
    a_nxdomain: StrictBool
    a_timeout: StrictBool
    a_servfail: StrictBool


class HostResolutionAddressEvidenceRow(WorkerAggregateModel):
    """Closed address data for one exact host-resolution query."""

    canonical_name: StrictStr | None
    ipv4_addresses: list[StrictStr]
    ipv6_addresses: list[StrictStr]


class HostResolutionResultRow(WorkerAggregateModel):
    """One selected DNS-name result, attributed to the input-domain row."""

    host: StrictStr
    dns: HostResolutionDnsEvidenceRow
    addresses: HostResolutionAddressEvidenceRow
    from_cache: StrictBool
    detail: StrictStr


class IPLocationResultRow(WorkerAggregateModel):
    """Closed IP-location evidence for one resolved address."""

    ip: StrictStr
    provider: StrictStr
    country_code: StrictStr
    region_code: StrictStr
    region_name: StrictStr
    status: StrictStr
    failure_reason: StrictStr


class IPLocationPolicyRow(WorkerAggregateModel):
    """Closed per-domain IP-location policy evidence."""

    status: StrictStr
    reason: StrictStr
    matched_ips: list[StrictStr]
    rejected_ips: list[StrictStr]


class InputDomainResultRow(WorkerAggregateModel):
    """One final source-blind route for an assigned input domain."""

    input_domain: StrictStr
    registrable_domain: StrictStr
    route: Literal["filtered", "review", "unactionable"]
    route_code: RouteCode
    route_reason: StrictStr
    host_resolution_results: list[HostResolutionResultRow]
    ip_location_results: list[IPLocationResultRow]
    ip_location_policy: IPLocationPolicyRow | None

    @model_validator(mode="after")
    def _validate_route(self) -> "InputDomainResultRow":
        route_by_code = {
            RouteCode.MANUALLY_SELECTED_FOR_FILTERED_TO_FILTERED: "filtered",
            RouteCode.MANUALLY_SELECTED_FOR_FILTERED_TO_FILTERED_PUBLIC_SUFFIX: "filtered",
            RouteCode.MANUALLY_ADDED_TO_FILTERED_ACTIONABLE: "filtered",
            RouteCode.HOST_RESOLUTION_TO_FILTERED_SKIPPED: "filtered",
            RouteCode.HOST_RESOLUTION_TO_FILTERED_RESOLVES: "filtered",
            RouteCode.IP_LOCATION_TO_FILTERED_POLICY_ACCEPTED: "filtered",
            RouteCode.DELEGATION_TO_UNACTIONABLE_NS_NXDOMAIN_SOA_ABSENT: "unactionable",
            RouteCode.DELEGATION_TO_UNACTIONABLE_NS_EMPTY_ANSWER: "unactionable",
            RouteCode.MANUALLY_SELECTED_FOR_FILTERED_TO_REVIEW_NOT_IN_SOURCES: "review",
            RouteCode.DELEGATION_TO_REVIEW_NS_NXDOMAIN_SOA_RETRY_EXHAUSTED: "review",
            RouteCode.DELEGATION_TO_REVIEW_NS_RETRY_EXHAUSTED_SOA_ABSENT: "review",
            RouteCode.DELEGATION_TO_REVIEW_NS_RETRY_EXHAUSTED_SOA_RETRY_EXHAUSTED: "review",
            RouteCode.DELEGATION_TO_REVIEW_NS_LOOKUP_ERROR: "review",
            RouteCode.HOST_RESOLUTION_TO_REVIEW_RESOLVED_WITHOUT_IP_ADDRESSES: "review",
            RouteCode.HOST_RESOLUTION_TO_REVIEW_TIMEOUT: "review",
            RouteCode.HOST_RESOLUTION_TO_REVIEW_SERVFAIL: "review",
            RouteCode.HOST_RESOLUTION_TO_REVIEW_NXDOMAIN: "review",
            RouteCode.HOST_RESOLUTION_TO_REVIEW_NODATA: "review",
            RouteCode.IP_LOCATION_TO_REVIEW_LOOKUP_FAILED: "review",
            RouteCode.IP_LOCATION_TO_REVIEW_POLICY_REJECTED: "review",
            RouteCode.IP_LOCATION_TO_REVIEW_REGION_NAME_UNAVAILABLE: "review",
        }
        expected_route = route_by_code.get(self.route_code)
        if expected_route is None or self.route != expected_route:
            raise ValueError("input-domain route does not match its terminal route code")
        if self.route_reason != ROUTE_REASON_TEXT[self.route_code]:
            raise ValueError("input-domain route reason does not match its route code")
        return self


class WorkerDomainResultsEnvelope(WorkerAggregateModel):
    """Two closed result collections in the existing worker result handoff."""

    registrable_domain_results: list[RegistrableDomainResultRow]
    input_domain_results: list[InputDomainResultRow]


class WorkerAggregateManifest(WorkerAggregateModel):
    """In-memory view of a worker-to-aggregate handoff."""

    batch_id: str
    worker_id: str
    handoff_finalized: bool
    registrable_domain_results: list[RegistrableDomainResultRow]
    input_domain_results: list[InputDomainResultRow]
    unactionable_input_domains: list[str]
    review_output_rows: list[dict[str, str]]
    log_text: str
    cache_path: Path | None
    cache_sha256: str | None

    @classmethod
    def empty(
        cls,
        batch_id: str,
        worker_id: str,
        *,
        finalized: bool = False,
    ) -> "WorkerAggregateManifest":
        """Build an empty handoff for a worker."""
        return cls(
            batch_id=batch_id,
            worker_id=worker_id,
            handoff_finalized=finalized,
            registrable_domain_results=[],
            input_domain_results=[],
            unactionable_input_domains=[],
            review_output_rows=[],
            log_text="",
            cache_path=None,
            cache_sha256=None,
        )

    @classmethod
    def initialized_from_prepare_worker_manifest(
        cls,
        manifest: PrepareWorkerManifest,
    ) -> "WorkerAggregateManifest":
        """Build an initialized worker-to-aggregate handoff stub."""
        return cls.empty(
            manifest.batch_id, manifest.worker_id
        )


def _manifest_path(*, batch_id: str, worker_id: str, state_root: Path) -> Path:
    return state_root / PathLayout(
        Path(".")
    ).workflow_state.worker_aggregate_manifest_path(
        batch_id=batch_id,
        worker_id=worker_id,
    )


def _read_text_values(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _read_review_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    return read_csv(path, tuple(REVIEW_OUTPUT_COLUMNS))


def parse_worker_domain_results_jsonl_text(
    contents: str,
) -> WorkerDomainResultsEnvelope:
    """Parse one JSONL record and reject unknown fields at every result depth."""
    records: list[Any] = []
    for line_number, line in enumerate(contents.splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(
                f"worker result record at line {line_number} must be a mapping"
            )
        records.append(value)
    if len(records) != 1:
        raise ValueError("worker result JSONL must contain exactly one collection record")
    return WorkerDomainResultsEnvelope.model_validate(records[0])


def _read_jsonl_result_envelope(path: Path) -> WorkerDomainResultsEnvelope:
    """Read the one closed result-collection record from the worker JSONL file."""
    if not path.is_file():
        raise ValueError(f"missing worker result collections {path}")
    return parse_worker_domain_results_jsonl_text(path.read_text(encoding="utf-8"))


def _expected_input_domains_by_root(
    prepare_manifest: PrepareWorkerManifest,
) -> dict[str, set[str]]:
    """Derive exact local input-domain coverage from the prepare assignment."""
    if prepare_manifest is None:
        raise ValueError("prepare worker manifest is missing")
    expected: dict[str, set[str]] = {}
    seen_domains: set[str] = set()
    for registrable_domain, root_work in (
        prepare_manifest.prepared_metadata.delegation_roots.items()
    ):
        input_domains = set(root_work.input_domains)
        if not input_domains:
            raise ValueError(
                f"assigned delegation root {registrable_domain!r} has no input domains"
            )
        repeated = sorted(input_domains & seen_domains)
        if repeated:
            raise ValueError(
                "prepare assignment contains input domains under multiple roots: "
                f"{repeated}"
            )
        seen_domains.update(input_domains)
        expected[registrable_domain] = input_domains
    return expected


def _psl_registrable_domain(input_domain: str) -> str | None:
    """Return the full-PSL registrable root for one normalized plain hostname."""
    parsed = DomainListParser().parse_source_item(
        input_domain, file_format=InputFileFormat.PLAIN
    )
    if parsed is None or parsed.error_reason is not None or len(parsed.targets) != 1:
        return None
    target = parsed.targets[0]
    if target.error_reason is not None:
        return None
    return target.registrable_domain


def validate_worker_domain_results(
    *,
    expected_input_domains_by_root: dict[str, set[str]],
    envelope: WorkerDomainResultsEnvelope,
) -> None:
    """Require exact root/domain coverage, membership, route fanout, and PSL roots."""
    expected_roots = set(expected_input_domains_by_root)
    root_rows = envelope.registrable_domain_results
    root_values = [row.registrable_domain for row in root_rows]
    if len(root_values) != len(set(root_values)):
        raise ValueError("worker registrable-domain results contain duplicates")
    if set(root_values) != expected_roots:
        missing = sorted(expected_roots - set(root_values))
        unexpected = sorted(set(root_values) - expected_roots)
        raise ValueError(
            "worker registrable-domain results do not match assigned roots: "
            f"missing={missing} unexpected={unexpected}"
        )
    for row in root_rows:
        if row.delegation_result.domain != row.registrable_domain:
            raise ValueError(
                "worker delegation evidence domain does not match its root result"
            )

    input_rows = envelope.input_domain_results
    input_values = [row.input_domain for row in input_rows]
    if len(input_values) != len(set(input_values)):
        raise ValueError("worker input-domain results contain duplicates")
    expected_pairs = {
        (root, domain)
        for root, domains in expected_input_domains_by_root.items()
        for domain in domains
    }
    returned_pairs = {
        (row.registrable_domain, row.input_domain) for row in input_rows
    }
    if returned_pairs != expected_pairs or len(returned_pairs) != len(input_rows):
        missing = sorted(expected_pairs - returned_pairs)
        unexpected = sorted(returned_pairs - expected_pairs)
        raise ValueError(
            "worker input-domain results do not match assigned domains: "
            f"missing={missing} unexpected={unexpected}"
        )

    root_dispositions = {row.registrable_domain: row.disposition for row in root_rows}
    for row in input_rows:
        psl_root = _psl_registrable_domain(row.input_domain)
        if psl_root != row.registrable_domain:
            raise ValueError(
                "worker input-domain registrable root does not match the full PSL: "
                f"{row.input_domain!r} -> {psl_root!r}, result={row.registrable_domain!r}"
            )
        root_disposition = root_dispositions[row.registrable_domain]
        if root_disposition in {"review", "unactionable"} and row.route != root_disposition:
            raise ValueError(
                "worker input-domain route does not follow its terminal root outcome: "
                f"{row.input_domain!r} route={row.route!r} "
                f"root={root_disposition!r}"
            )


def _validate_worker_domain_outputs(
    *,
    envelope: WorkerDomainResultsEnvelope,
    unactionable_domains: list[str],
    review_rows: list[dict[str, str]],
) -> None:
    """Require the published review and unactionable sidecars to match input routes."""
    expected_unactionable = {
        row.input_domain
        for row in envelope.input_domain_results
        if row.route == "unactionable"
    }
    if len(unactionable_domains) != len(set(unactionable_domains)):
        raise ValueError("worker unactionable input domains contain duplicates")
    if set(unactionable_domains) != expected_unactionable:
        raise ValueError("worker unactionable input-domain output does not match results")

    expected_review_rows = {
        row.input_domain: row
        for row in envelope.input_domain_results
        if row.route == "review"
    }
    review_hosts = [row.get("host", "").strip() for row in review_rows]
    if len(review_hosts) != len(set(review_hosts)):
        raise ValueError("worker review rows contain duplicate input domains")
    if set(review_hosts) != set(expected_review_rows):
        raise ValueError("worker review output does not match input-domain results")
    for review_row in review_rows:
        result = expected_review_rows[review_row["host"]]
        if (
            review_row["registrable_domain"] != result.registrable_domain
            or review_row["route_code"] != result.route_code
            or not review_row["review_reason"]
        ):
            raise ValueError(
                "worker review row does not match its input-domain result: "
                f"{review_row['host']!r}"
            )


def _read_optional_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def _snapshot_cache(cache_path: Path, destination: Path) -> CacheSnapshotMode:
    if destination.exists():
        destination.unlink()
    if not cache_path.is_file():
        return "missing"
    try:
        source = sqlite3.connect(f"file:{cache_path}?mode=ro", uri=True)
        try:
            target = sqlite3.connect(destination)
            try:
                source.backup(target)
            finally:
                target.close()
        finally:
            source.close()
        return "sqlite_backup"
    except (OSError, sqlite3.DatabaseError):
        destination.write_bytes(cache_path.read_bytes())
        return "raw_file"


def validate_worker_handoff_state(
    value: Any, *, batch_id: str, worker_id: str
) -> dict[str, Any]:
    """Validate the shared worker state fields, identity, and cache declaration."""
    expected = {
        "batch_id",
        "worker_id",
        "handoff_finalized",
        "cache_present",
        "cache_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("invalid handoff state fields")
    if (value["batch_id"], value["worker_id"]) != (batch_id, worker_id):
        raise ValueError("worker aggregate handoff identity mismatch")
    if not isinstance(value["handoff_finalized"], bool) or not isinstance(
        value["cache_present"], bool
    ):
        raise ValueError("invalid handoff flags")
    if value["cache_present"]:
        if not isinstance(value["cache_sha256"], str):
            raise ValueError("invalid cache checksum")
    elif value["cache_sha256"] is not None:
        raise ValueError("unexpected cache checksum")
    return value


def load_worker_aggregate_manifest(
    path: Path, *, state_root: Path, batch_id: str, worker_id: str
) -> WorkerAggregateManifest:
    """Load state and direct data files for one worker."""
    try:
        state = validate_worker_handoff_state(
            read_yaml(path), batch_id=batch_id, worker_id=worker_id
        )
        layout = PathLayout(state_root)
        state_paths = layout.workflow_state
        if path != state_paths.worker_aggregate_manifest_path(
            batch_id=batch_id, worker_id=worker_id
        ):
            raise ValueError("worker aggregate handoff path mismatch")
        cache = state_paths.worker_handoff_cache_path(
            batch_id=batch_id, worker_id=worker_id
        )
        if not state["cache_present"] and state["handoff_finalized"] and cache.exists():
            raise ValueError("unexpected cache")
        envelope = WorkerDomainResultsEnvelope(
            registrable_domain_results=[], input_domain_results=[]
        )
        unactionable_domains: list[str] = []
        review_rows: list[dict[str, str]] = []
        if state["handoff_finalized"]:
            for data_path in (
                state_paths.worker_handoff_unactionable_path(
                    batch_id=batch_id, worker_id=worker_id
                ),
                state_paths.worker_handoff_review_path(
                    batch_id=batch_id, worker_id=worker_id
                ),
                state_paths.worker_handoff_domain_results_path(
                    batch_id=batch_id, worker_id=worker_id
                ),
            ):
                if not data_path.is_file():
                    raise ValueError(f"missing {data_path}")
            envelope = _read_jsonl_result_envelope(
                state_paths.worker_handoff_domain_results_path(
                    batch_id=batch_id, worker_id=worker_id
                )
            )
            unactionable_domains = _read_text_values(
                state_paths.worker_handoff_unactionable_path(
                    batch_id=batch_id, worker_id=worker_id
                )
            )
            review_rows = _read_review_rows(
                state_paths.worker_handoff_review_path(
                    batch_id=batch_id, worker_id=worker_id
                )
            )
            _validate_worker_domain_outputs(
                envelope=envelope,
                unactionable_domains=unactionable_domains,
                review_rows=review_rows,
            )
        log_path = layout.output.worker_log_path(batch_id=batch_id, worker_id=worker_id)
        return WorkerAggregateManifest(
            batch_id=state["batch_id"],
            worker_id=state["worker_id"],
            handoff_finalized=state["handoff_finalized"],
            registrable_domain_results=envelope.registrable_domain_results,
            input_domain_results=envelope.input_domain_results,
            unactionable_input_domains=unactionable_domains,
            review_output_rows=review_rows,
            log_text=_read_optional_text(log_path),
            cache_path=cache if state["cache_present"] else None,
            cache_sha256=state["cache_sha256"],
        )
    except (OSError, UnicodeError, ValidationError, ValueError, KeyError) as exc:
        raise ValueError(f"invalid worker aggregate handoff {path}: {exc}") from exc


def load_worker_aggregate_manifest_for_worker(
    *, batch_id: str, worker_id: str, state_root: Path
) -> WorkerAggregateManifest | None:
    """Load one worker handoff when its state exists."""
    path = _manifest_path(batch_id=batch_id, worker_id=worker_id, state_root=state_root)
    if not path.is_file():
        return None
    manifest = load_worker_aggregate_manifest(
        path, state_root=state_root, batch_id=batch_id, worker_id=worker_id
    )
    if (manifest.batch_id, manifest.worker_id) != (batch_id, worker_id):
        raise ValueError(f"worker aggregate handoff identity mismatch: {path}")
    return manifest


def worker_aggregate_manifest_paths(*, batch_id: str, state_root: Path) -> list[Path]:
    """Discover worker handoff state paths for a batch."""
    root = PathLayout(state_root).workflow_state.worker_result_batch_root(
        batch_id=batch_id
    )
    state_name = _manifest_path(
        batch_id=batch_id, worker_id="_", state_root=state_root
    ).name
    return sorted(root.glob(f"*/{state_name}")) if root.is_dir() else []


def write_worker_aggregate_manifest(
    manifest: WorkerAggregateManifest, *, state_root: Path
) -> Path:
    """Write the worker handoff state at its canonical path."""
    path = _manifest_path(
        batch_id=manifest.batch_id, worker_id=manifest.worker_id, state_root=state_root
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    state = {
        "batch_id": manifest.batch_id,
        "worker_id": manifest.worker_id,
        "handoff_finalized": manifest.handoff_finalized,
        "cache_present": manifest.cache_path is not None,
        "cache_sha256": manifest.cache_sha256,
    }
    write_yaml(path, state)
    return path


def finalize_worker_aggregate_handoff(
    *,
    batch_id: str,
    worker_id: str,
    state_root: Path,
) -> dict[str, Any]:
    """Finalize one worker-to-aggregate handoff from worker-local sidecars."""
    prepare_manifest, failure_reason = load_prepare_worker_manifest_or_error(
        batch_id=batch_id,
        worker_id=worker_id,
        state_root=state_root,
    )
    if failure_reason:
        return {
            "batch_id": batch_id,
            "worker_id": worker_id,
            "handoff_finalized": False,
            "error_reason": failure_reason,
        }
    if prepare_manifest is None:
        raise RuntimeError("prepare worker manifest loader returned no manifest")
    paths = prepare_manifest.resolve_paths(state_root)
    expected_input_domains_by_root = _expected_input_domains_by_root(prepare_manifest)
    unactionable_domains = _read_text_values(paths["unactionable"])
    review_rows = _read_review_rows(paths["review"])
    envelope = _read_jsonl_result_envelope(paths["domain_results"])
    validate_worker_domain_results(
        expected_input_domains_by_root=expected_input_domains_by_root,
        envelope=envelope,
    )
    _validate_worker_domain_outputs(
        envelope=envelope,
        unactionable_domains=unactionable_domains,
        review_rows=review_rows,
    )
    path = _manifest_path(batch_id=batch_id, worker_id=worker_id, state_root=state_root)
    root = path.parent
    root.mkdir(parents=True, exist_ok=True)
    # Mark the handoff incomplete before replacing any data.
    write_worker_aggregate_manifest(
        WorkerAggregateManifest.empty(
            batch_id, worker_id
        ),
        state_root=state_root,
    )
    state_paths = PathLayout(state_root).workflow_state
    state_paths.worker_handoff_unactionable_path(
        batch_id=batch_id, worker_id=worker_id
    ).write_text(
        "".join(f"{value}\n" for value in unactionable_domains),
        encoding="utf-8",
    )
    write_csv(
        state_paths.worker_handoff_review_path(batch_id=batch_id, worker_id=worker_id),
        tuple(REVIEW_OUTPUT_COLUMNS),
        review_rows,
    )
    domain_results_path = state_paths.worker_handoff_domain_results_path(
        batch_id=batch_id, worker_id=worker_id
    )
    domain_results_path.parent.mkdir(parents=True, exist_ok=True)
    domain_results_path.write_text(
        json.dumps(
            envelope.model_dump(mode="json"),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    cache = state_paths.worker_handoff_cache_path(
        batch_id=batch_id, worker_id=worker_id
    )
    mode = _snapshot_cache(paths["cache"], cache)
    checksum = (
        hashlib.sha256(cache.read_bytes()).hexdigest() if mode != "missing" else None
    )
    manifest = WorkerAggregateManifest.empty(
        batch_id, worker_id, finalized=True
    ).model_copy(
        update={"cache_path": cache if checksum else None, "cache_sha256": checksum}
    )
    write_worker_aggregate_manifest(manifest, state_root=state_root)
    return {
        "batch_id": batch_id,
        "worker_id": worker_id,
        "handoff_finalized": True,
        "worker_aggregate_manifest_path": path.relative_to(state_root).as_posix(),
        "cache_snapshot_mode": mode,
        "cache_size_bytes": cache.stat().st_size if checksum else 0,
    }


def load_prepare_worker_manifest_or_error(
    *,
    batch_id: str,
    worker_id: str,
    state_root: Path,
) -> tuple[PrepareWorkerManifest | None, str]:
    """Load one prepare-worker manifest, returning validation failures as text."""
    try:
        return (
            load_prepare_worker_manifest_for_worker(
                batch_id=batch_id,
                worker_id=worker_id,
                state_root=state_root,
            ),
            "",
        )
    except (FileNotFoundError, ValueError) as exc:
        return None, str(exc)
