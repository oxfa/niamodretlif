"""Prepare-step planning owner."""

from __future__ import annotations

import dataclasses
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from domain_pipeline.prepare.classifications import (
    PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_PUBLIC_SUFFIX,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
)
from domain_pipeline.prepare.config.loader import PipelineConfigLoader
from domain_pipeline.prepare.delegation import delegation_behavior_fingerprint
from domain_pipeline.prepare.delegation_conflicts import (
    conflicting_delegation_behavior_message,
)
from domain_pipeline.prepare.ip_location_credentials import (
    IPLocationCredentialValidator,
)
from domain_pipeline.prepare.manual_inputs import ManualInputLoader, ManualInputSet
from domain_pipeline.prepare.merger import PreparedEntryMerger
from domain_pipeline.prepare.models import (
    MANUAL_ADD_SOURCE_ID,
    PreparedHostEntry,
    PreparedInputSet,
    PreparedProvenance,
    PreparedRootPlan,
    PreparedSourcePosition,
)
from domain_pipeline.prepare.sources.jobs import SourceJob, SourceJobFactory
from domain_pipeline.prepare.sources.parser import DomainListParser, ParsedDomainEntry
from domain_pipeline.routing.policy import route_for_pipeline_result_code
from domain_pipeline.worker.host_resolution.lookup import host_resolution_dns_profile
from domain_pipeline.worker.output.rows import (
    BaseRowRequest,
    BaseRowSourceRequest,
    build_base_row,
)


@dataclasses.dataclass(frozen=True)
class _PreparedSourceContext:
    source_id: str
    input_label: str
    output_stem: str
    config: dict[str, Any]


@dataclasses.dataclass
class PreparationCollections:
    """Mutable collections built while preparing one config."""

    entries_by_host: dict[str, PreparedHostEntry] = dataclasses.field(
        default_factory=dict
    )
    manual_out_by_host: dict[str, PreparedHostEntry] = dataclasses.field(
        default_factory=dict
    )
    review_rows: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    terminal_rows: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    matched_hosts: set[str] = dataclasses.field(default_factory=set)


@dataclasses.dataclass
class PreparationState:
    """State passed between prepare planning stages."""

    config: dict[str, Any]
    jobs: list[SourceJob]
    source_jobs_by_id: dict[str, SourceJob]
    manual_inputs: ManualInputSet
    parser: DomainListParser
    collections: PreparationCollections = dataclasses.field(
        default_factory=PreparationCollections
    )

    @property
    def primary_job(self) -> SourceJob:
        """Return the first enabled source job used for unmatched manual rows."""
        return self.jobs[0]


@dataclasses.dataclass(frozen=True)
class ManualRowRequest:
    """Inputs needed to project one prepare-owned manual review row."""

    job: SourceJob
    entry: ParsedDomainEntry
    pipeline_result_code: str
    input_label: str
    source_ids: tuple[str, ...] | None = None
    source_input_labels: tuple[str, ...] | None = None


@dataclasses.dataclass
class ManualRoutingState:
    """Manual-routing validation state shared while source rows are collected."""

    manual_inputs: ManualInputSet
    host_fingerprints: dict[str, str] = dataclasses.field(default_factory=dict)
    manual_add_fingerprints_by_host: dict[str, str] = dataclasses.field(
        default_factory=dict
    )


@dataclasses.dataclass(frozen=True)
class HostBehaviorRequest:
    """Inputs needed to validate one prepared host behavior fingerprint."""

    host: str
    job: SourceJob
    routing: ManualRoutingState


def _resolve_from_root(source_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else source_root / path


def _source_context_from_job(job: SourceJob) -> _PreparedSourceContext:
    return _PreparedSourceContext(
        source_id=job.source_id,
        input_label=job.input_label,
        output_stem=job.output_stem,
        config=job.config,
    )


def _manual_review_row(request: ManualRowRequest) -> dict[str, Any]:
    return build_base_row(
        BaseRowRequest(
            source=BaseRowSourceRequest(
                source_context=_source_context_from_job(request.job),
                provenance=PreparedProvenance(
                    source_id_override=request.pipeline_result_code,
                    source_input_label_override=request.input_label,
                    source_ids=request.source_ids or (request.pipeline_result_code,),
                    source_input_labels=request.source_input_labels
                    or (request.input_label,),
                ),
            ),
            entry=request.entry,
            pipeline_result_code=request.pipeline_result_code,
        )
    )


def _public_suffix_review_row(
    *,
    job: SourceJob,
    prepared_entry: PreparedHostEntry,
) -> dict[str, Any]:
    return build_base_row(
        BaseRowRequest(
            source=BaseRowSourceRequest(
                source_context=_source_context_from_job(job),
                provenance=PreparedProvenance(
                    source_id_override=prepared_entry.provenance.source_id_override,
                    source_input_label_override=(
                        prepared_entry.provenance.source_input_label_override
                    ),
                    source_ids=prepared_entry.provenance.source_ids,
                    source_input_labels=prepared_entry.provenance.source_input_labels,
                ),
            ),
            entry=prepared_entry.entry,
            pipeline_result_code=PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX,
        )
    )


def _manual_filter_pass_public_suffix_row(
    *,
    job: SourceJob,
    prepared_entry: PreparedHostEntry,
) -> dict[str, Any]:
    return build_base_row(
        BaseRowRequest(
            source=BaseRowSourceRequest(
                source_context=_source_context_from_job(job),
                provenance=PreparedProvenance(
                    source_id_override=prepared_entry.provenance.source_id_override,
                    source_input_label_override=(
                        prepared_entry.provenance.source_input_label_override
                    ),
                    source_ids=prepared_entry.provenance.source_ids,
                    source_input_labels=prepared_entry.provenance.source_input_labels,
                ),
            ),
            entry=prepared_entry.entry,
            pipeline_result_code=PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_PUBLIC_SUFFIX,
        )
    )


def _preparation_terminal_row(
    *,
    row: dict[str, Any],
    pipeline_result_code: str,
) -> dict[str, Any]:
    """Return a prepare-owned terminal row with the canonical route policy."""
    return {
        **row,
        "route": route_for_pipeline_result_code(pipeline_result_code),
    }


class PreparationPlanner:
    """Prepare worker entries and prepare-owned terminal rows."""

    def __init__(
        self,
        *,
        source_root: Path,
        entry_merger: PreparedEntryMerger | None = None,
        manual_loader: ManualInputLoader | None = None,
        credential_validator: IPLocationCredentialValidator | None = None,
    ) -> None:
        self.source_root = source_root
        self.entry_merger = entry_merger or PreparedEntryMerger()
        self.manual_loader = manual_loader or ManualInputLoader(source_root=source_root)
        self.credential_validator = (
            credential_validator or IPLocationCredentialValidator()
        )

    def prepare(self, *, config_path: Path) -> PreparedInputSet:
        """Load config and prepare worker entries plus terminal rows."""
        resolved_config_path = _resolve_from_root(self.source_root, config_path)
        config = PipelineConfigLoader().load(resolved_config_path)
        self.credential_validator.validate_config(config)
        return self.prepare_config(config)

    def prepare_config(self, config: dict[str, Any]) -> PreparedInputSet:
        """Prepare worker entries plus terminal rows from an already-loaded config."""
        jobs = SourceJobFactory().build_jobs(config, source_root=self.source_root)
        if not jobs:
            raise ValueError("config produced no enabled source jobs")

        state = PreparationState(
            config=config,
            jobs=jobs,
            source_jobs_by_id={job.source_id: job for job in jobs},
            manual_inputs=self.manual_loader.load(str(config["config_name"])),
            parser=DomainListParser(),
        )

        self._collect_configured_source_entries(state)
        self._append_manual_out_rows(state)
        self._merge_manual_add_entries(state)

        entries_by_source = self._partition_worker_entries(state)

        self._append_missing_manual_pass_rows(state)
        self._append_missing_manual_out_rows(state)

        root_plans = self._root_plans(
            entries_by_source=entries_by_source,
            source_jobs_by_id=state.source_jobs_by_id,
        )
        return PreparedInputSet(
            config=config,
            source_jobs_by_id=state.source_jobs_by_id,
            entries_by_source=dict(entries_by_source),
            root_plans=root_plans,
            preparation_review_rows=state.collections.review_rows,
            preparation_terminal_rows=state.collections.terminal_rows,
        )

    def _collect_configured_source_entries(self, state: PreparationState) -> None:
        routing = ManualRoutingState(manual_inputs=state.manual_inputs)
        for source_index, job in enumerate(state.jobs):
            source_format = job.config.get("input", {}).get("format", "auto")
            forced_format = None if source_format == "auto" else source_format
            for record in state.parser.process_entry_records(
                job.lines,
                source_name=job.input_label,
                forced_format=forced_format,
            ):
                host = record.entry.host
                state.collections.matched_hosts.add(host)
                self._validate_host_behavior_fingerprint(
                    HostBehaviorRequest(host=host, job=job, routing=routing)
                )
                prepared_entry = PreparedHostEntry(
                    entry=record.entry,
                    position=PreparedSourcePosition(
                        source_id=job.source_id,
                        source_index=source_index,
                        line_index=record.line_index,
                        raw_line=record.raw_line,
                    ),
                    provenance=PreparedProvenance(
                        manual_filter_pass=(
                            host in state.manual_inputs.manual_filter_pass_entries
                        ),
                        source_ids=(job.source_id,),
                        source_input_labels=(job.input_label,),
                    ),
                )
                if host in state.manual_inputs.manual_filter_out_entries:
                    self.entry_merger.merge_entry_by_host(
                        state.collections.manual_out_by_host, prepared_entry
                    )
                    continue
                self.entry_merger.merge_entry_by_host(
                    state.collections.entries_by_host, prepared_entry
                )

    def _validate_host_behavior_fingerprint(self, request: HostBehaviorRequest) -> None:
        if request.host in request.routing.manual_inputs.manual_add_entries:
            fingerprint = self._manual_add_behavior_fingerprint(request.job.config)
            previous = request.routing.manual_add_fingerprints_by_host.get(request.host)
            if previous is not None and previous != fingerprint:
                raise ValueError(
                    f"manual-add host {request.host!r} appears in multiple enabled "
                    "sources with different dns_query/delegation/output behavior"
                )
            request.routing.manual_add_fingerprints_by_host[request.host] = fingerprint
            return

        fingerprint = self._source_behavior_fingerprint(request.job.config)
        previous = request.routing.host_fingerprints.get(request.host)
        if previous is not None and previous != fingerprint:
            raise ValueError(
                f"duplicate host {request.host!r} has conflicting dns/stage/output behavior"
            )
        request.routing.host_fingerprints[request.host] = fingerprint

    def _append_manual_out_rows(self, state: PreparationState) -> None:
        for host in sorted(state.collections.manual_out_by_host):
            prepared_entry = state.collections.manual_out_by_host[host]
            source_ids = self.entry_merger.stable_unique_merge(
                (PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT,),
                prepared_entry.provenance.source_ids,
            )
            source_input_labels = self.entry_merger.stable_unique_merge(
                (str(state.manual_inputs.manual_filter_out_path),),
                prepared_entry.provenance.source_input_labels,
            )
            row = _manual_review_row(
                ManualRowRequest(
                    job=state.source_jobs_by_id[prepared_entry.position.source_id],
                    entry=prepared_entry.entry,
                    pipeline_result_code=PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT,
                    input_label=str(state.manual_inputs.manual_filter_out_path),
                    source_ids=source_ids,
                    source_input_labels=source_input_labels,
                )
            )
            state.collections.review_rows.append(row)
            state.collections.terminal_rows.append(
                _preparation_terminal_row(
                    row=row,
                    pipeline_result_code=PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT,
                )
            )

    def _merge_manual_add_entries(self, state: PreparationState) -> None:
        manual_add_config_fingerprints = {
            self._manual_add_behavior_fingerprint(job.config) for job in state.jobs
        }
        for host, entry in sorted(state.manual_inputs.manual_add_entries.items()):
            incoming = PreparedHostEntry(
                entry=entry,
                position=PreparedSourcePosition(
                    source_id=state.primary_job.source_id,
                    source_index=0,
                    line_index=10_000_000,
                    raw_line=host,
                ),
                provenance=PreparedProvenance(
                    manual_add=True,
                    source_id_override=MANUAL_ADD_SOURCE_ID,
                    source_input_label_override=str(
                        state.manual_inputs.manual_add_path
                    ),
                    source_ids=(MANUAL_ADD_SOURCE_ID,),
                    source_input_labels=(str(state.manual_inputs.manual_add_path),),
                ),
            )
            current = state.collections.entries_by_host.get(host)
            if current is None:
                if len(manual_add_config_fingerprints) > 1:
                    raise ValueError(
                        f"manual-add file {state.manual_inputs.manual_add_path} contains "
                        f"unmatched host {host!r}; unmatched manual_add requires "
                        "all enabled sources to share dns_query/delegation/output behavior"
                    )
                state.collections.entries_by_host[host] = incoming
            else:
                provenance = dataclasses.replace(
                    current.provenance,
                    manual_add=True,
                    source_id_override=MANUAL_ADD_SOURCE_ID,
                    source_input_label_override=str(
                        state.manual_inputs.manual_add_path
                    ),
                    source_ids=self.entry_merger.stable_unique_merge(
                        current.provenance.source_ids, (MANUAL_ADD_SOURCE_ID,)
                    ),
                    source_input_labels=self.entry_merger.stable_unique_merge(
                        current.provenance.source_input_labels,
                        (str(state.manual_inputs.manual_add_path),),
                    ),
                )
                state.collections.entries_by_host[host] = dataclasses.replace(
                    current,
                    provenance=provenance,
                )
            state.collections.matched_hosts.add(host)

    def _partition_worker_entries(
        self, state: PreparationState
    ) -> dict[str, list[PreparedHostEntry]]:
        entries_by_source: dict[str, list[PreparedHostEntry]] = defaultdict(list)
        for prepared_entry in sorted(
            state.collections.entries_by_host.values(),
            key=lambda current: (
                current.position.source_index,
                current.position.line_index,
                current.entry.host,
            ),
        ):
            if (
                prepared_entry.entry.semantics.is_public_suffix_input
                or not prepared_entry.entry.registrable_domain
            ):
                if prepared_entry.provenance.manual_filter_pass:
                    pipeline_result_code = (
                        PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_PUBLIC_SUFFIX
                    )
                    row = _manual_filter_pass_public_suffix_row(
                        job=state.source_jobs_by_id[prepared_entry.position.source_id],
                        prepared_entry=prepared_entry,
                    )
                else:
                    pipeline_result_code = PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX
                    row = _public_suffix_review_row(
                        job=state.source_jobs_by_id[prepared_entry.position.source_id],
                        prepared_entry=prepared_entry,
                    )
                    state.collections.review_rows.append(row)
                state.collections.terminal_rows.append(
                    _preparation_terminal_row(
                        row=row,
                        pipeline_result_code=pipeline_result_code,
                    )
                )
                continue
            entries_by_source[prepared_entry.position.source_id].append(prepared_entry)
        return entries_by_source

    def _append_missing_manual_pass_rows(self, state: PreparationState) -> None:
        for host, entry in sorted(
            state.manual_inputs.manual_filter_pass_entries.items()
        ):
            if host in state.collections.matched_hosts:
                continue
            row = _manual_review_row(
                ManualRowRequest(
                    job=state.primary_job,
                    entry=entry,
                    pipeline_result_code=PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
                    input_label=str(state.manual_inputs.manual_filter_pass_path),
                )
            )
            state.collections.review_rows.append(row)
            state.collections.terminal_rows.append(
                _preparation_terminal_row(
                    row=row,
                    pipeline_result_code=PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
                )
            )

    def _append_missing_manual_out_rows(self, state: PreparationState) -> None:
        for host, entry in sorted(
            state.manual_inputs.manual_filter_out_entries.items()
        ):
            if host in state.collections.manual_out_by_host:
                continue
            row = _manual_review_row(
                ManualRowRequest(
                    job=state.primary_job,
                    entry=entry,
                    pipeline_result_code=PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
                    input_label=str(state.manual_inputs.manual_filter_out_path),
                )
            )
            state.collections.review_rows.append(row)
            state.collections.terminal_rows.append(
                _preparation_terminal_row(
                    row=row,
                    pipeline_result_code=PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
                )
            )

    def _root_plans(
        self,
        *,
        entries_by_source: dict[str, list[PreparedHostEntry]],
        source_jobs_by_id: dict[str, SourceJob],
    ) -> dict[str, PreparedRootPlan]:
        root_entries: dict[str, list[PreparedHostEntry]] = defaultdict(list)
        for entries in entries_by_source.values():
            for entry in entries:
                if entry.entry.registrable_domain:
                    root_entries[entry.entry.registrable_domain].append(entry)

        root_plans: dict[str, PreparedRootPlan] = {}
        for registrable_domain, entries in sorted(root_entries.items()):
            ordered_entries = sorted(
                entries,
                key=lambda entry: (
                    entry.position.source_index,
                    entry.position.line_index,
                    entry.entry.host,
                ),
            )
            fingerprints_by_source = {
                entry.position.source_id: delegation_behavior_fingerprint(
                    source_jobs_by_id[entry.position.source_id].config
                )
                for entry in ordered_entries
            }
            fingerprints = set(fingerprints_by_source.values())
            if len(fingerprints) > 1:
                raise ValueError(
                    conflicting_delegation_behavior_message(
                        registrable_domain, fingerprints_by_source
                    )
                )
            delegation_config_source_id = ordered_entries[0].position.source_id
            root_plans[registrable_domain] = PreparedRootPlan(
                registrable_domain=registrable_domain,
                entry_count=len(ordered_entries),
                delegation_config_source_id=delegation_config_source_id,
                delegation_behavior_fingerprint=fingerprints_by_source[
                    delegation_config_source_id
                ],
            )
        return root_plans

    def _stage_dns_config(self, source_config: dict[str, Any]) -> dict[str, Any]:
        return {
            **dict(source_config["dns_query"]),
            "delegation": dict(source_config["delegation"]),
            "host_resolution": dict(source_config["host_resolution"]),
        }

    def _canonical_delegation_behavior(
        self, source_config: dict[str, Any]
    ) -> dict[str, Any]:
        return json.loads(delegation_behavior_fingerprint(source_config))

    def _canonical_host_resolution_behavior(
        self, source_config: dict[str, Any]
    ) -> dict[str, Any]:
        dns_config = self._stage_dns_config(source_config)
        host_resolution_config = dict(source_config["host_resolution"])
        return {
            **host_resolution_dns_profile(dns_config),
            "enabled": host_resolution_config["enabled"],
            "retry_attempts": host_resolution_config["retry_attempts"],
        }

    def _source_behavior_fingerprint(self, source_config: dict[str, Any]) -> str:
        payload = {
            "dns_query": source_config["dns_query"],
            "delegation": self._canonical_delegation_behavior(source_config),
            "host_resolution": self._canonical_host_resolution_behavior(source_config),
            "ip_location": source_config["ip_location"],
            "output": source_config["output"],
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def _manual_add_behavior_fingerprint(self, source_config: dict[str, Any]) -> str:
        payload = {
            "dns_query": source_config["dns_query"],
            "delegation": self._canonical_delegation_behavior(source_config),
            "output": source_config["output"],
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))
