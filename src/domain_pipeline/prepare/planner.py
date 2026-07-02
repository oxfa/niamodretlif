"""Prepare-step planning owner."""

from __future__ import annotations

import dataclasses
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from domain_pipeline.prepare.config.loader import PipelineConfigLoader
from domain_pipeline.prepare.delegation import delegation_behavior_fingerprint
from domain_pipeline.prepare.delegation_conflicts import (
    conflicting_delegation_behavior_message,
)
from domain_pipeline.prepare.ip_location_credentials import (
    IPLocationCredentialValidator,
)
from domain_pipeline.prepare.manual_inputs import ManualInputLoader, ManualInputSet
from domain_pipeline.prepare.merger import PreparedEntryMerger, prepared_entry_merge_key
from domain_pipeline.prepare.models import (
    MANUALLY_ADDED_SOURCE_ID,
    MANUALLY_SELECTED_FOR_FILTERED_SOURCE_ID,
    PreparedInputSet,
    PreparedManualRouting,
    PreparedOutputRows,
    PreparedRootPlan,
)
from domain_pipeline.prepare.sources.jobs import SourceJob, SourceJobFactory
from domain_pipeline.prepare.sources.parser import DomainEntry, DomainListParser
from domain_pipeline.routing import (
    InputValidationRoutingPolicy,
    ManualRoutingPolicy,
    TerminalRouteTransition,
)
from domain_pipeline.worker.host_resolution.lookup import host_resolution_dns_profile
from domain_pipeline.worker.output.rows import (
    BaseRowRequest,
    BaseRowSourceRequest,
    TerminalRowBuilder,
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

    entries_by_host: dict[str, DomainEntry] = dataclasses.field(default_factory=dict)
    source_id_by_host: dict[str, str] = dataclasses.field(default_factory=dict)
    manual_routing_by_host: dict[str, PreparedManualRouting] = dataclasses.field(
        default_factory=dict
    )
    review_rows: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    terminal_rows: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    matched_hosts: set[str] = dataclasses.field(default_factory=set)
    parsed_source_entry_count: int = 0


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
    entry: DomainEntry
    route_transition: TerminalRouteTransition
    source_id: str
    input_label: str


@dataclasses.dataclass
class ManualRoutingState:
    """Manual-routing validation state shared while source rows are collected."""

    manual_inputs: ManualInputSet
    host_fingerprints: dict[str, str] = dataclasses.field(default_factory=dict)
    manually_added_fingerprints_by_host: dict[str, str] = dataclasses.field(
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


def _source_relative_label(source_root: Path, path: Path) -> str:
    """Return a stable source-root-relative label for emitted source context."""
    try:
        return path.relative_to(source_root).as_posix()
    except ValueError:
        return path.resolve().relative_to(source_root.resolve()).as_posix()


def _source_context_from_job(job: SourceJob) -> _PreparedSourceContext:
    return _PreparedSourceContext(
        source_id=job.source_id,
        input_label=job.input_label,
        output_stem=job.output_stem,
        config=job.config,
    )


def _manual_review_row(request: ManualRowRequest) -> dict[str, Any]:
    return TerminalRowBuilder().build(
        BaseRowRequest(
            source=BaseRowSourceRequest(
                source_context=_source_context_from_job(request.job),
                source_id=request.source_id,
                source_input_label=request.input_label,
            ),
            entry=request.entry,
            route_transition=request.route_transition,
        )
    )


def _public_suffix_review_row(
    *,
    job: SourceJob,
    entry: DomainEntry,
    manual_routing: PreparedManualRouting,
) -> dict[str, Any]:
    route_transition = InputValidationRoutingPolicy().public_suffix()
    return TerminalRowBuilder().build(
        BaseRowRequest(
            source=BaseRowSourceRequest(
                source_context=_source_context_from_job(job),
                source_id=manual_routing.output_source_id,
                source_input_label=manual_routing.output_source_input_label,
            ),
            entry=entry,
            route_transition=route_transition,
        )
    )


def _manually_selected_public_suffix_row(
    *,
    job: SourceJob,
    entry: DomainEntry,
    manual_routing: PreparedManualRouting,
) -> dict[str, Any]:
    route_transition = ManualRoutingPolicy().selected_public_suffix_for_filtered()
    return TerminalRowBuilder().build(
        BaseRowRequest(
            source=BaseRowSourceRequest(
                source_context=_source_context_from_job(job),
                source_id=manual_routing.output_source_id,
                source_input_label=manual_routing.output_source_input_label,
            ),
            entry=entry,
            route_transition=route_transition,
        )
    )


def _preparation_terminal_row(
    *,
    row: dict[str, Any],
    route_transition: TerminalRouteTransition,
) -> dict[str, Any]:
    """Return a prepare-owned terminal row with the canonical route policy."""
    return {
        **row,
        "route": route_transition.route,
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
        self._merge_manually_added_entries(state)

        entries_by_source = self._partition_worker_entries(state)

        self._append_missing_manually_selected_rows(state)

        root_plans = self._root_plans(
            entries_by_source=entries_by_source,
            source_jobs_by_id=state.source_jobs_by_id,
        )
        return PreparedInputSet(
            config=config,
            source_jobs_by_id=state.source_jobs_by_id,
            parsed_source_entry_count=state.collections.parsed_source_entry_count,
            entries_by_source=dict(entries_by_source),
            manual_routing_by_host=dict(state.collections.manual_routing_by_host),
            root_plans=root_plans,
            preparation_outputs=PreparedOutputRows(
                review_rows=state.collections.review_rows,
                terminal_rows=state.collections.terminal_rows,
            ),
        )

    def _collect_configured_source_entries(self, state: PreparationState) -> None:
        routing = ManualRoutingState(manual_inputs=state.manual_inputs)
        excluded_hosts = set(state.manual_inputs.manually_excluded_from_sources_entries)
        for job in state.jobs:
            configured_format = job.config.get("input", {}).get("format", "auto")
            forced_format = None if configured_format == "auto" else configured_format
            for entry in state.parser.process_entries(
                job.lines,
                source_name=job.input_label,
                forced_format=forced_format,
            ):
                host = entry.host
                state.collections.parsed_source_entry_count += 1
                state.collections.matched_hosts.add(host)
                if host in excluded_hosts:
                    continue
                self._validate_host_behavior_fingerprint(
                    HostBehaviorRequest(host=host, job=job, routing=routing)
                )
                manual_routing = PreparedManualRouting(
                    manually_selected_for_filtered=(
                        host
                        in state.manual_inputs.manually_selected_for_filtered_entries
                    )
                )
                self.entry_merger.merge_entry_by_host(
                    state.collections.entries_by_host, entry
                )
                state.collections.source_id_by_host.setdefault(host, job.source_id)
                if manual_routing.manually_selected_for_filtered:
                    state.collections.manual_routing_by_host[host] = manual_routing

    def _validate_host_behavior_fingerprint(self, request: HostBehaviorRequest) -> None:
        if request.host in request.routing.manual_inputs.manually_added_entries:
            fingerprint = self._manually_added_behavior_fingerprint(request.job.config)
            previous = request.routing.manually_added_fingerprints_by_host.get(
                request.host
            )
            if previous is not None and previous != fingerprint:
                raise ValueError(
                    f"manually added host {request.host!r} appears in multiple enabled "
                    "sources with different dns_query/delegation/output behavior"
                )
            request.routing.manually_added_fingerprints_by_host[request.host] = (
                fingerprint
            )
            return

        fingerprint = self._source_behavior_fingerprint(request.job.config)
        previous = request.routing.host_fingerprints.get(request.host)
        if previous is not None and previous != fingerprint:
            raise ValueError(
                f"duplicate host {request.host!r} has conflicting dns/stage/output behavior"
            )
        request.routing.host_fingerprints[request.host] = fingerprint

    def _merge_manually_added_entries(self, state: PreparationState) -> None:
        manually_added_config_fingerprints = {
            self._manually_added_behavior_fingerprint(job.config) for job in state.jobs
        }
        manually_added_label = _source_relative_label(
            self.source_root,
            state.manual_inputs.manually_added_path,
        )
        for host, entry in sorted(state.manual_inputs.manually_added_entries.items()):
            manual_routing = PreparedManualRouting(
                manually_added=True,
                output_source_id=MANUALLY_ADDED_SOURCE_ID,
                output_source_input_label=manually_added_label,
            )
            current_keys = self._matching_prepared_entry_keys(
                state.collections.entries_by_host,
                entry,
            )
            if not current_keys:
                if len(manually_added_config_fingerprints) > 1:
                    raise ValueError(
                        "manually added file "
                        f"{state.manual_inputs.manually_added_path} contains "
                        f"unmatched host {host!r}; unmatched manually_added requires "
                        "all enabled sources to share dns_query/delegation/output behavior"
                    )
                state.collections.entries_by_host[prepared_entry_merge_key(entry)] = (
                    entry
                )
                state.collections.source_id_by_host[host] = state.primary_job.source_id
                state.collections.manual_routing_by_host[host] = manual_routing
            else:
                for current_key in current_keys:
                    current_routing = state.collections.manual_routing_by_host.get(
                        current_key, PreparedManualRouting()
                    )
                    state.collections.manual_routing_by_host[current_key] = (
                        dataclasses.replace(
                            current_routing,
                            manually_added=True,
                            output_source_id=MANUALLY_ADDED_SOURCE_ID,
                            output_source_input_label=manually_added_label,
                        )
                    )
            state.collections.matched_hosts.add(host)

    def _matching_prepared_entry_keys(
        self,
        entries_by_key: dict[str, DomainEntry],
        incoming: DomainEntry,
    ) -> list[str]:
        """Return prepared-entry keys that should receive a manual override."""
        return [
            key
            for key, _entry in sorted(
                (
                    (key, entry)
                    for key, entry in entries_by_key.items()
                    if entry.host == incoming.host
                ),
                key=lambda item: item[0],
            )
        ]

    def _partition_worker_entries(
        self, state: PreparationState
    ) -> dict[str, list[DomainEntry]]:
        entries_by_source: dict[str, list[DomainEntry]] = defaultdict(list)
        for entry in sorted(
            state.collections.entries_by_host.values(),
            key=lambda current: (
                state.jobs.index(
                    state.source_jobs_by_id[
                        state.collections.source_id_by_host[current.host]
                    ]
                ),
                current.host,
            ),
        ):
            source_id = state.collections.source_id_by_host[entry.host]
            manual_routing = state.collections.manual_routing_by_host.get(
                entry.host, PreparedManualRouting()
            )
            if entry.registrable_domain is None:
                if manual_routing.manually_selected_for_filtered:
                    route_transition = (
                        ManualRoutingPolicy().selected_public_suffix_for_filtered()
                    )
                    row = _manually_selected_public_suffix_row(
                        job=state.source_jobs_by_id[source_id],
                        entry=entry,
                        manual_routing=manual_routing,
                    )
                else:
                    route_transition = InputValidationRoutingPolicy().public_suffix()
                    row = _public_suffix_review_row(
                        job=state.source_jobs_by_id[source_id],
                        entry=entry,
                        manual_routing=manual_routing,
                    )
                    state.collections.review_rows.append(row)
                state.collections.terminal_rows.append(
                    _preparation_terminal_row(
                        row=row,
                        route_transition=route_transition,
                    )
                )
                continue
            entries_by_source[source_id].append(entry)
        return entries_by_source

    def _append_missing_manually_selected_rows(self, state: PreparationState) -> None:
        for host, entry in sorted(
            state.manual_inputs.manually_selected_for_filtered_entries.items()
        ):
            if host in state.collections.matched_hosts:
                continue
            route_transition = (
                ManualRoutingPolicy().selected_for_filtered_not_in_sources()
            )
            row = _manual_review_row(
                ManualRowRequest(
                    job=state.primary_job,
                    entry=entry,
                    route_transition=route_transition,
                    source_id=MANUALLY_SELECTED_FOR_FILTERED_SOURCE_ID,
                    input_label=_source_relative_label(
                        self.source_root,
                        state.manual_inputs.manually_selected_for_filtered_path,
                    ),
                )
            )
            state.collections.review_rows.append(row)
            state.collections.terminal_rows.append(
                _preparation_terminal_row(
                    row=row,
                    route_transition=route_transition,
                )
            )

    def _root_plans(
        self,
        *,
        entries_by_source: dict[str, list[DomainEntry]],
        source_jobs_by_id: dict[str, SourceJob],
    ) -> dict[str, PreparedRootPlan]:
        root_entries: dict[str, list[tuple[str, DomainEntry]]] = defaultdict(list)
        source_order_by_id = {
            source_id: source_index
            for source_index, source_id in enumerate(source_jobs_by_id)
        }
        for source_id, entries in entries_by_source.items():
            for entry in entries:
                if entry.registrable_domain:
                    root_entries[entry.registrable_domain].append((source_id, entry))

        root_plans: dict[str, PreparedRootPlan] = {}
        for registrable_domain, entries in sorted(root_entries.items()):
            ordered_entries = sorted(
                entries,
                key=lambda entry: (
                    source_order_by_id[entry[0]],
                    entry[1].host,
                ),
            )
            fingerprints_by_source = {
                source_id: delegation_behavior_fingerprint(
                    source_jobs_by_id[source_id].config
                )
                for source_id, _entry in ordered_entries
            }
            fingerprints = set(fingerprints_by_source.values())
            if len(fingerprints) > 1:
                raise ValueError(
                    conflicting_delegation_behavior_message(
                        registrable_domain, fingerprints_by_source
                    )
                )
            delegation_config_source_id = ordered_entries[0][0]
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

    def _manually_added_behavior_fingerprint(
        self, source_config: dict[str, Any]
    ) -> str:
        payload = {
            "dns_query": source_config["dns_query"],
            "delegation": self._canonical_delegation_behavior(source_config),
            "output": source_config["output"],
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))
