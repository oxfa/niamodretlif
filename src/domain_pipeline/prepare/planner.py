"""Prepare-step planning owner."""

from __future__ import annotations

import dataclasses
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from domain_pipeline.prepare.config.loader import PipelineConfigLoader
from domain_pipeline.prepare.delegation import (
    effective_delegation_profile,
    effective_host_resolution_profile,
    effective_ip_location_profile,
)
from domain_pipeline.prepare.delegation_conflicts import (
    conflicting_delegation_behavior_message,
)
from domain_pipeline.prepare.ip_location_credentials import (
    IPLocationCredentialValidator,
)
from domain_pipeline.prepare.manual_inputs import ManualInputLoader, ManualInputSet
from domain_pipeline.prepare.merger import PreparedEntryMerger, prepared_entry_merge_key
from domain_pipeline.prepare.models import (
    MANUALLY_SELECTED_FOR_FILTERED_SOURCE_ID,
    PreparedInputDomainPlan,
    PreparedInputSet,
    PreparedManualRouting,
    PreparedRootPlan,
)
from domain_pipeline.prepare.sources.jobs import SourceJob, SourceJobFactory
from domain_pipeline.prepare.sources.parser import (
    DomainEntry,
    DomainListParser,
    ParsedSourceFile,
)
from domain_pipeline.routing import (
    ManualRoutingPolicy,
    TerminalRouteTransition,
)
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
    source_ids_by_host: dict[str, set[str]] = dataclasses.field(default_factory=dict)
    manual_routing_by_host: dict[str, PreparedManualRouting] = dataclasses.field(
        default_factory=dict
    )
    terminal_rows: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    matched_hosts: set[str] = dataclasses.field(default_factory=set)
    parsed_source_entry_count: int = 0
    parsed_source_files: dict[str, ParsedSourceFile] = dataclasses.field(
        default_factory=dict
    )


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
            manual_inputs=self.manual_loader.load(
                str(config["config_name"]), config["manual_inputs"]
            ),
            parser=DomainListParser(),
        )

        self._collect_configured_source_entries(state)
        self._merge_manually_added_entries(state)

        entries_by_source = self._partition_worker_entries(state)

        self._append_missing_manually_selected_rows(state)

        root_plans = self._root_plans(
            source_jobs_by_id=state.source_jobs_by_id,
            entries_by_host=state.collections.entries_by_host,
            source_ids_by_host=state.collections.source_ids_by_host,
            manual_routing_by_host=state.collections.manual_routing_by_host,
        )
        return PreparedInputSet(
            config=config,
            source_jobs_by_id=state.source_jobs_by_id,
            parsed_source_entry_count=state.collections.parsed_source_entry_count,
            entries_by_source=dict(entries_by_source),
            manual_routing_by_host=dict(state.collections.manual_routing_by_host),
            root_plans=root_plans,
            preparation_terminal_rows=state.collections.terminal_rows,
            source_ids_by_host={
                host: tuple(sorted(source_ids))
                for host, source_ids in state.collections.source_ids_by_host.items()
            },
            manually_added_entries=dict(
                state.manual_inputs.manually_added_entries
            ),
            excluded_source_hosts=set(
                state.manual_inputs.manually_excluded_from_sources_entries
            ),
            parsed_source_files=dict(state.collections.parsed_source_files),
        )

    def _collect_configured_source_entries(self, state: PreparationState) -> None:
        excluded_hosts = set(state.manual_inputs.manually_excluded_from_sources_entries)
        for job in state.jobs:
            configured_format = job.config.get("input", {}).get("format", "auto")
            forced_format = None if configured_format == "auto" else configured_format
            parsed_source_file = state.parser.parse_source_file(
                job.lines,
                source_name=job.input_label,
                forced_format=forced_format,
            )
            state.collections.parsed_source_files[job.source_id] = parsed_source_file
            for entry in state.parser.entries_from_parsed_source_file(
                parsed_source_file
            ):
                host = entry.host
                state.collections.parsed_source_entry_count += 1
                state.collections.matched_hosts.add(host)
                if host in excluded_hosts:
                    continue
                state.collections.source_ids_by_host.setdefault(host, set()).add(
                    job.source_id
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

    def _merge_manually_added_entries(self, state: PreparationState) -> None:
        for host, entry in sorted(state.manual_inputs.manually_added_entries.items()):
            manual_routing = PreparedManualRouting(manually_added=True)
            current_keys = self._matching_prepared_entry_keys(
                state.collections.entries_by_host,
                entry,
            )
            if not current_keys:
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
            if entry.registrable_domain is None:
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
            state.collections.terminal_rows.append(
                _preparation_terminal_row(
                    row=row,
                    route_transition=route_transition,
                )
            )

    def _root_plans(
        self,
        *,
        source_jobs_by_id: dict[str, SourceJob],
        entries_by_host: dict[str, DomainEntry],
        source_ids_by_host: dict[str, set[str] | tuple[str, ...]],
        manual_routing_by_host: dict[str, PreparedManualRouting],
    ) -> dict[str, PreparedRootPlan]:
        root_entries: dict[str, dict[str, DomainEntry]] = defaultdict(dict)
        for host, entry in entries_by_host.items():
            if entry.registrable_domain:
                root_entries[entry.registrable_domain][host] = entry

        root_plans: dict[str, PreparedRootPlan] = {}
        for registrable_domain, entries in sorted(root_entries.items()):
            delegation_profiles_by_source: dict[str, dict[str, Any]] = {}
            for host in sorted(entries):
                source_ids = tuple(sorted(source_ids_by_host.get(host, ())))
                routing = manual_routing_by_host.get(host, PreparedManualRouting())
                if routing.manually_added and not source_ids:
                    source_ids = tuple(sorted(source_jobs_by_id))
                for source_id in source_ids:
                    delegation_profiles_by_source[source_id] = (
                        effective_delegation_profile(
                            source_jobs_by_id[source_id].config
                        )
                    )

            profile_keys = {
                _profile_key(profile)
                for profile in delegation_profiles_by_source.values()
            }
            if len(profile_keys) > 1:
                raise ValueError(
                    conflicting_delegation_behavior_message(
                        registrable_domain, delegation_profiles_by_source
                    )
                )
            if not delegation_profiles_by_source:
                raise ValueError(
                    f"registrable domain {registrable_domain!r} has no effective "
                    "delegation profile"
                )
            delegation_profile = delegation_profiles_by_source[
                sorted(delegation_profiles_by_source)[0]
            ]

            input_domains: dict[str, PreparedInputDomainPlan] = {}
            for host, entry in sorted(entries.items()):
                routing = manual_routing_by_host.get(host, PreparedManualRouting())
                host_profile: dict[str, Any] | None = None
                ip_profile: dict[str, Any] | None = None
                if not (
                    routing.manually_selected_for_filtered or routing.manually_added
                ):
                    source_ids = tuple(sorted(source_ids_by_host.get(host, ())))
                    if not source_ids:
                        raise ValueError(
                            f"ordinary input domain {host!r} has no source profile"
                        )
                    source_configs = [
                        source_jobs_by_id[source_id].config
                        for source_id in source_ids
                    ]
                    host_enabled = {
                        bool(source["host_resolution"].get("enabled", False))
                        for source in source_configs
                    }
                    if len(host_enabled) > 1:
                        raise _domain_profile_conflict(
                            registrable_domain,
                            host,
                            source_ids,
                            "different host-resolution enablement",
                        )
                    if True in host_enabled:
                        effective_host_profiles = {
                            source_id: effective_host_resolution_profile(
                                source_jobs_by_id[source_id].config
                            )
                            for source_id in source_ids
                        }
                        host_profile_keys = {
                            _profile_key(
                                profile
                                if host == registrable_domain
                                else {
                                    key: value
                                    for key, value in profile.items()
                                    if key
                                    != "resolve_www_for_registrable_domain"
                                }
                            )
                            for profile in effective_host_profiles.values()
                        }
                        if len(host_profile_keys) > 1:
                            raise _domain_profile_conflict(
                                registrable_domain,
                                host,
                                source_ids,
                                "different effective host-resolution profile",
                            )
                        host_profile = effective_host_profiles[source_ids[0]]

                        ip_enabled = {
                            bool(source["ip_location"].get("enabled", False))
                            for source in source_configs
                        }
                        if len(ip_enabled) > 1:
                            raise _domain_profile_conflict(
                                registrable_domain,
                                host,
                                source_ids,
                                "different IP-location enablement",
                            )
                        if True in ip_enabled:
                            effective_ip_profiles = {
                                source_id: effective_ip_location_profile(
                                    source_jobs_by_id[source_id].config
                                )
                                for source_id in source_ids
                            }
                            if len(
                                {
                                    _profile_key(profile)
                                    for profile in effective_ip_profiles.values()
                                }
                            ) > 1:
                                raise _domain_profile_conflict(
                                    registrable_domain,
                                    host,
                                    source_ids,
                                    "different effective IP-location profile",
                                )
                            ip_profile = effective_ip_profiles[source_ids[0]]
                input_domains[host] = PreparedInputDomainPlan(
                    host=entry.host,
                    manual_routing=routing,
                    host_resolution_profile=host_profile,
                    ip_location_profile=ip_profile,
                )

            root_plans[registrable_domain] = PreparedRootPlan(
                registrable_domain=registrable_domain,
                delegation_profile=delegation_profile,
                input_domains=input_domains,
            )
        return root_plans


def _profile_key(profile: dict[str, Any]) -> str:
    """Return a deterministic key for one fully effective runtime profile."""
    return json.dumps(profile, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _domain_profile_conflict(
    registrable_domain: str,
    host: str,
    source_ids: tuple[str, ...],
    reason: str,
) -> ValueError:
    """Describe conflicting enabled-stage behavior for a deduplicated host."""
    return ValueError(
        f"input domain {host!r} under registrable domain {registrable_domain!r} "
        f"appears in sources with {reason}: {', '.join(source_ids)}"
    )
