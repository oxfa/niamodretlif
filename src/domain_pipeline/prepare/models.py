"""Prepare-step data models."""

from __future__ import annotations

import dataclasses
from typing import Any

from domain_pipeline.prepare.sources.jobs import SourceJob
from domain_pipeline.prepare.sources.parser import DomainEntry, ParsedSourceFile

MANUALLY_SELECTED_FOR_FILTERED_SOURCE_ID = "manually_selected_for_filtered"
MANUALLY_ADDED_SOURCE_ID = "manually_added"


@dataclasses.dataclass(frozen=True)
class PreparedInputDomainPlan:
    """Effective worker stages and manual routing for one input domain."""

    host: str
    manual_routing: "PreparedManualRouting"
    host_resolution_profile: dict[str, Any] | None = None
    ip_location_profile: dict[str, Any] | None = None


@dataclasses.dataclass(frozen=True)
class PreparedRootPlan:
    """Source-blind worker work beneath one registrable domain."""

    registrable_domain: str
    status: str = "pending"
    delegation_profile: dict[str, Any] = dataclasses.field(default_factory=dict)
    input_domains: dict[str, PreparedInputDomainPlan] = dataclasses.field(
        default_factory=dict
    )

    @property
    def entry_count(self) -> int:
        """Return the unique input-domain count assigned beneath this root."""
        return len(self.input_domains)


@dataclasses.dataclass(frozen=True)
class PreparedManualRouting:
    """Explicit manual-input routing state for a prepared host."""

    manually_selected_for_filtered: bool = False
    manually_added: bool = False


@dataclasses.dataclass
class PreparedInputSet:
    """Prepared entries, root plans, and preparation-owned terminal rows."""

    config: dict[str, Any]
    source_jobs_by_id: dict[str, SourceJob]
    parsed_source_entry_count: int
    entries_by_source: dict[str, list[DomainEntry]]
    manual_routing_by_host: dict[str, PreparedManualRouting]
    root_plans: dict[str, PreparedRootPlan]
    preparation_terminal_rows: list[dict[str, Any]]
    source_ids_by_host: dict[str, tuple[str, ...]] = dataclasses.field(
        default_factory=dict
    )
    manually_added_entries: dict[str, DomainEntry] = dataclasses.field(
        default_factory=dict
    )
    excluded_source_hosts: set[str] = dataclasses.field(default_factory=set)
    parsed_source_files: dict[str, ParsedSourceFile] = dataclasses.field(
        default_factory=dict
    )
