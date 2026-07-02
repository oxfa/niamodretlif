"""Prepare-step data models."""

from __future__ import annotations

import dataclasses
from collections import defaultdict
from typing import Any

from domain_pipeline.prepare.sources.jobs import SourceJob
from domain_pipeline.prepare.sources.parser import DomainEntry

MANUALLY_SELECTED_FOR_FILTERED_SOURCE_ID = "manually_selected_for_filtered"
MANUALLY_ADDED_SOURCE_ID = "manually_added"


@dataclasses.dataclass(frozen=True)
class PreparedRootPlan:
    """Preparation-time delegation metadata for one registrable domain."""

    registrable_domain: str
    status: str = "pending"
    entry_count: int = 0
    delegation_config_source_id: str = ""
    delegation_behavior_fingerprint: str = ""


@dataclasses.dataclass(frozen=True)
class PreparedManualRouting:
    """Explicit manual-input routing state for a prepared host."""

    manually_selected_for_filtered: bool = False
    manually_added: bool = False
    output_source_id: str | None = None
    output_source_input_label: str | None = None


@dataclasses.dataclass(frozen=True)
class PreparedOutputRows:
    """Prepare-owned output rows emitted before worker runtime."""

    review_rows: list[dict[str, Any]]
    terminal_rows: list[dict[str, Any]]


@dataclasses.dataclass
class PreparedInputSet:
    """Prepared entries, root plans, and preparation-owned terminal rows."""

    config: dict[str, Any]
    source_jobs_by_id: dict[str, SourceJob]
    parsed_source_entry_count: int
    entries_by_source: dict[str, list[DomainEntry]]
    manual_routing_by_host: dict[str, PreparedManualRouting]
    root_plans: dict[str, PreparedRootPlan]
    preparation_outputs: PreparedOutputRows

    @property
    def preparation_review_rows(self) -> list[dict[str, Any]]:
        """Return prepare-owned review rows."""
        return self.preparation_outputs.review_rows

    @property
    def preparation_terminal_rows(self) -> list[dict[str, Any]]:
        """Return prepare-owned terminal rows."""
        return self.preparation_outputs.terminal_rows

    def split_entries_for_planning(
        self,
    ) -> tuple[dict[str, list[tuple[str, DomainEntry]]], list[tuple[str, DomainEntry]]]:
        """Split prepared entries into delegation-root and public-suffix groups."""
        root_entries: dict[str, list[tuple[str, DomainEntry]]] = defaultdict(list)
        public_suffix_entries: list[tuple[str, DomainEntry]] = []
        for source_id, entries in self.entries_by_source.items():
            for entry in entries:
                if entry.registrable_domain is None:
                    public_suffix_entries.append((source_id, entry))
                else:
                    root_entries[entry.registrable_domain].append((source_id, entry))
        return dict(root_entries), public_suffix_entries
