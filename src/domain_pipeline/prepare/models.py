"""Prepare-step data models."""

# pylint: disable=too-many-instance-attributes

from __future__ import annotations

import dataclasses
from collections import defaultdict
from typing import Any

from domain_pipeline.prepare.sources.jobs import SourceJob
from domain_pipeline.prepare.sources.parser import ParsedDomainEntry

MANUAL_ADD_SOURCE_ID = "manual_add"


@dataclasses.dataclass(frozen=True)
class PreparedRootPlan:
    """Preparation-time delegation metadata for one registrable domain."""

    registrable_domain: str
    status: str = "pending"


@dataclasses.dataclass(frozen=True)
class PreparedHostEntry:
    """One prepared parsed entry and its source provenance."""

    source_id: str
    source_index: int
    line_index: int
    raw_line: str
    entry: ParsedDomainEntry
    manual_filter_pass: bool = False
    manual_add: bool = False
    source_id_override: str | None = None
    source_input_label_override: str | None = None
    source_ids: tuple[str, ...] = ()
    source_input_labels: tuple[str, ...] = ()


@dataclasses.dataclass
class PreparedInputSet:
    """Prepared entries, root plans, and preparation-owned terminal rows."""

    config: dict[str, Any]
    source_jobs_by_id: dict[str, SourceJob]
    entries_by_source: dict[str, list[PreparedHostEntry]]
    root_plans: dict[str, PreparedRootPlan]
    preparation_review_rows: list[dict[str, Any]]
    preparation_terminal_rows: list[dict[str, Any]]

    def split_entries_for_planning(
        self,
    ) -> tuple[dict[str, list[PreparedHostEntry]], list[PreparedHostEntry]]:
        """Split prepared entries into delegation-root and public-suffix groups."""
        root_entries: dict[str, list[PreparedHostEntry]] = defaultdict(list)
        public_suffix_entries: list[PreparedHostEntry] = []
        for entries in self.entries_by_source.values():
            for entry in entries:
                if (
                    entry.entry.is_public_suffix_input
                    or not entry.entry.registrable_domain
                ):
                    public_suffix_entries.append(entry)
                else:
                    root_entries[entry.entry.registrable_domain].append(entry)
        return dict(root_entries), public_suffix_entries


def root_plan_runtime_payload(plan: PreparedRootPlan) -> dict[str, Any]:
    """Serialize prepared delegation root metadata for worker runtime."""
    return dataclasses.asdict(plan)
