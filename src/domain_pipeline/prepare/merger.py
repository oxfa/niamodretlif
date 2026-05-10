"""Prepare-step duplicate-host merge behavior."""

from __future__ import annotations

import dataclasses

from domain_pipeline.prepare.models import PreparedHostEntry


class PreparedEntryMerger:
    """Merge same-host prepared entries while preserving source provenance."""

    def stable_unique_merge(
        self, first: tuple[str, ...], second: tuple[str, ...]
    ) -> tuple[str, ...]:
        """Return first-seen unique values from two provenance tuples."""
        merged: list[str] = []
        seen: set[str] = set()
        for value in (*first, *second):
            if value in seen:
                continue
            seen.add(value)
            merged.append(value)
        return tuple(merged)

    def merge_entries(
        self, current: PreparedHostEntry, incoming: PreparedHostEntry
    ) -> PreparedHostEntry:
        """Merge same-host prepared entries while preserving earliest ordering."""
        provenance = dataclasses.replace(
            current.provenance,
            manual_filter_pass=(
                current.provenance.manual_filter_pass
                or incoming.provenance.manual_filter_pass
            ),
            manual_add=current.provenance.manual_add or incoming.provenance.manual_add,
            source_ids=self.stable_unique_merge(
                current.provenance.source_ids, incoming.provenance.source_ids
            ),
            source_input_labels=self.stable_unique_merge(
                current.provenance.source_input_labels,
                incoming.provenance.source_input_labels,
            ),
        )
        return dataclasses.replace(
            current,
            provenance=provenance,
        )

    def merge_entry_by_host(
        self,
        entries_by_host: dict[str, PreparedHostEntry],
        incoming: PreparedHostEntry,
    ) -> None:
        """Insert or merge one prepared entry by final output host."""
        host = incoming.entry.host
        current = entries_by_host.get(host)
        if current is None:
            entries_by_host[host] = incoming
            return
        entries_by_host[host] = self.merge_entries(current, incoming)
