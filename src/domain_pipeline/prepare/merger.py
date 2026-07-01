"""Prepare-step duplicate-host merge behavior."""

from __future__ import annotations

import dataclasses

from domain_pipeline.prepare.models import PreparedHostEntry


def prepared_entry_merge_key(entry: PreparedHostEntry) -> str:
    """Return the duplicate-collapse key for one prepared entry."""
    semantics = entry.entry.semantics
    return "\0".join(
        (
            entry.entry.host,
            semantics.input_kind,
            semantics.apex_scope,
        )
    )


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
            manually_selected_for_filtered=(
                current.provenance.manually_selected_for_filtered
                or incoming.provenance.manually_selected_for_filtered
            ),
            manually_added=(
                current.provenance.manually_added or incoming.provenance.manually_added
            ),
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
        """Insert or merge one prepared entry by host and input semantics."""
        key = prepared_entry_merge_key(incoming)
        current = entries_by_host.get(key)
        if current is None:
            entries_by_host[key] = incoming
            return
        entries_by_host[key] = self.merge_entries(current, incoming)
