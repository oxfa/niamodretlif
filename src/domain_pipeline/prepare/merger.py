"""Prepare-step duplicate-host merge behavior."""

from __future__ import annotations

from domain_pipeline.prepare.sources.parser import DomainEntry


def prepared_entry_merge_key(entry: DomainEntry) -> str:
    """Return the duplicate-collapse key for one prepared entry."""
    return entry.host


class PreparedEntryMerger:
    """Merge same-host prepared entries while preserving earliest source context."""

    def merge_entries(self, current: DomainEntry, incoming: DomainEntry) -> DomainEntry:
        """Merge same-host prepared entries while preserving earliest ordering."""
        _ = incoming
        return current

    def merge_entry_by_host(
        self,
        entries_by_host: dict[str, DomainEntry],
        incoming: DomainEntry,
    ) -> None:
        """Insert or merge one prepared entry by host."""
        key = prepared_entry_merge_key(incoming)
        current = entries_by_host.get(key)
        if current is None:
            entries_by_host[key] = incoming
            return
        entries_by_host[key] = self.merge_entries(current, incoming)
