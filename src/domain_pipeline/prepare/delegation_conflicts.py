"""Shared messages for delegation-root planning conflicts."""

from __future__ import annotations

from collections.abc import Iterable


def conflicting_delegation_behavior_message(
    registrable_domain: str,
    source_ids: Iterable[str],
) -> str:
    """Return the validation message for conflicting root delegation behavior."""
    conflicting_sources = ", ".join(sorted(source_ids))
    return (
        f"registrable domain {registrable_domain!r} appears in sources with "
        f"different delegation DNS behavior: {conflicting_sources}"
    )
