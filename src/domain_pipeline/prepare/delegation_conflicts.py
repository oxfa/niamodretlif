"""Shared messages for delegation-root planning conflicts."""

from __future__ import annotations

from collections.abc import Iterable


def conflicting_delegation_behavior_message(
    registrable_domain: str,
    source_id_values: Iterable[str],
) -> str:
    """Return the validation message for conflicting root delegation behavior."""
    conflicting_sources = ", ".join(sorted(source_id_values))
    return (
        f"registrable domain {registrable_domain!r} appears in sources with "
        f"different delegation DNS behavior: {conflicting_sources}"
    )
