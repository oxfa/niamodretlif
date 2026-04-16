"""Shared duplicate-output invariant errors."""

from __future__ import annotations

from typing import Any


class DuplicateOutputInvariantError(ValueError):
    """Raised when one runtime or aggregate stage emits duplicate final outputs."""

    def __init__(
        self,
        output_kind: str,
        duplicate_key: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> None:
        self.output_kind = output_kind
        self.duplicate_key = duplicate_key
        self.context = context or {}
        context_summary = ""
        if self.context:
            ordered_parts = ", ".join(
                f"{key}={value}" for key, value in sorted(self.context.items())
            )
            context_summary = f" ({ordered_parts})"
        super().__init__(
            f"duplicate {output_kind} output detected for {duplicate_key!r}{context_summary}"
        )
