"""Compatibility module for the removed registration bootstrap stage."""

from __future__ import annotations


class AsyncBootstrapCache:
    """Placeholder retained so stale imports fail at construction time."""

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise RuntimeError("registration bootstrap is unsupported; use DNS delegation")
