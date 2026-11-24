"""Tests for the strict DNS resolver-entry configuration contract."""

from __future__ import annotations

import pytest

from domain_pipeline.worker.dns_query.lookup import (
    dns_resolver_entry_values,
    dns_stage_resolver_profile,
)


def test_dns_resolver_entries_require_mapping_shape() -> None:
    """Resolver entries use the normalized object shape from configuration."""
    with pytest.raises(ValueError, match="resolver entries must be mappings"):
        dns_resolver_entry_values(["1.1.1.1"])  # type: ignore[arg-type]


def test_dns_stage_rejects_separate_resolver_weights() -> None:
    """Weights belong on resolver entries, not in a parallel mapping."""
    with pytest.raises(ValueError, match="set weights on resolver entries"):
        dns_stage_resolver_profile(
            {},
            {
                "resolvers": [{"resolver": "1.1.1.1"}],
                "resolver_weights": {"1.1.1.1": 4},
            },
        )


def test_dns_stage_reads_inline_resolver_weights() -> None:
    """The canonical resolver entry retains its configured endpoint weight."""
    assert dns_stage_resolver_profile(
        {},
        {"resolvers": [{"resolver": "1.1.1.1", "weight": 4}]},
    ) == (["1.1.1.1"], {"1.1.1.1": 4})
