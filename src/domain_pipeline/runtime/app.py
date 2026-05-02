"""Top-level orchestration helpers for the workflow-owned async runtime."""

from __future__ import annotations

import asyncio
import logging
from collections import Counter
from pathlib import Path
from typing import Any

from .async_pipeline import run_prepared_pipeline_async

log = logging.getLogger(__name__)


def run_prepared_pipeline(
    runtime_config: dict[str, Any],
    *,
    runtime_identity: dict[str, str],
    max_runtime_seconds: float | None = None,
    prepared_metadata: dict[str, Any] | None = None,
    effective_parallel_workers: int = 1,
) -> int:
    """Run one workflow-owned runtime payload from a prepared automation manifest."""
    try:
        return asyncio.run(
            run_prepared_pipeline_async(
                runtime_config,
                runtime_identity=runtime_identity,
                max_runtime_seconds=max_runtime_seconds,
                prepared_metadata=prepared_metadata,
                effective_parallel_workers=effective_parallel_workers,
            )
        )
    except ValueError as exc:
        log.error("%s", exc)
        return 2


def _log_run_summary(
    elapsed: float,
    counts: Counter,
    cache_stats: Counter,
    cache_file: Path,
    output_paths: list[Path],
) -> None:
    """Backward-compatible summary helper retained for the existing test surface."""
    log.info("========================================")
    log.info("Pipeline complete in %.1fs", elapsed)
    if not cache_file.is_file():
        raise RuntimeError(f"expected cache database was not created: {cache_file}")
    log.info("  Cache file: %s (%d bytes)", cache_file, cache_file.stat().st_size)
    existing_output_paths = [path for path in output_paths if path.is_file()]
    if not existing_output_paths:
        raise RuntimeError("no output files were created")
    for output_path in existing_output_paths:
        with output_path.open("r", encoding="utf-8") as handle:
            line_count = sum(1 for _ in handle)
        log.info(
            "  Output file: %s (%d lines, %d bytes)",
            output_path,
            line_count,
            output_path.stat().st_size,
        )
    emitted_hosts = counts.get("route_filtered", 0)
    review_hosts = counts.get("route_review", 0)
    unactionable_hosts = counts.get("route_unactionable", 0)
    log.info(
        "  Total input hosts: %d",
        emitted_hosts + review_hosts + unactionable_hosts,
    )
    log.info("  Hosts emitted to filtered output: %d", emitted_hosts)
    log.info("  Hosts routed to review: %d", review_hosts)
    log.info(
        "  Hosts written to output/unactionable after failed delegation: %d",
        unactionable_hosts,
    )
    log.info("  Cache writes: %d", cache_stats.get("cached_written", 0))
    log.info("  Cache refreshes: %d", cache_stats.get("cached_refreshed", 0))
    log.info("  Cache clears: %d", cache_stats.get("cache_cleared", 0))
    log.info(
        "  Delegation cache hits: %d",
        cache_stats.get("delegation_cache_hits", 0),
    )
    log.info(
        "  Delegation cache misses: %d",
        cache_stats.get("delegation_cache_misses", 0),
    )
    log.info(
        "  Delegation overlay cache hits: %d",
        cache_stats.get("delegation_overlay_cache_hits", 0),
    )
    log.info(
        "  Delegation baseline cache hits: %d",
        cache_stats.get("delegation_baseline_cache_hits", 0),
    )
    log.info(
        "  Host-resolution cache hits: %d",
        cache_stats.get("host_resolution_cache_hits", 0),
    )
    log.info(
        "  Host-resolution cache misses: %d",
        cache_stats.get("host_resolution_cache_misses", 0),
    )
    log.info(
        "  Host-resolution overlay cache hits: %d",
        cache_stats.get("host_resolution_overlay_cache_hits", 0),
    )
    log.info(
        "  Host-resolution baseline cache hits: %d",
        cache_stats.get("host_resolution_baseline_cache_hits", 0),
    )
    log.info("  Geo cache hits: %d", cache_stats.get("geo_cache_hits", 0))
    log.info("  Geo cache misses: %d", cache_stats.get("geo_cache_misses", 0))
    log.info(
        "  Geo overlay cache hits: %d",
        cache_stats.get("geo_overlay_cache_hits", 0),
    )
    log.info(
        "  Geo baseline cache hits: %d",
        cache_stats.get("geo_baseline_cache_hits", 0),
    )
    log.info(
        "  geo_policy_decision_accepted %d",
        counts.get("geo_policy_decision_accepted", 0),
    )
