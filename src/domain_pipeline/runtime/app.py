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
) -> int:
    """Run one workflow-owned runtime payload from a prepared automation manifest."""
    try:
        return asyncio.run(
            run_prepared_pipeline_async(
                runtime_config,
                runtime_identity=runtime_identity,
                max_runtime_seconds=max_runtime_seconds,
                prepared_metadata=prepared_metadata,
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
    emitted_hosts = counts.get("routed_normal_output", 0)
    review_hosts = counts.get("routed_review", 0)
    filtered_dead_roots = counts.get("filtered_dead_root", 0)
    log.info(
        "  Total input hosts: %d", emitted_hosts + review_hosts + filtered_dead_roots
    )
    log.info("  Hosts emitted to filtered output: %d", emitted_hosts)
    log.info("  Hosts routed to review: %d", review_hosts)
    log.info(
        "  Hosts written to output/dead after RDAP-unregistered verdict: %d",
        filtered_dead_roots,
    )
    log.info("  Cache writes: %d", cache_stats.get("cached_written", 0))
    log.info("  Cache refreshes: %d", cache_stats.get("cached_refreshed", 0))
    log.info("  Cache clears: %d", cache_stats.get("cache_cleared", 0))
    log.info("  RDAP cache hits: %d", cache_stats.get("rdap_cache_hits", 0))
    log.info("  RDAP cache misses: %d", cache_stats.get("rdap_cache_misses", 0))
    log.info(
        "  RDAP overlay cache hits: %d",
        cache_stats.get("rdap_overlay_cache_hits", 0),
    )
    log.info(
        "  RDAP baseline cache hits: %d",
        cache_stats.get("rdap_baseline_cache_hits", 0),
    )
    log.info("  DNS cache hits: %d", cache_stats.get("dns_cache_hits", 0))
    log.info("  DNS cache misses: %d", cache_stats.get("dns_cache_misses", 0))
    log.info(
        "  DNS overlay cache hits: %d",
        cache_stats.get("dns_overlay_cache_hits", 0),
    )
    log.info(
        "  DNS baseline cache hits: %d",
        cache_stats.get("dns_baseline_cache_hits", 0),
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
