"""Async transport wrappers for worker DNS and ip location lookups."""

from __future__ import annotations

import asyncio
from concurrent.futures import Executor
from typing import Any

from domain_pipeline.worker.delegation.lookup import DelegationResult
from domain_pipeline.worker.host_resolution.lookup import HostResolutionResult
from domain_pipeline.worker.ip_location.providers import (
    IPLocationProvider,
    IPLocationResult,
)


async def lookup_delegation_async(
    checker: Any,
    domain: str,
    *,
    executor: Executor | None = None,
) -> DelegationResult:
    """Resolve one delegation result on a worker thread."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(executor, checker.delegation_lookup, domain)


async def lookup_host_resolution_async(
    checker: Any,
    host: str,
    *,
    executor: Executor | None = None,
) -> HostResolutionResult:
    """Resolve one host-resolution result on a worker thread."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(executor, checker.host_resolution_lookup, host)


async def lookup_ip_locations_async(
    provider: IPLocationProvider,
    ips: list[str],
) -> list[IPLocationResult]:
    """Resolve IP location for multiple IPs on a worker thread."""
    return await asyncio.to_thread(provider.lookup_ips, ips)
