"""Async transport wrappers for worker DNS and ip location lookups."""

from __future__ import annotations

import asyncio
from concurrent.futures import Executor
from typing import Any

from domain_pipeline.worker.delegation import DelegationResult
from domain_pipeline.worker.host_resolution import HostResolutionResult
from domain_pipeline.worker.ip_location import IPLocationProvider, IPLocationResult


class AsyncDelegationTransport:
    """Async wrapper around mandatory delegation authority checks."""

    def __init__(self, checker: Any, *, executor: Executor | None = None) -> None:
        self.checker = checker
        self.executor = executor

    async def lookup(self, domain: str) -> DelegationResult:
        """Resolve one delegation result on a worker thread."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self.executor, self.checker.delegation_lookup, domain
        )


class AsyncHostResolutionTransport:
    """Async wrapper around optional host-resolution lookups."""

    def __init__(self, checker: Any, *, executor: Executor | None = None) -> None:
        self.checker = checker
        self.executor = executor

    async def lookup(self, host: str) -> HostResolutionResult:
        """Resolve one host-resolution result on a worker thread."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self.executor, self.checker.host_resolution_lookup, host
        )


class AsyncIpLocationTransport:
    """Async wrapper around IP location providers."""

    def __init__(self, provider: IPLocationProvider) -> None:
        self.provider = provider

    async def lookup_ips(self, ips: list[str]) -> list[IPLocationResult]:
        """Resolve IP location for multiple IPs on a worker thread."""
        return await asyncio.to_thread(self.provider.lookup_ips, ips)
