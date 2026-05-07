"""Async transport wrappers for worker DNS and geo lookups."""

from __future__ import annotations

import asyncio
from concurrent.futures import Executor
from typing import Any

from domain_pipeline.worker.dns import (
    DelegationResult,
    HostResolutionResult,
)
from domain_pipeline.worker.geo import IPGeoProvider, IPGeoResult


class AsyncDelegationTransport:
    """Async wrapper around mandatory NS delegation lookups."""

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
        """Resolve one dns.host_resolution result on a worker thread."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self.executor, self.checker.host_resolution_lookup, host
        )


class AsyncGeoTransport:
    """Async wrapper around IP geolocation providers."""

    def __init__(self, provider: IPGeoProvider) -> None:
        self.provider = provider

    async def lookup_ips(self, ips: list[str]) -> list[IPGeoResult]:
        """Resolve geolocation for multiple IPs on a worker thread."""
        return await asyncio.to_thread(self.provider.lookup_ips, ips)
