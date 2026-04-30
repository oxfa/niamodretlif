"""Async transport wrappers for DNS and geo lookups."""

from __future__ import annotations

import asyncio
import logging

from ..checking import (
    DelegationResult,
    DomainChecker,
    HostResolutionResult,
    IPGeoProvider,
    IPGeoResult,
)

logger = logging.getLogger(__name__)


class AsyncDelegationTransport:
    """Async wrapper around mandatory NS delegation lookups."""

    def __init__(self, checker: DomainChecker) -> None:
        self.checker = checker

    async def lookup(self, domain: str) -> DelegationResult:
        """Resolve one delegation result on a worker thread."""
        logger.debug("Dispatching async delegation lookup for %s", domain)
        return await asyncio.to_thread(self.checker.delegation_lookup, domain)


class AsyncHostResolutionTransport:
    """Async wrapper around optional host-resolution lookups."""

    def __init__(self, checker: DomainChecker) -> None:
        self.checker = checker

    async def lookup(self, host: str) -> HostResolutionResult:
        """Resolve one dns.host_resolution result on a worker thread."""
        logger.debug("Dispatching async host resolution lookup for %s", host)
        return await asyncio.to_thread(self.checker.host_resolution_lookup, host)


AsyncDNSTransport = AsyncHostResolutionTransport
"""Backward-compatible alias for the host-resolution transport."""


class AsyncGeoTransport:
    """Async wrapper around IP geolocation providers."""

    def __init__(self, provider: IPGeoProvider) -> None:
        self.provider = provider

    async def lookup_ips(self, ips: list[str]) -> list[IPGeoResult]:
        """Resolve geolocation for multiple IPs on a worker thread."""
        return await asyncio.to_thread(self.provider.lookup_ips, ips)
