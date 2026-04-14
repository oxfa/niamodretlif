"""Run-scoped async RDAP bootstrap cache."""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, List

from ..checking.domain_checker import DomainChecker

logger = logging.getLogger(__name__)


class AsyncBootstrapCache:
    """Shared in-memory bootstrap cache with refresh locking."""

    def __init__(self, checker: DomainChecker) -> None:
        self._checker = checker
        self._lock = asyncio.Lock()

    async def get_services(self) -> Dict[str, List[str]]:
        """Load and cache authoritative RDAP bootstrap services for this run."""
        logger.debug("Awaiting authoritative RDAP bootstrap services refresh")
        get_bootstrap_services = getattr(self._checker, "_get_bootstrap_services")
        async with self._lock:
            services = await asyncio.to_thread(get_bootstrap_services)
        logger.debug(
            "Loaded authoritative RDAP bootstrap services (%d suffix entries)",
            len(services),
        )
        return services

    async def authoritative_base_url(self, domain: str) -> str | None:
        """Resolve the authoritative RDAP base URL for one domain."""
        await self.get_services()
        authoritative_base_url = getattr(self._checker, "_authoritative_base_url")
        base_url = await asyncio.to_thread(authoritative_base_url, domain)
        logger.debug(
            "Resolved authoritative RDAP base URL for %s -> %s",
            domain,
            base_url or "(none)",
        )
        return base_url
