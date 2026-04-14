"""Async transport wrappers for RDAP, DNS, and geo lookups."""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from typing import cast

import requests

from ..checking import (
    DNSResult,
    DomainChecker,
    IPGeoProvider,
    IPGeoResult,
    RDAPResult,
    build_geo_provider,
)
from ..checking.ip_geo import GEOJS_BULK_CHUNK_SIZE, IPINFO_LITE_BULK_CHUNK_SIZE
from .bootstrap_async import AsyncBootstrapCache

logger = logging.getLogger(__name__)

BULK_LOOKUP_CHUNK_SIZES = {
    "geojs": GEOJS_BULK_CHUNK_SIZE,
    "ipinfo_lite": IPINFO_LITE_BULK_CHUNK_SIZE,
}


@dataclass
class AsyncRDAPTransport:
    """Async RDAP transport wrapper."""

    checker: DomainChecker
    bootstrap_cache: AsyncBootstrapCache

    async def lookup(
        self, domain: str, *, authoritative_base_url: str | None = None
    ) -> RDAPResult:
        """Resolve one RDAP result on a worker thread."""
        logger.debug("Dispatching async RDAP lookup for %s", domain)
        if (
            getattr(self.checker, "rdap_mode", None)
            == DomainChecker.RDAP_MODE_AUTHORITATIVE
            and authoritative_base_url is None
        ):
            await self.bootstrap_cache.get_services()
        result = await asyncio.to_thread(
            self.checker.rdap_lookup,
            domain,
            authoritative_base_url=authoritative_base_url,
        )
        logger.debug(
            "Async RDAP lookup for %s -> exists=%s statuses=%s from_cache=%s",
            domain,
            result.exists,
            list(result.statuses) or "(none)",
            result.from_cache,
        )
        return result


@dataclass
class AsyncDNSTransport:
    """Async DNS transport wrapper."""

    checker: DomainChecker

    async def lookup(self, host: str) -> DNSResult:
        """Resolve one DNS result on a worker thread."""
        logger.debug("Dispatching async DNS lookup for %s", host)
        result = await asyncio.to_thread(self.checker.dns_lookup, host)
        logger.debug(
            "Async DNS lookup for %s -> status=%s cname=%s ips=%s",
            host,
            result.status,
            result.canonical_name or "(none)",
            result.resolved_ips or "(none)",
        )
        return result


class AsyncGeoTransport:
    """Async geo transport for one runtime-selected provider path."""

    def __init__(
        self,
        configured_provider: IPGeoProvider,
        *,
        timeout: float,
        token: str = "",
    ) -> None:
        self.configured_provider = configured_provider
        self.timeout = timeout
        self.token = token
        self._providers: dict[str, IPGeoProvider] = {
            configured_provider.provider_name: configured_provider,
        }
        self._bulk_batch_locks = {
            provider_name: asyncio.Lock() for provider_name in BULK_LOOKUP_CHUNK_SIZES
        }
        self._pending_bulk_requests: dict[
            str, dict[str, list[asyncio.Future[IPGeoResult]]]
        ] = {provider_name: {} for provider_name in BULK_LOOKUP_CHUNK_SIZES}
        self._bulk_flush_tasks: dict[str, asyncio.Task[None] | None] = {
            provider_name: None for provider_name in BULK_LOOKUP_CHUNK_SIZES
        }

    async def lookup_ip(self, provider_name: str, ip: str) -> IPGeoResult:
        """Resolve one IP through the requested provider on a worker thread."""
        provider = self._provider(provider_name)
        logger.debug(
            "Dispatching async geo lookup for provider=%s ip=%s",
            provider_name,
            ip,
        )
        result = await asyncio.to_thread(provider.lookup_ip, ip)
        logger.debug(
            "Async geo lookup for provider=%s ip=%s -> status=%s country=%s "
            "region_code=%s region_name=%s",
            provider_name,
            ip,
            result.status,
            result.country_code or "(none)",
            result.region_code or "(none)",
            result.region_name or "(none)",
        )
        return result

    async def lookup_ips(self, provider_name: str, ips: list[str]) -> list[IPGeoResult]:
        """Resolve multiple IPs through one provider on a worker thread."""
        provider = self._provider(provider_name)
        logger.debug(
            "Dispatching async bulk geo lookup for provider=%s ips=%s",
            provider_name,
            ips or "(none)",
        )
        if provider_name in BULK_LOOKUP_CHUNK_SIZES:
            return await self._lookup_bulk_provider_ips(provider_name, provider, ips)
        lookup_ips = getattr(provider, "lookup_ips", None)
        if callable(lookup_ips):
            results = cast(list[IPGeoResult], await asyncio.to_thread(lookup_ips, ips))
            logger.debug(
                "Async bulk geo lookup for provider=%s returned %d results",
                provider_name,
                len(results),
            )
            return results
        return [await self.lookup_ip(provider_name, ip) for ip in ips]

    async def _lookup_bulk_provider_ips(
        self, provider_name: str, provider: IPGeoProvider, ips: list[str]
    ) -> list[IPGeoResult]:
        """Coalesce concurrent bulk-provider requests by unique IP."""
        if not ips:
            return []

        loop = asyncio.get_running_loop()
        futures: list[asyncio.Future[IPGeoResult]] = []
        async with self._bulk_batch_locks[provider_name]:
            for ip in ips:
                future: asyncio.Future[IPGeoResult] = loop.create_future()
                self._pending_bulk_requests[provider_name].setdefault(ip, []).append(
                    future
                )
                futures.append(future)
            current_task = self._bulk_flush_tasks[provider_name]
            if current_task is None or current_task.done():
                self._bulk_flush_tasks[provider_name] = asyncio.create_task(
                    self._flush_bulk_provider_batches(provider_name, provider)
                )
            logger.debug(
                "Queued async bulk geo lookup for provider=%s requested_ips=%s "
                "pending_unique_ips=%d",
                provider_name,
                ips,
                len(self._pending_bulk_requests[provider_name]),
            )
        return cast(list[IPGeoResult], await asyncio.gather(*futures))

    async def _flush_bulk_provider_batches(
        self, provider_name: str, provider: IPGeoProvider
    ) -> None:
        """Flush pending provider requests in capped unique-IP batches."""
        chunk_size = BULK_LOOKUP_CHUNK_SIZES[provider_name]
        while True:
            async with self._bulk_batch_locks[provider_name]:
                if not self._pending_bulk_requests[provider_name]:
                    self._bulk_flush_tasks[provider_name] = None
                    return
                pending_ips = list(self._pending_bulk_requests[provider_name])[
                    :chunk_size
                ]
                future_groups = {
                    ip: self._pending_bulk_requests[provider_name].pop(ip)
                    for ip in pending_ips
                }
            logger.debug(
                "Flushing async bulk geo lookup for provider=%s batch_size=%d ips=%s",
                provider_name,
                len(pending_ips),
                pending_ips,
            )

            try:
                results = cast(
                    list[IPGeoResult],
                    await asyncio.to_thread(provider.lookup_ips, pending_ips),
                )
                if len(results) != len(pending_ips):
                    raise ValueError(
                        f"{provider.provider_name} returned {len(results)} geo results "
                        f"for {len(pending_ips)} requested IPs"
                    )
            except (requests.RequestException, ValueError) as exc:
                logger.debug(
                    "Async bulk geo lookup failed for provider=%s ips=%s: %s",
                    provider_name,
                    pending_ips,
                    exc,
                )
                for future_list in future_groups.values():
                    for future in future_list:
                        if not future.done():
                            future.set_exception(exc)
                continue

            logger.debug(
                "Async bulk geo lookup completed for provider=%s batch_size=%d",
                provider_name,
                len(results),
            )
            for ip, result in zip(pending_ips, results):
                for future in future_groups[ip]:
                    if not future.done():
                        future.set_result(result)

    def _provider(self, provider_name: str) -> IPGeoProvider:
        """Return the cached provider instance for one provider name."""
        provider = self._providers.get(provider_name)
        if provider is None:
            logger.debug("Creating async geo provider instance for %s", provider_name)
            provider = build_geo_provider(
                provider_name,
                timeout=self.timeout,
                token=self.token,
            )
            self._providers[provider_name] = provider
        else:
            logger.debug("Reusing async geo provider instance for %s", provider_name)
        return provider


def resolve_geo_token(geo_config: dict[str, object], provider_name: str) -> str:
    """Resolve the provider token from environment first, then config fallback."""
    env_var_by_provider = {
        "ipinfo_lite": "GEO_IPINFO_TOKEN",
        "ip2location_io": "GEO_IP2LOCATION_TOKEN",
    }
    env_var = env_var_by_provider.get(provider_name)
    if env_var is None:
        return str(geo_config.get("token", ""))
    env_value = os.environ.get(env_var, "").strip()
    if env_value:
        return env_value
    config_value = str(geo_config.get("token", "")).strip()
    if config_value:
        return config_value
    raise ValueError(
        f"geo lookup requires {env_var} or geo.token because effective_provider "
        f"resolved to {provider_name}"
    )
