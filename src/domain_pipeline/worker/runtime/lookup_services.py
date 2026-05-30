"""Runtime lookup services for cache-backed worker stages."""

from __future__ import annotations

import dataclasses
import logging
import os
from collections.abc import Callable
from typing import Any

import requests

from domain_pipeline.worker.cache.requests import (
    CacheIdentity,
    CacheTimestamps,
    DelegationCacheWriteRequest,
    HostResolutionCacheWriteRequest,
    IpLocationCacheEvidence,
    IpLocationCacheIdentity,
    IpLocationCacheWriteRequest,
)
from domain_pipeline.worker.cache.repository import utc_now
from domain_pipeline.worker.cache.service import CacheHitSource
from domain_pipeline.routing import IpLocationRoutingPolicy, TerminalRouteTransition
from domain_pipeline.worker.delegation.lookup import DelegationResult
from domain_pipeline.worker.host_resolution.lookup import HostResolutionResult
from domain_pipeline.worker.ip_location.providers import (
    IP_LOCATION_STATUS_CACHE_HIT,
    IPLocationResult,
    build_ip_location_provider,
    evaluate_ip_location_policy,
)
from domain_pipeline.worker.runtime.busy_state import BusyReason, BusyStateRecorder
from domain_pipeline.worker.runtime.results import (
    delegation_result_from_cache_record,
    host_resolution_result_from_cache_record,
    ip_location_result_from_cache_record,
)
from domain_pipeline.worker.runtime.transports import (
    lookup_delegation_async,
    lookup_host_resolution_async,
    lookup_ip_locations_async,
)

logger = logging.getLogger(__name__)
IP_LOCATION_EXPECTED_FAILURES = (requests.RequestException, ValueError)
_NON_CACHEABLE_DELEGATION_STATUSES = frozenset(
    {
        "ns_nxdomain_soa_retry_exhausted",
        "ns_retry_exhausted_soa_absent",
        "ns_retry_exhausted_soa_retry_exhausted",
        "ns_lookup_error",
    }
)


@dataclasses.dataclass(frozen=True)
class IpLocationCachePartition:
    """Cache hits and unique misses for one IP-location lookup."""

    cached_results: dict[str, IPLocationResult]
    missing_ips: list[str]


def _ip_location_provider_token(ip_location_config: dict[str, Any]) -> str:
    """Return runtime-only IP-location token without persisting environment secrets."""
    config_token = str(ip_location_config.get("token", "")).strip()
    if config_token:
        logger.debug("IpLocation provider token source=config")
        return config_token
    env_token = os.environ.get("IP_LOCATION_IPINFO_TOKEN", "").strip()
    logger.debug(
        "IpLocation provider token source=%s",
        "IP_LOCATION_IPINFO_TOKEN" if env_token else "empty",
    )
    return env_token


class RuntimeDNSCacheLookupService:
    """Own cache-backed delegation and host-resolution lookup operations."""

    def __init__(
        self,
        *,
        config: dict[str, Any],
        cache_resources: Any,
        dns_executors: Any,
        busy_state: BusyStateRecorder,
    ) -> None:
        self.config = config
        self.cache_resources = cache_resources
        self.dns_executors = dns_executors
        self.busy_state = busy_state

    async def lookup_delegation_root_once(
        self,
        *,
        checker: Any,
        registrable_domain: str,
        resolver_key: str,
    ) -> DelegationResult:
        """Run or cache-read one root-level delegation lookup."""
        now = utc_now()
        async with self.busy_state.track(BusyReason.CACHE_READ):
            cached, source = (
                await self.cache_resources.reader.get_fresh_delegation_with_source(
                    registrable_domain, resolver_key, now
                )
            )
        if cached is not None:
            cached_result = delegation_result_from_cache_record(cached)
            self._record_cache_hit("delegation", source)
            return cached_result
        self._record_cache_miss("delegation")
        async with self.busy_state.track(BusyReason.LIVE_DNS):
            result = await lookup_delegation_async(
                checker,
                registrable_domain,
                executor=self.dns_executors.delegation,
            )
        if result.status in _NON_CACHEABLE_DELEGATION_STATUSES:
            return result
        ttl_config = self.config["cache"]["delegation_ttl_days"]
        ttl_days = (
            int(ttl_config["actionable"])
            if result.actionable
            else int(ttl_config["unactionable"])
        )
        async with self.busy_state.track(BusyReason.CACHE_WRITE_QUEUE_PUT):
            await self.cache_resources.bundle.writers[0].enqueue(
                DelegationCacheWriteRequest(
                    identity=CacheIdentity(
                        name=result.domain,
                        resolver_key=resolver_key,
                    ),
                    dns=result.dns,
                    soa=result.soa,
                    no_nameservers=result.no_nameservers,
                    nameservers=result.nameservers,
                    timestamps=CacheTimestamps(checked_at=now, ttl_days=ttl_days),
                )
            )
        return result

    async def lookup_host_resolution(
        self,
        *,
        checker: Any,
        host: str,
        resolver_key: str,
    ) -> HostResolutionResult:
        """Run or cache-read one host-resolution lookup."""
        now = utc_now()
        async with self.busy_state.track(BusyReason.CACHE_READ):
            cached, source = (
                await self.cache_resources.reader.get_fresh_host_resolution_with_source(
                    host, resolver_key, now
                )
            )
        if cached is not None:
            cached_result = host_resolution_result_from_cache_record(cached)
            if cached_result.status != "unknown":
                self._record_cache_hit("host_resolution", source)
                return cached_result
            logger.debug(
                "Ignoring host-resolution cache row for %s with unknown status",
                host,
            )
        self._record_cache_miss("host_resolution")
        async with self.busy_state.track(BusyReason.LIVE_DNS):
            result = await lookup_host_resolution_async(
                checker,
                host,
                executor=self.dns_executors.host_resolution,
            )
        if result.status in {"timeout", "servfail", "unknown"}:
            return result
        ttl_days = self._host_resolution_ttl_days(result)
        if ttl_days <= 0:
            return result
        async with self.busy_state.track(BusyReason.CACHE_WRITE_QUEUE_PUT):
            await self.cache_resources.bundle.writers[1].enqueue(
                HostResolutionCacheWriteRequest(
                    identity=CacheIdentity(
                        name=result.host,
                        resolver_key=resolver_key,
                    ),
                    dns=result.dns,
                    addresses=result.addresses,
                    timestamps=CacheTimestamps(checked_at=now, ttl_days=ttl_days),
                )
            )
        return result

    def _host_resolution_ttl_days(self, result: HostResolutionResult) -> int:
        """Return cache retention for one stable host-resolution outcome."""
        ttl_config = self.config["cache"].get("host_resolution_ttl_days", {})
        return int(ttl_config.get(result.status, 1))

    def _record_cache_hit(self, prefix: str, source: CacheHitSource | None) -> None:
        """Record cache hit counters, including overlay/baseline source."""
        self.cache_resources.stats[f"{prefix}_cache_hits"] += 1
        if source is not None:
            self.cache_resources.stats[f"{prefix}_{source}_cache_hits"] += 1

    def _record_cache_miss(self, prefix: str) -> None:
        """Record cache misses for one cache family."""
        self.cache_resources.stats[f"{prefix}_cache_misses"] += 1


class RuntimeIpLocationService:
    """Own cache-backed IP-location lookup and policy evaluation."""

    def __init__(
        self,
        *,
        cache_resources: Any,
        provider_builder: Callable[..., Any] = build_ip_location_provider,
    ) -> None:
        self.cache_resources = cache_resources
        self.provider_builder = provider_builder

    async def lookup_ip_location(
        self,
        *,
        ip_location_config: dict[str, Any],
        host_resolution_result: HostResolutionResult,
    ) -> tuple[TerminalRouteTransition, list[IPLocationResult], Any | None]:
        """Run or cache-read the optional IP-location stage and evaluate its policy."""
        provider_name = str(ip_location_config.get("effective_provider", ""))
        now = utc_now()
        cache_partition = await self._partition_ip_location_cache(
            provider_name=provider_name,
            ips=host_resolution_result.resolved_ips,
            checked_at=now,
        )
        results: list[IPLocationResult] = []
        try:
            fetched_results = await self.fetch_missing_ips(
                provider_name=provider_name,
                ip_location_config=ip_location_config,
                missing_ips=cache_partition.missing_ips,
            )
            await self._queue_ip_location_cache_writes(
                provider_name=provider_name,
                ip_location_config=ip_location_config,
                checked_at=now,
                fetched_results=fetched_results,
            )
            fetched_by_ip = {result.ip: result for result in fetched_results}
            results = [
                (
                    cache_partition.cached_results[ip]
                    if ip in cache_partition.cached_results
                    else fetched_by_ip[ip]
                )
                for ip in host_resolution_result.resolved_ips
                if ip in cache_partition.cached_results or ip in fetched_by_ip
            ]
            policy = evaluate_ip_location_policy(results, ip_location_config["policy"])
        except IP_LOCATION_EXPECTED_FAILURES as exc:
            logger.warning(
                "IpLocation lookup failed for %s: %s", host_resolution_result.host, exc
            )
            return IpLocationRoutingPolicy().lookup_failed(), results, None
        return (
            IpLocationRoutingPolicy().for_policy(
                policy,
                results,
                ip_location_config["policy"],
            ),
            results,
            policy,
        )

    async def _partition_ip_location_cache(
        self,
        *,
        provider_name: str,
        ips: list[str],
        checked_at: Any,
    ) -> IpLocationCachePartition:
        cached_results: dict[str, IPLocationResult] = {}
        missing_ips: list[str] = []
        seen_missing_ips: set[str] = set()
        for ip in ips:
            cached, source = (
                await self.cache_resources.reader.get_fresh_ip_location_with_source(
                    provider_name, ip, checked_at
                )
            )
            if cached is not None:
                self._record_cache_hit("ip_location", source)
                cached_results[ip] = ip_location_result_from_cache_record(cached)
                continue
            if ip not in seen_missing_ips:
                self.cache_resources.stats["ip_location_cache_misses"] += 1
                missing_ips.append(ip)
                seen_missing_ips.add(ip)
        return IpLocationCachePartition(
            cached_results=cached_results,
            missing_ips=missing_ips,
        )

    async def fetch_missing_ips(
        self,
        *,
        provider_name: str,
        ip_location_config: dict[str, Any],
        missing_ips: list[str],
    ) -> list[IPLocationResult]:
        """Fetch IP-location rows for cache misses through the configured provider."""
        if not missing_ips:
            return []
        provider = self.provider_builder(
            provider_name,
            timeout=float(ip_location_config.get("timeout", 5.0)),
            token=_ip_location_provider_token(ip_location_config),
        )
        return await lookup_ip_locations_async(provider, missing_ips)

    async def _queue_ip_location_cache_writes(
        self,
        *,
        provider_name: str,
        ip_location_config: dict[str, Any],
        checked_at: Any,
        fetched_results: list[IPLocationResult],
    ) -> None:
        for result in fetched_results:
            if not result.usable or result.status == IP_LOCATION_STATUS_CACHE_HIT:
                continue
            await self.cache_resources.bundle.writers[2].enqueue(
                IpLocationCacheWriteRequest(
                    identity=IpLocationCacheIdentity(
                        provider=provider_name,
                        ip=result.ip,
                    ),
                    evidence=IpLocationCacheEvidence(
                        country_code=result.country_code,
                        region_code=result.region_code,
                        region_name=result.region_name,
                    ),
                    timestamps=CacheTimestamps(
                        checked_at=checked_at,
                        ttl_days=int(ip_location_config.get("cache_ttl_days", 7)),
                    ),
                )
            )

    def _record_cache_hit(self, prefix: str, source: CacheHitSource | None) -> None:
        """Record cache hit counters, including overlay/baseline source."""
        self.cache_resources.stats[f"{prefix}_cache_hits"] += 1
        if source is not None:
            self.cache_resources.stats[f"{prefix}_{source}_cache_hits"] += 1
