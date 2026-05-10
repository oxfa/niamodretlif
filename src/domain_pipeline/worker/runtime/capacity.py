"""Adaptive runtime DNS capacity discovery."""

from __future__ import annotations

import dataclasses
from typing import Any

from domain_pipeline.worker.delegation.lookup import delegation_stage_dns_profile
from domain_pipeline.worker.dns_query.lookup import dns_query_coordinator_config
from domain_pipeline.worker.host_resolution.lookup import host_resolution_dns_profile
from domain_pipeline.worker.dns_query.query_coordinator import (
    DNSProviderCapacitySnapshot,
    DNSProviderRateLimit,
    provider_for_nameserver,
)
from domain_pipeline.worker.runtime.adaptive import AdaptiveDNSPressureState
from domain_pipeline.worker.runtime.loading import RuntimeItemLoader


@dataclasses.dataclass(frozen=True, order=True)
class DNSStageCapacityGroup:
    """One provider-policy group that can constrain worker-local DNS capacity."""

    provider: str
    qps_per_worker: float
    burst: int
    max_pending: int


@dataclasses.dataclass(frozen=True)
class RuntimeDNSCapacityGroups:
    """Provider-policy groups used by adaptive delegation and host resolution."""

    delegation: tuple[DNSStageCapacityGroup, ...]
    host_resolution: tuple[DNSStageCapacityGroup, ...]


def _stage_capacity_groups(
    dns_profile: dict[str, Any],
) -> tuple[DNSStageCapacityGroup, ...]:
    """Return deduped provider-policy groups for one DNS stage profile."""
    query_config = dns_query_coordinator_config(
        query_rate_limit=dns_profile.get("query_rate_limit", {})
    )
    if not query_config.rate_limit_enabled:
        return ()
    resolvers = list(dns_profile.get("resolvers") or [None])
    groups: set[DNSStageCapacityGroup] = set()
    for resolver in resolvers:
        provider = provider_for_nameserver(None if resolver is None else str(resolver))
        limit = query_config.provider_limits.get(provider)
        if limit is None:
            continue
        groups.add(_capacity_group(provider, limit))
    return tuple(sorted(groups))


def _capacity_group(
    provider: str, limit: DNSProviderRateLimit
) -> DNSStageCapacityGroup:
    """Return one immutable provider-policy capacity group."""
    return DNSStageCapacityGroup(
        provider=provider,
        qps_per_worker=float(limit.qps_per_worker),
        burst=int(limit.burst),
        max_pending=int(limit.max_pending),
    )


def discover_dns_capacity_groups(
    loader: RuntimeItemLoader,
) -> RuntimeDNSCapacityGroups:
    """Discover adaptive DNS capacity groups from runtime source contexts."""
    delegation_groups: set[DNSStageCapacityGroup] = set()
    host_resolution_groups: set[DNSStageCapacityGroup] = set()
    for source_context in loader.source_contexts():
        dns_config = {
            **dict(source_context.config["dns_query"]),
            "delegation": dict(source_context.config["delegation"]),
            "host_resolution": dict(source_context.config["host_resolution"]),
        }
        delegation_groups.update(
            _stage_capacity_groups(delegation_stage_dns_profile(dns_config))
        )
        host_config = dict(source_context.config["host_resolution"])
        if not host_config.get("enabled", False):
            continue
        host_resolution_groups.update(
            _stage_capacity_groups(host_resolution_dns_profile(dns_config))
        )
    return RuntimeDNSCapacityGroups(
        delegation=tuple(sorted(delegation_groups)),
        host_resolution=tuple(sorted(host_resolution_groups)),
    )


def capacity_state_for_groups(
    groups: tuple[DNSStageCapacityGroup, ...],
    snapshots: tuple[DNSProviderCapacitySnapshot, ...],
) -> AdaptiveDNSPressureState:
    """Return capacity state for one stage's provider-policy groups."""
    if not groups:
        return AdaptiveDNSPressureState(summary="unlimited")
    matched_snapshots = tuple(
        snapshot
        for snapshot in snapshots
        if any(_snapshot_matches_capacity_group(snapshot, group) for group in groups)
    )
    if not matched_snapshots:
        return AdaptiveDNSPressureState(summary="no_provider_snapshots")
    return AdaptiveDNSPressureState(
        recent_pressure=any(snapshot.recent_pressure for snapshot in matched_snapshots),
        capacity_available=all(
            (snapshot.available_tokens is None or snapshot.available_tokens >= 1.0)
            and (snapshot.pending_available is None or snapshot.pending_available > 0)
            for snapshot in matched_snapshots
        ),
        summary=",".join(
            _capacity_snapshot_summary(snapshot) for snapshot in matched_snapshots
        ),
    )


def _snapshot_matches_capacity_group(
    snapshot: DNSProviderCapacitySnapshot, group: DNSStageCapacityGroup
) -> bool:
    """Return whether a provider snapshot belongs to one stage capacity group."""
    return (
        snapshot.provider == group.provider
        and snapshot.qps_per_worker == group.qps_per_worker
        and snapshot.burst == group.burst
        and snapshot.max_pending == group.max_pending
    )


def _capacity_snapshot_summary(snapshot: DNSProviderCapacitySnapshot) -> str:
    """Return compact operator text for one provider capacity snapshot."""
    tokens = (
        "unlimited"
        if snapshot.available_tokens is None
        else f"{snapshot.available_tokens:.3f}"
    )
    pending = (
        "unlimited"
        if snapshot.pending_available is None
        else str(snapshot.pending_available)
    )
    return (
        f"{snapshot.provider}:tokens={tokens}:pending={pending}:"
        f"pressure={snapshot.recent_pressure}"
    )
