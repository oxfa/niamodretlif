"""Prepare/runtime helpers for delegation-root grouping."""

from __future__ import annotations

import json
from typing import Any

from domain_pipeline.worker.delegation.lookup import delegation_stage_dns_profile
from domain_pipeline.worker.host_resolution.lookup import host_resolution_dns_profile


def delegation_dns_config(source_config: dict[str, Any]) -> dict[str, Any]:
    """Return the shared DNS-query payload plus delegation settings."""
    return {
        **dict(source_config["dns_query"]),
        "delegation": dict(source_config["delegation"]),
    }


def delegation_behavior_payload(source_config: dict[str, Any]) -> dict[str, Any]:
    """Return DNS behavior that affects one live delegation check."""
    dns_config = delegation_dns_config(source_config)
    delegation_config = dict(source_config["delegation"])
    return {
        **delegation_stage_dns_profile(dns_config),
        "retry_attempts": delegation_config["retry_attempts"],
    }


def delegation_behavior_fingerprint(source_config: dict[str, Any]) -> str:
    """Return a deterministic behavior key for delegation root grouping."""
    return json.dumps(
        delegation_behavior_payload(source_config),
        sort_keys=True,
        separators=(",", ":"),
    )


def effective_delegation_profile(source_config: dict[str, Any]) -> dict[str, Any]:
    """Return source-blind, fully resolved DNS settings for one root query."""
    behavior = delegation_behavior_payload(source_config)
    resolver_entries = _resolver_entries(
        behavior["resolvers"], behavior["resolver_weights"]
    )
    return {
        "dns_query": {
            "default_resolvers": resolver_entries,
            "timeout": behavior["timeout"],
            "retry_backoff_base_seconds": behavior[
                "retry_backoff_base_seconds"
            ],
            "query_rate_limit": behavior["query_rate_limit"],
        },
        "delegation": {
            "resolvers": None,
            "timeout": None,
            "query_rate_limit": None,
            "retry_attempts": behavior["retry_attempts"],
        },
    }


def effective_host_resolution_profile(
    source_config: dict[str, Any],
) -> dict[str, Any]:
    """Return source-blind, fully resolved settings for one input domain."""
    dns_config = {
        **dict(source_config["dns_query"]),
        "host_resolution": dict(source_config["host_resolution"]),
    }
    behavior = host_resolution_dns_profile(dns_config)
    host_config = source_config["host_resolution"]
    return {
        "resolvers": _resolver_entries(
            behavior["resolvers"], behavior["resolver_weights"]
        ),
        "timeout": behavior["timeout"],
        "retry_backoff_base_seconds": behavior["retry_backoff_base_seconds"],
        "query_rate_limit": behavior["query_rate_limit"],
        "retry_attempts": host_config["retry_attempts"],
        "ecs": dict(host_config["ecs"]),
        "resolve_www_for_registrable_domain": host_config[
            "resolve_www_for_registrable_domain"
        ],
    }


def effective_ip_location_profile(source_config: dict[str, Any]) -> dict[str, Any]:
    """Return source-blind, credential-free effective IP-location settings."""
    config = source_config["ip_location"]
    return {
        "timeout": config["timeout"],
        "cache_ttl_days": config["cache_ttl_days"],
        "policy": json.loads(json.dumps(config["policy"])),
        "requires_region_lookup": config["requires_region_lookup"],
        "effective_provider": config["effective_provider"],
    }


def _resolver_entries(
    resolvers: list[str], weights: dict[str, int]
) -> list[dict[str, Any]]:
    """Encode effective resolver weights on their normalized resolver entries."""
    entries: list[dict[str, Any]] = []
    for resolver in resolvers:
        entry: dict[str, Any] = {"resolver": resolver}
        weight = weights.get(resolver)
        if weight is not None:
            entry["weight"] = weight
        entries.append(entry)
    return entries
