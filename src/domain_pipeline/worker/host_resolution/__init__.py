"""Worker host-resolution stage owner."""

from domain_pipeline.worker.dns_query.lookup import RetryableDNSLookupError
from domain_pipeline.worker.host_resolution.lookup import (
    CNAME_CHAIN_LIMIT,
    DEFAULT_ECS_FALLBACK_NAMESERVERS,
    QUAD9_ECS_PUBLIC_DNS_NAMESERVERS,
    HostResolutionChecker,
    HostResolutionResult,
    effective_host_resolution_resolvers,
    host_resolution_dns_profile,
)

__all__ = [
    "CNAME_CHAIN_LIMIT",
    "DEFAULT_ECS_FALLBACK_NAMESERVERS",
    "QUAD9_ECS_PUBLIC_DNS_NAMESERVERS",
    "HostResolutionChecker",
    "HostResolutionResult",
    "RetryableDNSLookupError",
    "effective_host_resolution_resolvers",
    "host_resolution_dns_profile",
]
