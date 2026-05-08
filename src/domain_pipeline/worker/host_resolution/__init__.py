"""Worker host-resolution stage owner."""

from domain_pipeline.worker.dns_query import RetryableDNSLookupError
from domain_pipeline.worker.host_resolution.lookup import (
    CNAME_CHAIN_LIMIT,
    DEFAULT_ECS_FALLBACK_NAMESERVERS,
    QUAD9_ECS_PUBLIC_DNS_NAMESERVERS,
    HostResolutionChecker,
    HostResolutionResult,
    effective_host_resolution_nameservers,
    effective_host_resolution_resolvers,
    host_resolution_dns_profile,
)
from domain_pipeline.worker.host_resolution.result_policy import (
    classify_host_resolution,
    host_resolution_skipped_result_code,
)

__all__ = [
    "DEFAULT_ECS_FALLBACK_NAMESERVERS",
    "CNAME_CHAIN_LIMIT",
    "HostResolutionChecker",
    "HostResolutionResult",
    "QUAD9_ECS_PUBLIC_DNS_NAMESERVERS",
    "RetryableDNSLookupError",
    "classify_host_resolution",
    "effective_host_resolution_nameservers",
    "effective_host_resolution_resolvers",
    "host_resolution_dns_profile",
    "host_resolution_skipped_result_code",
]
