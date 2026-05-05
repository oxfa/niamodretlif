"""Worker DNS delegation and host-resolution owners."""

from domain_pipeline.worker.dns.lookup import (
    DEFAULT_ECS_FALLBACK_NAMESERVERS,
    QUAD9_ECS_PUBLIC_DNS_NAMESERVERS,
    DelegationResult,
    DomainChecker,
    HostResolutionResult,
    RetryableDNSLookupError,
    delegation_dns_profile,
    dns_resolver_key,
    effective_dns_nameservers,
    effective_dns_resolvers,
    effective_host_resolution_nameservers,
    effective_host_resolution_resolvers,
    host_resolution_dns_profile,
)
from domain_pipeline.worker.dns.result_policy import (
    classify_delegation,
    classify_host_resolution,
    host_resolution_skipped_result_code,
)
from domain_pipeline.worker.dns.constants import SYSTEM_DNS_NAMESERVER
from domain_pipeline.worker.dns.policy import DNSConfigPolicy

__all__ = [
    "DEFAULT_ECS_FALLBACK_NAMESERVERS",
    "QUAD9_ECS_PUBLIC_DNS_NAMESERVERS",
    "DNSConfigPolicy",
    "DelegationResult",
    "DomainChecker",
    "HostResolutionResult",
    "RetryableDNSLookupError",
    "SYSTEM_DNS_NAMESERVER",
    "classify_delegation",
    "classify_host_resolution",
    "delegation_dns_profile",
    "dns_resolver_key",
    "effective_dns_nameservers",
    "effective_dns_resolvers",
    "effective_host_resolution_nameservers",
    "effective_host_resolution_resolvers",
    "host_resolution_dns_profile",
    "host_resolution_skipped_result_code",
]
