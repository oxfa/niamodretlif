"""Shared DNS resolver query mechanics."""

from domain_pipeline.worker.dns_query.constants import SYSTEM_DNS_NAMESERVER
from domain_pipeline.worker.dns_query.lookup import (
    DNSQueryService,
    RetryableDNSLookupError,
    dns_resolver_key,
)
from domain_pipeline.worker.dns_query.policy import DNSConfigPolicy

__all__ = [
    "DNSConfigPolicy",
    "DNSQueryService",
    "RetryableDNSLookupError",
    "SYSTEM_DNS_NAMESERVER",
    "dns_resolver_key",
]
