"""Domain pipeline package.

This package processes host lists in three stages:

1. ``DomainListParser`` extracts and normalizes entries from supported input
   formats, derives the ICANN registrable domain for each entry, and preserves
   the original input token for final text output.
2. ``delegation`` performs the mandatory delegation authority check once
   per compatible registrable domain/resolver profile inside a worker, then
   fans the result out to each host under that root. The check starts with an
   NS query and uses SOA fallback only after NS NODATA. Inputs whose
   registrable domain is not delegated are written to ``output/unactionable/``
   because they are not currently actionable for positive output. Timeout and
   SERVFAIL outcomes are retried and then sent to review without cache writes.
3. ``host_resolution`` and ``ip_location`` are review gates when enabled. Host
   resolution or ip location failures route to review; they do not make an entry
   unactionable. Stable host-resolution and successful usable ip location results are
   cached.
"""

from domain_pipeline.prepare.sources import DomainListParser, ParsedDomainEntry
from domain_pipeline.worker.cache import DelegationHistoryRecord, PipelineCache
from domain_pipeline.worker.delegation import DelegationChecker
from domain_pipeline.worker.host_resolution import HostResolutionChecker
from domain_pipeline.worker.host_resolution import HostResolutionResult
from domain_pipeline.worker.ip_location import (
    IPLocationJSProvider,
    LocationPolicyDecision,
    IPLocationResult,
    IPInfoLiteProvider,
    build_ip_location_provider,
    evaluate_ip_location_policy,
)

__all__ = [
    "DelegationChecker",
    "DomainListParser",
    "HostResolutionChecker",
    "IPLocationJSProvider",
    "LocationPolicyDecision",
    "HostResolutionResult",
    "IPLocationResult",
    "IPInfoLiteProvider",
    "ParsedDomainEntry",
    "PipelineCache",
    "DelegationHistoryRecord",
    "build_ip_location_provider",
    "evaluate_ip_location_policy",
]
