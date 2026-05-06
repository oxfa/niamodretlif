"""Domain pipeline package.

This package processes host lists in three stages:

1. ``DomainListParser`` extracts and normalizes entries from supported input
   formats, derives the ICANN registrable domain for each entry, and preserves
   the original input token for final text output.
2. ``dns.delegation`` performs the mandatory NS lookup once per compatible
   registrable domain/resolver profile inside a worker, then fans the result out
   to each host under that root. Inputs whose registrable domain is not
   delegated are written to ``output/unactionable/`` because they are not
   currently actionable for positive output. Timeout and SERVFAIL outcomes are
   retried and then sent to review without cache writes.
3. ``dns.host_resolution`` and ``geo`` are review gates when enabled. Host
   resolution or geo failures route to review; they do not make an entry
   unactionable. Stable host DNS and successful usable geo results are cached.
"""

from domain_pipeline.prepare.sources import DomainListParser, ParsedDomainEntry
from domain_pipeline.worker.cache import DelegationHistoryRecord, PipelineCache
from domain_pipeline.worker.dns import (
    DomainChecker,
    HostResolutionResult,
)
from domain_pipeline.worker.geo import (
    GeoJSProvider,
    GeoPolicyDecision,
    IPGeoResult,
    IPInfoLiteProvider,
    build_geo_provider,
    evaluate_geo_policy,
)

__all__ = [
    "DomainChecker",
    "DomainListParser",
    "GeoJSProvider",
    "GeoPolicyDecision",
    "HostResolutionResult",
    "IPGeoResult",
    "IPInfoLiteProvider",
    "ParsedDomainEntry",
    "PipelineCache",
    "DelegationHistoryRecord",
    "build_geo_provider",
    "evaluate_geo_policy",
]
