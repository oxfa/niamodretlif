"""Domain pipeline package.

This package processes host lists in three stages:

1. ``DomainListParser`` extracts and normalizes entries from supported input
   formats, derives the ICANN registrable domain for each entry, and preserves
   the original input token for final text output.
2. ``dns.delegation`` performs the mandatory NS lookup for the registrable
   domain. Inputs whose registrable domain is not delegated are written to
   ``output/unactionable/`` because they are not currently actionable for
   positive output. Timeout and SERVFAIL outcomes are retried and then sent to
   review without cache writes.
3. ``dns.host_resolution`` and ``geo`` are review gates when enabled. Host
   resolution or geo failures route to review; they do not make an entry
   unactionable. Stable host DNS and successful usable geo results are cached.
"""

from .checking import (
    DomainChecker,
    GeoJSProvider,
    GeoPolicyDecision,
    HostResolutionResult,
    IPGeoResult,
    IPInfoLiteProvider,
    build_geo_provider,
    classify,
    evaluate_geo_policy,
)
from .io.parser import DomainListParser, ParsedDomainEntry
from .runtime.history import DelegationHistoryRecord, PipelineCache

__all__ = [
    "DomainChecker",
    "classify",
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
