"""Domain pipeline package.

This package processes host lists in three stages:

1. ``DomainListParser`` extracts and normalizes exact hosts from supported
   input formats, derives the registrable domain for each host, and removes
   duplicates within the current input.
2. RDAP is consulted only at the registrable-domain level to decide whether a
   registrable domain is unregistered. When a registrable domain is proven
   unregistered, that domain and every input host under it are written to the
   dedicated ``output/dead/`` host list instead of continuing through DNS and
   geo checks.
3. Hosts under registrable domains that are not proven unregistered either
   continue through exact-host DNS checks and optional IP geo policy
   evaluation, or emit directly from the RDAP stage when DNS is disabled in
   config.

The convenience function ``classify`` exposes the lower-level checker logic for
single-host workflows. The repository test suite under ``tests/`` contains
examples that mock RDAP, DNS, and geo responses.
"""

from .checking import (
    DomainChecker,
    GeoJSProvider,
    GeoPolicyDecision,
    IPGeoResult,
    IPInfoLiteProvider,
    build_geo_provider,
    classify,
    evaluate_geo_policy,
)
from .io.parser import DomainListParser, ParsedDomainEntry
from .runtime.history import PipelineCache, RootDomainClassificationRecord

__all__ = [
    "DomainChecker",
    "classify",
    "DomainListParser",
    "GeoJSProvider",
    "GeoPolicyDecision",
    "IPGeoResult",
    "IPInfoLiteProvider",
    "ParsedDomainEntry",
    "PipelineCache",
    "RootDomainClassificationRecord",
    "build_geo_provider",
    "evaluate_geo_policy",
]
