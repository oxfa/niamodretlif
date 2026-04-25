"""Source expansion, RDAP-unregistered-root filtering, host DNS checks, and output writing."""

from __future__ import annotations

# pylint: disable=duplicate-code,too-many-lines

import glob
import ipaddress
import json
import logging
from collections import Counter
from collections import defaultdict, deque
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO, cast

import dns.resolver
import dns.edns
import requests

from domain_pipeline.classifications import (
    CLASSIFICATION_DNS_RESOLVED_WITHOUT_IP_ADDRESSES,
    CLASSIFICATION_DNS_RESOLVES,
    CLASSIFICATION_GEO_LOOKUP_FAILED,
    CLASSIFICATION_GEO_POLICY_REJECTED,
    CLASSIFICATION_GEO_REGION_NAME_UNAVAILABLE,
    CLASSIFICATION_INPUT_PUBLIC_SUFFIX,
    CLASSIFICATION_RDAP_LOOKUP_UNAVAILABLE_DNS_DISABLED,
    CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_REGISTERED_DNS_DISABLED,
    CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED,
    PRE_GEO_REVIEW_CLASSIFICATIONS,
    ROOT_CLASSIFICATION_RDAP_LOOKUP_UNAVAILABLE,
    ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_REGISTERED,
    ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED,
)
from ..checking import (
    CacheableRDAPUnavailableError,
    DNSResult,
    DomainChecker,
    GEO_STATUS_CACHE_HIT,
    GeoPolicyDecision,
    IPGeoProvider,
    IPGeoResult,
    RDAPResult,
    RDAPUnavailableError,
    build_geo_provider,
    evaluate_geo_policy,
)
from ..io.output_manager import (
    dead_output_path_for_job,
    review_output_path_for_job,
    write_review_rows,
)
from ..io.parser import DomainListParser, InputFileFormat, ParsedDomainEntry
from ..shared import SourceJob
from .pure_helpers import (
    ROUTE_DEAD,
    ROUTE_FILTERED,
    ROUTE_REVIEW,
    build_output_row,
    route_for_row,
)
from ..settings.constants import (
    GEO_PROVIDER_GEOJS,
    GEO_PROVIDER_IPINFO_LITE,
)
from .history import PipelineCache
from .transports import resolve_geo_token

log = logging.getLogger(__name__)
GOOGLE_PUBLIC_DNS_NAMESERVERS = [
    "8.8.8.8",
    "8.8.4.4",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
]
QUAD9_ECS_NAMESERVERS = [
    "9.9.9.11",
    "149.112.112.11",
    "2620:fe::11",
    "2620:fe::fe:11",
]
DEFAULT_ECS_FALLBACK_NAMESERVERS = GOOGLE_PUBLIC_DNS_NAMESERVERS
ECS_CAPABLE_PUBLIC_DNS_NAMESERVERS = frozenset(
    str(ipaddress.ip_address(address))
    for address in [*GOOGLE_PUBLIC_DNS_NAMESERVERS, *QUAD9_ECS_NAMESERVERS]
)


def _geo_policy_has_rules(policy: dict[str, Any]) -> bool:
    """Return whether a geo policy has any effective include/exclude rules."""
    include = policy.get("include", {})
    exclude = policy.get("exclude", {})
    return (
        any(include.get("countries", []))
        or any(include.get("regions", []))
        or any(exclude.get("countries", []))
        or any(exclude.get("regions", []))
    )


def _geo_requires_region_lookup(geo_config: dict[str, Any]) -> bool:
    """Return whether one geo config requires region-capable results."""
    policy = cast(dict[str, Any], geo_config.get("policy", {}))
    include = cast(dict[str, Any], policy.get("include", {}))
    exclude = cast(dict[str, Any], policy.get("exclude", {}))
    return bool(include.get("regions", []) or exclude.get("regions", []))


def _effective_geo_provider_name(geo_config: dict[str, Any]) -> str:
    """Return the effective provider for one source geo config."""
    if "effective_provider" in geo_config:
        return str(geo_config["effective_provider"])
    if _geo_requires_region_lookup(geo_config):
        return GEO_PROVIDER_GEOJS
    return GEO_PROVIDER_IPINFO_LITE


def read_text_lines(path: Path) -> list[str]:
    """Read UTF-8 text lines from a local file."""
    return path.read_text(encoding="utf-8").splitlines(keepends=True)


def read_local_source(label: str, reader: Callable[[], list[str]]) -> list[str] | None:
    """Read one local source and log recoverable file-level failures."""
    try:
        file_lines = reader()
    except FileNotFoundError:
        log.warning("File not found, skipping: %s", label)
        return None
    except (OSError, UnicodeDecodeError) as exc:
        log.warning("Unable to read %s, skipping: %s", label, exc)
        return None
    log.info("Read %d lines from %s", len(file_lines), label)
    return file_lines


def expand_input_location(input_cfg: dict[str, Any]) -> list[Path]:
    """Expand one file input location into concrete paths."""
    location = input_cfg["location"]
    if input_cfg["type"] != "file":
        return []
    if not any(char in location for char in "*?["):
        return [Path(location)]
    matched_paths = [Path(path) for path in sorted(glob.glob(location, recursive=True))]
    if not matched_paths:
        log.warning("No files matched pattern, skipping: %s", location)
    return matched_paths


def build_source_jobs(
    config: dict[str, Any],
    *,
    prepared_source_ids: set[str] | None = None,
) -> list[SourceJob]:
    """Expand configured sources into concrete input jobs."""
    jobs: list[SourceJob] = []
    prepared_source_ids = prepared_source_ids or set()
    for source in config["sources"]:
        if not source["enabled"]:
            continue
        input_cfg = source["input"]
        stem = config["config_name"]
        if source["id"] in prepared_source_ids:
            jobs.append(
                SourceJob(
                    source_id=source["id"],
                    input_label=input_cfg.get("label") or input_cfg["location"],
                    output_stem=stem,
                    lines=[],
                    config=source,
                )
            )
            continue
        if input_cfg["type"] == "url":
            try:
                response = requests.get(
                    input_cfg["location"],
                    timeout=source["fetch"]["request_timeout"],
                )
                response.raise_for_status()
            except requests.RequestException as exc:
                log.warning("Unable to fetch %s: %s", input_cfg["location"], exc)
                continue
            jobs.append(
                SourceJob(
                    source_id=source["id"],
                    input_label=input_cfg.get("label") or input_cfg["location"],
                    output_stem=stem,
                    lines=response.text.splitlines(keepends=True),
                    config=source,
                )
            )
            continue

        matched_paths = expand_input_location(input_cfg)
        combined_lines: list[str] = []
        for file_path in matched_paths:
            if not file_path.is_file():
                log.warning("Matched path is not a file, skipping: %s", file_path)
                continue
            lines = read_local_source(
                str(file_path),
                lambda current_path=file_path: read_text_lines(current_path),
            )
            if lines is None:
                continue
            combined_lines.extend(lines)
        if not combined_lines:
            continue
        jobs.append(
            SourceJob(
                source_id=source["id"],
                input_label=input_cfg.get("label") or input_cfg["location"],
                output_stem=stem,
                lines=combined_lines,
                config=source,
            )
        )
    return jobs


def parse_source_entries(
    job: SourceJob,
) -> tuple[list[ParsedDomainEntry], Counter]:
    """Parse one source job into normalized entries."""
    parser_obj = DomainListParser()
    parser_stats: Counter = Counter()
    forced_format_value = str(job.config["input"].get("format", "auto"))
    forced_format = (
        None if forced_format_value == "auto" else InputFileFormat(forced_format_value)
    )
    entries = list(
        parser_obj.process_entries(
            job.lines,
            source_name=job.input_label,
            stats=parser_stats,
            forced_format=forced_format,
        )
    )
    if not entries:
        log.warning("Source %s produced no valid hosts after parsing", job.source_id)
    return entries, parser_stats


def _round_robin_roots_by_server(
    server_to_roots: dict[str, list[str]],
    fallback_roots: list[str],
) -> list[str]:
    """Return roots interleaved by RDAP server, then append fallback roots."""
    ordered_servers = sorted(server_to_roots)
    queues = {
        server: deque(server_to_roots[server])
        for server in ordered_servers
        if server_to_roots[server]
    }
    scheduled_roots: list[str] = []
    while queues:
        exhausted_servers: list[str] = []
        for server in ordered_servers:
            queue = queues.get(server)
            if queue is None:
                continue
            if queue:
                scheduled_roots.append(queue.popleft())
            if not queue:
                exhausted_servers.append(server)
        for server in exhausted_servers:
            queues.pop(server, None)
    scheduled_roots.extend(fallback_roots)
    return scheduled_roots


def schedule_rdap_entries(
    checker: DomainChecker,
    job: SourceJob,
    entries: list[ParsedDomainEntry],
) -> list[ParsedDomainEntry]:
    """Return entries reordered for authoritative RDAP scheduling."""
    if not hasattr(checker, "_authoritative_base_url"):
        log.info(
            "Source %s uses authoritative RDAP scheduling but checker lacks authoritative "
            "bootstrap resolution; preserving parsed entry order",
            job.source_id,
        )
        return entries

    root_to_entries: dict[str, list[ParsedDomainEntry]] = defaultdict(list)
    ordered_roots: list[str] = []
    seen_roots: set[str] = set()
    for entry in entries:
        root = entry.registrable_domain or entry.host
        root_to_entries[root].append(entry)
        if root not in seen_roots:
            seen_roots.add(root)
            ordered_roots.append(root)

    try:
        server_to_roots: dict[str, list[str]] = defaultdict(list)
        fallback_roots: list[str] = []
        for root in ordered_roots:
            # This scheduler only runs for the authoritative checker path.
            # It needs the resolved RDAP bucket, so this internal helper is
            # the narrowest available interface here.
            # pylint: disable=protected-access
            base_url = checker._authoritative_base_url(root)
            if base_url is None:
                fallback_roots.append(root)
                continue
            server_to_roots[base_url].append(root)
    except RuntimeError as exc:
        log.warning(
            "Source %s authoritative RDAP scheduling could not resolve bootstrap data; "
            "preserving parsed entry order: %s",
            job.source_id,
            exc,
        )
        return entries

    scheduled_roots = _round_robin_roots_by_server(server_to_roots, fallback_roots)
    scheduled_entries: list[ParsedDomainEntry] = []
    for root in scheduled_roots:
        scheduled_entries.extend(root_to_entries[root])
    log.info(
        "Source %s using authoritative RDAP scheduling; "
        "interleaved %d roots across %d authoritative RDAP server buckets "
        "(fallback_roots=%d)",
        job.source_id,
        len(ordered_roots),
        len(server_to_roots),
        len(fallback_roots),
    )
    return scheduled_entries


def cached_or_live_rdap_result(
    checker: DomainChecker,
    cache: PipelineCache,
    registrable_domain: str,
    now: datetime,
    rdap_lookup_unavailable_ttl_days: int,
) -> RDAPResult | None:
    """Return one root-level RDAP decision, using cache when available."""
    cached_root = cache.get_fresh_root(registrable_domain, now)
    if cached_root is None:
        log.debug(
            "RDAP root cache miss at %s for root=%s; "
            "performing live RDAP registrable-domain lookup",
            cache.path,
            registrable_domain,
        )
        try:
            return checker.rdap_lookup(registrable_domain)
        except CacheableRDAPUnavailableError:
            cache.upsert_root(
                registrable_domain,
                ROOT_CLASSIFICATION_RDAP_LOOKUP_UNAVAILABLE,
                [],
                False,
                now,
                rdap_lookup_unavailable_ttl_days,
            )
            log.debug(
                "RDAP unavailable cache stored at %s for root=%s ttl_days=%d",
                cache.path,
                registrable_domain,
                rdap_lookup_unavailable_ttl_days,
            )
            return None
    if (
        cached_root.classification
        == ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED
    ):
        log.debug(
            "RDAP root cache hit at %s for root=%s classification=%s; filtering hosts under root",
            cache.path,
            registrable_domain,
            cached_root.classification,
        )
        return RDAPResult(False, [], from_cache=True)
    if cached_root.is_cached_rdap_unavailable():
        log.debug(
            "RDAP root cache hit at %s for root=%s classification=%s with cached unavailable "
            "bootstrap state; skipping live RDAP and continuing to DNS",
            cache.path,
            registrable_domain,
            cached_root.classification,
        )
        return None
    if not cached_root.statuses_complete:
        log.debug(
            "RDAP root cache hit at %s for root=%s classification=%s but cached statuses "
            "are incomplete; refreshing live RDAP",
            cache.path,
            registrable_domain,
            cached_root.classification,
        )
        try:
            return checker.rdap_lookup(registrable_domain)
        except CacheableRDAPUnavailableError:
            cache.upsert_root(
                registrable_domain,
                ROOT_CLASSIFICATION_RDAP_LOOKUP_UNAVAILABLE,
                [],
                False,
                now,
                rdap_lookup_unavailable_ttl_days,
            )
            log.debug(
                "RDAP unavailable cache stored at %s for root=%s ttl_days=%d",
                cache.path,
                registrable_domain,
                rdap_lookup_unavailable_ttl_days,
            )
            return None
    log.debug(
        "RDAP root cache hit at %s for root=%s classification=%s; "
        "skipping live RDAP and continuing to DNS",
        cache.path,
        registrable_domain,
        cached_root.classification,
    )
    return RDAPResult(True, list(cached_root.statuses), from_cache=True)


def effective_dns_nameservers(dns_config: dict[str, Any]) -> list[str]:
    """Return the resolver IPs that will actually be used for DNS lookups."""
    nameservers = list(dns_config["nameservers"])
    if nameservers and not dns_config["ecs"]["enabled"]:
        return nameservers
    if nameservers and dns_config["ecs"]["enabled"]:
        normalized_nameservers = {
            str(ipaddress.ip_address(address)) for address in nameservers
        }
        if normalized_nameservers.issubset(ECS_CAPABLE_PUBLIC_DNS_NAMESERVERS):
            return nameservers
        return list(DEFAULT_ECS_FALLBACK_NAMESERVERS)
    if dns_config["ecs"]["enabled"]:
        return list(DEFAULT_ECS_FALLBACK_NAMESERVERS)
    return []


def dns_resolver_key(dns_config: dict[str, Any]) -> str:
    """Return a stable cache key for the effective DNS resolver settings."""
    nameservers = effective_dns_nameservers(dns_config)
    ecs_config = dns_config["ecs"]
    key_parts = ["system" if not nameservers else ",".join(nameservers)]
    if ecs_config["enabled"]:
        key_parts.append(
            f"ecs={ecs_config['subnet']}@{ecs_config['scope_prefix_length']}"
        )
    else:
        key_parts.append("ecs=off")
    return "|".join(key_parts)


def _dns_result_from_history(record: Any) -> DNSResult:
    """Reconstruct a DNS result from one cached DNS record."""
    return DNSResult(
        host=record.host,
        a_exists=record.a_exists,
        a_nodata=record.a_nodata,
        a_nxdomain=record.a_nxdomain,
        a_timeout=record.a_timeout,
        a_servfail=record.a_servfail,
        canonical_name=record.canonical_name or None,
        ipv4_addresses=list(record.ipv4_addresses),
        ipv6_addresses=list(record.ipv6_addresses),
    )


def cached_or_live_dns_result(
    checker: DomainChecker,
    cache: PipelineCache,
    host: str,
    resolver_key: str,
    now: datetime,
    ttl_days: int,
) -> tuple[DNSResult, Counter]:
    """Return a cached DNS result when fresh, otherwise perform and store a live lookup."""
    stats: Counter = Counter()
    cached_record = cache.get_fresh_dns(host, resolver_key, now)
    if cached_record is not None:
        stats["dns_cache_hits"] += 1
        dns_result = _dns_result_from_history(cached_record)
        log.debug(
            "DNS cache hit at %s for host=%s resolver=%s -> status=%s cname=%s ips=%s",
            cache.path,
            host,
            resolver_key,
            dns_result.status,
            dns_result.canonical_name or "(none)",
            dns_result.resolved_ips or "(none)",
        )
        return dns_result, stats

    stats["dns_cache_misses"] += 1
    log.debug(
        "DNS cache miss at %s for host=%s resolver=%s", cache.path, host, resolver_key
    )
    dns_result = checker.dns_lookup(host)
    cache.upsert_dns(
        host,
        resolver_key,
        a_exists=dns_result.a_exists,
        a_nodata=dns_result.a_nodata,
        a_nxdomain=dns_result.a_nxdomain,
        a_timeout=dns_result.a_timeout,
        a_servfail=dns_result.a_servfail,
        canonical_name=dns_result.canonical_name or "",
        ipv4_addresses=list(dns_result.ipv4_addresses),
        ipv6_addresses=list(dns_result.ipv6_addresses),
        checked_at=now,
        ttl_days=ttl_days,
    )
    log.debug(
        "DNS cache stored at %s for host=%s resolver=%s ttl_days=%d status=%s",
        cache.path,
        host,
        resolver_key,
        ttl_days,
        dns_result.status,
    )
    return dns_result, stats


def classify_host_with_cached_dns(
    checker: DomainChecker,
    cache: PipelineCache,
    host: str,
    registrable_domain: str,
    rdap_result: RDAPResult | None,
    resolver_key: str,
    now: datetime,
    dns_ttl_days: int,
) -> tuple[str, RDAPResult | None, DNSResult, Counter]:
    """Classify one host while resolving DNS through the persistent cache."""
    if rdap_result is not None and not rdap_result.exists:
        classification, cached_rdap_result, dns_result = (
            checker.classify_host_with_known_rdap(
                host,
                registrable_domain,
                rdap_result,
            )
        )
        return classification, cached_rdap_result, dns_result, Counter()

    dns_result, dns_stats = cached_or_live_dns_result(
        checker,
        cache,
        host,
        resolver_key,
        now,
        dns_ttl_days,
    )
    original_dns_lookup = checker.dns_lookup
    try:
        cached_host = host

        # Temporarily inject the cached DNS result for the exact host so the
        # downstream host-processing logic can reuse it without another lookup.
        def cached_dns_lookup(host: str) -> DNSResult:
            return dns_result if host == cached_host else original_dns_lookup(host)

        checker.dns_lookup = cached_dns_lookup
        classification, cached_rdap_result, classified_dns_result = (
            checker.classify_host_with_known_rdap(
                host,
                registrable_domain,
                rdap_result,
            )
        )
    finally:
        checker.dns_lookup = original_dns_lookup
    return classification, cached_rdap_result, classified_dns_result, dns_stats


def write_result_row(
    output_kind: str,
    output_file: TextIO,
    row: dict[str, Any],
) -> None:
    """Write a single result row in the configured output format."""
    if output_kind in {"filtered", "dead"}:
        output_file.write(f"{row['host']}\n")
        return
    json.dump(row, output_file)
    output_file.write("\n")


def _audit_row(row: dict[str, Any], *, route: str) -> dict[str, Any]:
    """Return the serialized raw-audit row for one sync runtime result."""
    audit_row = dict(row)
    audit_row["route"] = route
    return audit_row


def lookup_geo_results(
    cache: PipelineCache,
    provider: IPGeoProvider,
    dns_result: DNSResult,
    now: datetime,
    cache_ttl_days: int,
) -> tuple[list[IPGeoResult], Counter]:
    """Resolve or retrieve cached geo results for one host."""
    stats: Counter = Counter()
    resolved_ips = list(dns_result.resolved_ips)
    results: list[IPGeoResult | None] = [None] * len(resolved_ips)
    missed_indices: list[int] = []
    missed_ips: list[str] = []
    for index, ip in enumerate(resolved_ips):
        cached = cache.get_fresh_geo(provider.provider_name, ip, now)
        if cached is not None:
            stats["geo_cache_hits"] += 1
            log.debug(
                "Geo cache hit at %s for provider=%s ip=%s -> country=%s region_code=%s "
                "region_name=%s",
                cache.path,
                provider.provider_name,
                ip,
                cached.country_code or "(none)",
                cached.region_code or "(none)",
                cached.region_name or "(none)",
            )
            results[index] = IPGeoResult(
                ip=ip,
                provider=provider.provider_name,
                country_code=cached.country_code,
                region_code=cached.region_code,
                region_name=cached.region_name,
                status=GEO_STATUS_CACHE_HIT,
            )
            continue
        stats["geo_cache_misses"] += 1
        log.debug(
            "Geo cache miss at %s for provider=%s ip=%s",
            cache.path,
            provider.provider_name,
            ip,
        )
        missed_indices.append(index)
        missed_ips.append(ip)

    lookup_ips = getattr(provider, "lookup_ips", None)
    looked_up_results: list[IPGeoResult]
    if missed_ips:
        if callable(lookup_ips):
            looked_up_results = cast(list[IPGeoResult], lookup_ips(missed_ips))
        else:
            looked_up_results = [provider.lookup_ip(ip) for ip in missed_ips]
        if len(looked_up_results) != len(missed_ips):
            raise ValueError(
                f"{provider.provider_name} returned {len(looked_up_results)} geo results "
                f"for {len(missed_ips)} requested IPs"
            )
    else:
        looked_up_results = []

    for index, result in zip(missed_indices, looked_up_results):
        ip = resolved_ips[index]
        log.debug(
            "Geo lookup result for provider=%s ip=%s -> status=%s "
            "country=%s region_code=%s region_name=%s",
            provider.provider_name,
            ip,
            result.status,
            result.country_code or "(none)",
            result.region_code or "(none)",
            result.region_name or "(none)",
        )
        results[index] = result
        if result.usable:
            cache.upsert_geo(
                provider.provider_name,
                ip,
                result.country_code,
                result.region_code,
                result.region_name,
                now,
                cache_ttl_days,
            )
            log.debug(
                "Geo cache stored at %s for provider=%s ip=%s ttl_days=%d",
                cache.path,
                provider.provider_name,
                ip,
                cache_ttl_days,
            )
    return [result for result in results if result is not None], stats


def lookup_geo_results_with_fallback(
    cache: PipelineCache,
    configured_provider: IPGeoProvider,
    job: SourceJob,
    dns_result: DNSResult,
    now: datetime,
) -> tuple[IPGeoProvider | None, list[IPGeoResult], Counter, list[dict[str, Any]]]:
    """Resolve geo results for the one effective provider selected by policy."""
    stats: Counter = Counter()
    geo_config = job.config["geo"]
    provider_name = _effective_geo_provider_name(geo_config)
    provider = configured_provider
    if provider.provider_name != provider_name:
        provider = build_geo_provider(
            provider_name,
            timeout=float(geo_config["timeout"]),
            token=resolve_geo_token(geo_config, provider_name),
        )
    results, provider_stats = lookup_geo_results(
        cache,
        provider,
        dns_result,
        now,
        int(geo_config["cache_ttl_days"]),
    )
    stats.update(provider_stats)
    attempts = [
        {
            "provider": provider.provider_name,
            "statuses": {result.ip: result.status for result in results},
        }
    ]
    if any(result.usable for result in results):
        return provider, results, stats, attempts
    log.info(
        "Geo provider %s yielded no usable geo data for host=%s",
        provider.provider_name,
        dns_result.host,
    )
    return None, results, stats, attempts


def _update_host_history(
    cache: PipelineCache,
    cache_stats: Counter,
    host: str,
    classification: str,
    now: datetime,
    rdap_registrable_domain_unregistered_ttl_days: int,
    rdap_registrable_domain_registered_ttl_days: int,
) -> None:
    """Host-level classification rows were removed from persistent cache storage."""
    del (
        cache,
        cache_stats,
        host,
        classification,
        now,
        rdap_registrable_domain_unregistered_ttl_days,
        rdap_registrable_domain_registered_ttl_days,
    )


def _update_root_history(
    cache: PipelineCache,
    cache_stats: Counter,
    root: str,
    rdap_result: RDAPResult | None,
    now: datetime,
    rdap_registrable_domain_unregistered_ttl_days: int,
    rdap_registrable_domain_registered_ttl_days: int,
) -> None:
    """Update registrable-domain RDAP cache entries."""
    if rdap_result is None or rdap_result.from_cache:
        return
    root_classification = (
        ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_REGISTERED
        if rdap_result.exists
        else ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED
    )
    root_existing_record = cache.get_root(root)
    ttl_days = (
        rdap_registrable_domain_registered_ttl_days
        if root_classification == ROOT_CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_REGISTERED
        else rdap_registrable_domain_unregistered_ttl_days
    )
    cache.upsert_root(
        root,
        root_classification,
        list(rdap_result.statuses),
        True,
        now,
        ttl_days,
    )
    cache_stats["cached_written"] += 1
    if root_existing_record is not None:
        cache_stats["cached_refreshed"] += 1


# pylint: disable=too-many-statements
def classify_and_write_source(
    checker: DomainChecker,
    provider: IPGeoProvider | None,
    job: SourceJob,
    entries: list[ParsedDomainEntry],
    cache: PipelineCache,
    now: datetime,
    rdap_registrable_domain_unregistered_ttl_days: int,
    rdap_registrable_domain_registered_ttl_days: int,
    dns_ttl_days: int,
    output_files: dict[str, TextIO],
    row_collector: dict[str, list[dict[str, Any]]] | None = None,
    rdap_lookup_unavailable_ttl_days: int | None = None,
) -> tuple[Counter, Counter]:
    """Process each host for one source job and write sorted output rows."""
    if rdap_lookup_unavailable_ttl_days is None:
        rdap_lookup_unavailable_ttl_days = rdap_registrable_domain_registered_ttl_days
    counts: Counter = Counter()
    cache_stats: Counter = Counter()
    total = len(entries)
    output_rows: list[dict[str, Any]] = []
    dead_rows: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []
    review_rows: list[dict[str, Any]] = []
    rdap_cache: dict[str, RDAPResult | None] = {}
    persisted_root_cache_updates: set[str] = set()
    dns_enabled = bool(job.config["dns"].get("enabled", True))
    geo_enabled = bool(job.config["geo"]["enabled"])
    resolver_key = dns_resolver_key(job.config["dns"])
    try:
        for idx, entry in enumerate(entries, start=1):
            host = entry.host
            root = entry.registrable_domain
            rdap_result: RDAPResult | None = None
            dns_result = DNSResult(
                host=host,
                a_exists=False,
                a_nodata=False,
                a_nxdomain=False,
                a_timeout=False,
                a_servfail=False,
                canonical_name=None,
            )
            dns_stats: Counter = Counter()
            geo_provider_for_row: IPGeoProvider | None = provider
            geo_results: list[IPGeoResult] = []
            geo_status = "skipped"
            geo_reason = "geo_disabled"
            geo_policy_status = "skipped"
            geo_policy_reason = "geo_disabled"
            geo_attempts: list[dict[str, Any]] = []
            dns_status_override: str | None = None
            route = ROUTE_FILTERED

            if entry.is_public_suffix_input:
                classification = CLASSIFICATION_INPUT_PUBLIC_SUFFIX
                route = ROUTE_REVIEW
                counts[classification] += 1
                counts["geo_skipped"] += 1
                counts["geo_policy_skipped"] += 1
                geo_reason = "public_suffix_guard"
                geo_policy_reason = "public_suffix_guard"
                dns_status_override = "skipped"
                log.info(
                    "[%s %d/%d] %s -> %s (public_suffix=%s, input_kind=%s, apex_scope=%s)",
                    job.source_id,
                    idx,
                    total,
                    host,
                    classification,
                    entry.public_suffix,
                    entry.input_kind,
                    entry.apex_scope,
                )
            else:
                if root not in rdap_cache:
                    try:
                        rdap_result = cached_or_live_rdap_result(
                            checker,
                            cache,
                            root,
                            now,
                            rdap_lookup_unavailable_ttl_days,
                        )
                    except RDAPUnavailableError as exc:
                        rdap_result = None
                        if dns_enabled:
                            log.info(
                                "[%s %d/%d] %s RDAP unavailable for root=%s; continuing to DNS: %s",
                                job.source_id,
                                idx,
                                total,
                                host,
                                root,
                                exc,
                            )
                        else:
                            log.info(
                                "[%s %d/%d] %s RDAP unavailable for root=%s; DNS is "
                                "disabled so routing directly from RDAP stage: %s",
                                job.source_id,
                                idx,
                                total,
                                host,
                                root,
                                exc,
                            )
                    rdap_cache[root] = rdap_result
                else:
                    rdap_result = rdap_cache[root]
                if rdap_result is not None and not rdap_result.exists:
                    log.info(
                        "[%s %d/%d] %s filtered "
                        "(rdap_unregistered_registrable_domain=%s, rdap_source=%s)",
                        job.source_id,
                        idx,
                        total,
                        host,
                        root,
                        "cache" if rdap_result.from_cache else "live_404",
                    )
                    if root not in persisted_root_cache_updates:
                        _update_root_history(
                            cache,
                            cache_stats,
                            root,
                            rdap_result,
                            now,
                            rdap_registrable_domain_unregistered_ttl_days,
                            rdap_registrable_domain_registered_ttl_days,
                        )
                        persisted_root_cache_updates.add(root)
                    dead_row = build_output_row(
                        job,
                        entry,
                        CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED,
                        rdap_result,
                        DNSResult(
                            host=host,
                            a_exists=False,
                            a_nodata=False,
                            a_nxdomain=True,
                            a_timeout=False,
                            a_servfail=False,
                            canonical_name=None,
                        ),
                        [],
                        "skipped",
                        "dead_root",
                        "skipped",
                        "dead_root",
                        None,
                        dns_status_override="skipped",
                    )
                    dead_rows.append(dead_row)
                    audit_rows.append(_audit_row(dead_row, route=ROUTE_DEAD))
                    counts["routed_dead"] += 1
                    continue
                if not dns_enabled:
                    classification = (
                        CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_REGISTERED_DNS_DISABLED
                        if rdap_result is not None
                        else CLASSIFICATION_RDAP_LOOKUP_UNAVAILABLE_DNS_DISABLED
                    )
                    counts["geo_skipped"] += 1
                    counts["geo_policy_skipped"] += 1
                    dns_status_override = "skipped"
                    geo_status = "skipped"
                    geo_reason = "dns_disabled"
                    geo_policy_status = "skipped"
                    geo_policy_reason = "dns_disabled"
                    log.info(
                        "[%s %d/%d] %s -> %s (root=%s, dns=skipped, rdap_statuses=%s)",
                        job.source_id,
                        idx,
                        total,
                        host,
                        classification,
                        root,
                        (
                            "|".join(rdap_result.statuses)
                            if rdap_result is not None
                            else "(none)"
                        ),
                    )
                else:
                    classification, rdap_result, dns_result, dns_stats = (
                        classify_host_with_cached_dns(
                            checker,
                            cache,
                            host,
                            root,
                            rdap_result,
                            resolver_key,
                            now,
                            dns_ttl_days,
                        )
                    )
                    cache_stats.update(dns_stats)
                    log.info(
                        "[%s %d/%d] %s -> %s (root=%s, dns=%s, rdap_statuses=%s)",
                        job.source_id,
                        idx,
                        total,
                        host,
                        classification,
                        root,
                        dns_result.status,
                        (
                            "|".join(rdap_result.statuses)
                            if rdap_result is not None
                            else "(none)"
                        ),
                    )

                _update_host_history(
                    cache,
                    cache_stats,
                    host,
                    classification,
                    now,
                    rdap_registrable_domain_unregistered_ttl_days,
                    rdap_registrable_domain_registered_ttl_days,
                )
                if root not in persisted_root_cache_updates:
                    _update_root_history(
                        cache,
                        cache_stats,
                        root,
                        rdap_result,
                        now,
                        rdap_registrable_domain_unregistered_ttl_days,
                        rdap_registrable_domain_registered_ttl_days,
                    )
                    persisted_root_cache_updates.add(root)

                geo_stats: Counter = Counter()
                decision: GeoPolicyDecision | None = None
                if not dns_enabled:
                    pass
                elif classification in PRE_GEO_REVIEW_CLASSIFICATIONS:
                    counts["geo_skipped"] += 1
                    counts["geo_policy_skipped"] += 1
                    geo_status = "skipped"
                    geo_reason = "classification_precludes_geo_lookup"
                    geo_policy_status = "skipped"
                    geo_policy_reason = "classification_precludes_geo_lookup"
                elif not dns_result.resolved_ips:
                    if classification == CLASSIFICATION_DNS_RESOLVES:
                        classification = (
                            CLASSIFICATION_DNS_RESOLVED_WITHOUT_IP_ADDRESSES
                        )
                    counts["geo_skipped"] += 1
                    counts["geo_policy_skipped"] += 1
                    geo_status = "skipped"
                    geo_reason = "no_resolved_ips"
                    geo_policy_status = "skipped"
                    geo_policy_reason = "no_resolved_ips"
                elif geo_enabled and provider is not None:
                    (
                        geo_provider_for_row,
                        geo_results,
                        geo_stats,
                        geo_attempts,
                    ) = lookup_geo_results_with_fallback(
                        cache,
                        provider,
                        job,
                        dns_result,
                        now,
                    )
                    cache_stats.update(geo_stats)
                    if geo_provider_for_row is None:
                        classification = CLASSIFICATION_GEO_LOOKUP_FAILED
                        geo_status = "review"
                        geo_reason = "geo_lookup_failed"
                        counts["geo_policy_skipped"] += 1
                        geo_policy_status = "skipped"
                        geo_policy_reason = "geo_lookup_failed"
                        counts["geo_review"] += 1
                        log.info(
                            "[%s %d/%d] %s routed to review after geo lookup failed: %s",
                            job.source_id,
                            idx,
                            total,
                            host,
                            [attempt["provider"] for attempt in geo_attempts],
                        )
                    else:
                        geo_status = "ok"
                        geo_reason = "lookup_succeeded"
                        policy = job.config["geo"]["policy"]
                        if _geo_requires_region_lookup(job.config["geo"]) and not any(
                            result.region_name.strip()
                            for result in geo_results
                            if result.usable
                        ):
                            classification = CLASSIFICATION_GEO_REGION_NAME_UNAVAILABLE
                            geo_status = "review"
                            geo_reason = "region_name_unavailable"
                            counts["geo_policy_skipped"] += 1
                            geo_policy_status = "skipped"
                            geo_policy_reason = "region_name_unavailable"
                            counts["geo_review"] += 1
                        elif not policy["enabled"]:
                            counts["geo_policy_skipped"] += 1
                            geo_policy_status = "skipped"
                            geo_policy_reason = "policy_disabled"
                        elif not _geo_policy_has_rules(policy):
                            counts["geo_policy_skipped"] += 1
                            geo_policy_status = "skipped"
                            geo_policy_reason = "policy_has_no_rules"
                        else:
                            decision = evaluate_geo_policy(geo_results, policy)
                            geo_policy_status = decision.status
                            geo_policy_reason = decision.reason
                            if decision.status == "rejected":
                                classification = CLASSIFICATION_GEO_POLICY_REJECTED
                            counts[f"geo_policy_decision_{decision.status}"] += 1
                else:
                    counts["geo_skipped"] += 1
                    counts["geo_policy_skipped"] += 1
                    log.debug(
                        "[%s %d/%d] %s geo disabled", job.source_id, idx, total, host
                    )

                counts[classification] += 1

                matched_ips = decision.matched_ips if decision is not None else []
                rejected_ips = decision.rejected_ips if decision is not None else []
                log.debug(
                    "[%s %d/%d] %s geo -> %s/%s (lookup_reason=%s, policy_reason=%s, "
                    "provider=%s, ips=%s, matched=%s, rejected=%s, cache_hits=%d, "
                    "cache_misses=%d)",
                    job.source_id,
                    idx,
                    total,
                    host,
                    geo_status,
                    geo_reason,
                    geo_policy_status,
                    geo_policy_reason,
                    (
                        geo_provider_for_row.provider_name
                        if geo_provider_for_row is not None
                        else ""
                    ),
                    [result.ip for result in geo_results] or "(none)",
                    matched_ips,
                    rejected_ips,
                    geo_stats.get("geo_cache_hits", 0),
                    geo_stats.get("geo_cache_misses", 0),
                )
                route = route_for_row(classification, geo_policy_status, geo_reason)

            row = build_output_row(
                job,
                entry,
                classification,
                rdap_result,
                dns_result,
                geo_results,
                geo_status,
                geo_reason,
                geo_policy_status,
                geo_policy_reason,
                geo_provider_for_row,
                dns_status_override=dns_status_override,
            )
            if (
                classification
                in {
                    CLASSIFICATION_GEO_LOOKUP_FAILED,
                    CLASSIFICATION_GEO_REGION_NAME_UNAVAILABLE,
                }
                and geo_attempts
            ):
                row["geo_attempts"] = geo_attempts
            audit_rows.append(_audit_row(row, route=route))
            if route == ROUTE_REVIEW:
                counts["routed_review"] += 1
                review_rows.append(row)
                continue
            if route == ROUTE_DEAD:
                counts["routed_dead"] += 1
                dead_rows.append(row)
                continue
            counts["routed_filtered"] += 1
            output_rows.append(row)
        if row_collector is not None:
            row_collector.setdefault("output_rows", []).extend(output_rows)
            row_collector.setdefault("dead_rows", []).extend(dead_rows)
            row_collector.setdefault("audit_rows", []).extend(audit_rows)
            row_collector.setdefault("review_rows", []).extend(review_rows)
            return counts, cache_stats
        if "filtered" in output_files:
            for row in sorted(output_rows, key=lambda output_row: output_row["host"]):
                write_result_row("filtered", output_files["filtered"], row)
        if "dead" in output_files:
            for row in sorted(dead_rows, key=lambda output_row: output_row["host"]):
                write_result_row("dead", output_files["dead"], row)
        elif dead_rows:
            dead_output_path = dead_output_path_for_job(job)
            dead_output_path.parent.mkdir(parents=True, exist_ok=True)
            with dead_output_path.open("a", encoding="utf-8", newline="") as handle:
                for row in sorted(dead_rows, key=lambda output_row: output_row["host"]):
                    write_result_row("dead", handle, row)
        if "audit" in output_files:
            for row in sorted(audit_rows, key=lambda output_row: output_row["host"]):
                write_result_row("audit", output_files["audit"], row)
        review_output_path = review_output_path_for_job(job)
        if review_rows:
            write_review_rows(review_output_path, review_rows)
            for row in sorted(review_rows, key=lambda output_row: output_row["host"]):
                log.info(
                    "[%s review] %s routed to review file %s",
                    job.source_id,
                    row["host"],
                    review_output_path,
                )
    finally:
        pass
    return counts, cache_stats


def build_checker(source_config: dict[str, Any]) -> DomainChecker:
    """Build a checker instance for one source configuration."""
    dns_config = source_config["dns"]
    nameservers = effective_dns_nameservers(dns_config)
    resolver = dns.resolver.Resolver(configure=not nameservers)
    if nameservers:
        resolver.nameservers = nameservers
    ecs_config = dns_config["ecs"]
    if ecs_config["enabled"]:
        network = ipaddress.ip_network(ecs_config["subnet"], strict=False)
        resolver.use_edns(
            edns=0,
            options=[
                dns.edns.ECSOption(
                    str(network.network_address),
                    network.prefixlen,
                    ecs_config["scope_prefix_length"],
                )
            ],
        )
    return DomainChecker(
        rdap_timeout=source_config["rdap"]["timeout"],
        dns_timeout=dns_config["timeout"],
        resolver=resolver,
    )
