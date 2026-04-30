"""Workflow-owned DNS actionability runtime."""

from __future__ import annotations

import asyncio
import logging
from collections import Counter
from pathlib import Path
from typing import Any

from domain_pipeline.checking import (
    DelegationResult,
    GEO_STATUS_CACHE_HIT,
    HostResolutionResult,
    IPGeoResult,
    build_geo_provider,
    evaluate_geo_policy,
)
from domain_pipeline.classifications import (
    CLASSIFICATION_GEO_LOOKUP_FAILED,
    CLASSIFICATION_INPUT_PUBLIC_SUFFIX,
    CLASSIFICATION_MANUAL_ADD_ACTIONABLE,
    CLASSIFICATION_MANUAL_FILTER_PASSED,
)
from domain_pipeline.io.parser import DomainListParser, ParsedDomainEntry
from domain_pipeline.runtime.cache_async import CacheHitSource, AsyncCacheReadFacade
from domain_pipeline.runtime.contracts import CompletedHostResult
from domain_pipeline.runtime.history import PipelineCache, utc_now
from domain_pipeline.runtime.pipeline_runner import build_checker, build_source_jobs
from domain_pipeline.runtime.pure_helpers import (
    build_base_row,
    classify_delegation,
    classify_host_resolution,
    geo_policy_classification,
    host_resolution_skipped_classification,
    route_for_classification,
)
from domain_pipeline.runtime.writer import ResultCollectorWriter
from domain_pipeline.shared import SourceJob

logger = logging.getLogger(__name__)


def _entry_from_payload(payload: dict[str, Any]) -> ParsedDomainEntry:
    return ParsedDomainEntry(
        host=str(payload["host"]),
        registrable_domain=str(payload.get("registrable_domain", "")),
        input_name=str(payload.get("input_name", payload["host"])),
        public_suffix=str(payload.get("public_suffix", "")),
        is_public_suffix_input=bool(payload.get("is_public_suffix_input", False)),
        input_kind=str(payload.get("input_kind", "exact_host")),
        apex_scope=str(payload.get("apex_scope", "exact_only")),
        source_format=str(payload.get("source_format", "plain")),
    )


def _prepared_entries(
    job: SourceJob, prepared_metadata: dict[str, Any] | None
) -> list[tuple[ParsedDomainEntry, dict[str, Any]]]:
    if not prepared_metadata:
        return []
    source_payload = prepared_metadata.get("sources", {}).get(job.source_id)
    if not isinstance(source_payload, dict):
        return []
    entries = source_payload.get("entries", [])
    if not isinstance(entries, list):
        return []
    result: list[tuple[ParsedDomainEntry, dict[str, Any]]] = []
    for item in entries:
        if isinstance(item, dict):
            result.append((_entry_from_payload(item), item))
    return result


class AsyncPipelineRuntime:
    """Small sequential runtime with an async-compatible public entrypoint."""

    def __init__(
        self,
        config: dict[str, Any],
        *,
        runtime_identity: dict[str, str] | None = None,
        prepared_metadata: dict[str, Any] | None = None,
    ) -> None:
        self.config = config
        self.runtime_identity = runtime_identity or {}
        self.prepared_metadata = prepared_metadata or {}
        self.writer = ResultCollectorWriter()
        cache_payload = config.get("cache", {})
        cache_file = str(cache_payload.get("cache_file", "")).strip()
        cache_path = Path(cache_file) if cache_file else Path(".cache.sqlite3")
        baseline_cache_file = str(cache_payload.get("baseline_cache_file", "")).strip()
        baseline_cache_path = Path(baseline_cache_file) if baseline_cache_file else None
        self.cache = PipelineCache.load(cache_path)
        self.cache_reader = AsyncCacheReadFacade(
            cache_path,
            baseline_path=baseline_cache_path,
        )
        self.cache_stats: Counter[str] = Counter()

    @classmethod
    def from_runtime_payload(
        cls,
        runtime_config: dict[str, Any],
        *,
        runtime_identity: dict[str, str] | None = None,
        prepared_metadata: dict[str, Any] | None = None,
    ) -> "AsyncPipelineRuntime":
        """Build a runtime from a manifest-owned payload."""
        return cls(
            runtime_config,
            runtime_identity=runtime_identity,
            prepared_metadata=prepared_metadata,
        )

    def close(self) -> None:
        """Close runtime resources."""
        self.cache.close()

    def _delegation_from_cache_record(self, record: Any) -> DelegationResult:
        return DelegationResult(
            domain=record.domain,
            ns_exists=record.ns_exists,
            ns_nodata=record.ns_nodata,
            ns_nxdomain=record.ns_nxdomain,
            ns_timeout=record.ns_timeout,
            ns_servfail=record.ns_servfail,
            no_nameservers=record.no_nameservers,
            nameservers=record.nameservers,
            from_cache=True,
        )

    def _host_resolution_from_cache_record(self, record: Any) -> HostResolutionResult:
        """Build a host-resolution result from the physical dns_history table."""
        return HostResolutionResult(
            host=record.host,
            a_exists=record.a_exists,
            a_nodata=record.a_nodata,
            a_nxdomain=record.a_nxdomain,
            a_timeout=record.a_timeout,
            a_servfail=record.a_servfail,
            canonical_name=record.canonical_name or None,
            ipv4_addresses=record.ipv4_addresses,
            ipv6_addresses=record.ipv6_addresses,
            from_cache=True,
        )

    def _geo_from_cache_record(self, record: Any) -> IPGeoResult:
        return IPGeoResult(
            ip=record.ip,
            provider=record.provider,
            country_code=record.country_code,
            region_code=record.region_code,
            region_name=record.region_name,
            status=GEO_STATUS_CACHE_HIT,
        )

    def _record_cache_hit(self, prefix: str, source: CacheHitSource | None) -> None:
        """Record cache hit counters, including overlay/baseline source."""
        self.cache_stats[f"{prefix}_cache_hits"] += 1
        if source is not None:
            self.cache_stats[f"{prefix}_{source}_cache_hits"] += 1
        if prefix == "host_resolution":
            self.cache_stats["dns_cache_hits"] += 1
            if source is not None:
                self.cache_stats[f"dns_{source}_cache_hits"] += 1

    def _record_cache_miss(self, prefix: str) -> None:
        """Record cache misses with legacy dns_* aliases for host resolution."""
        self.cache_stats[f"{prefix}_cache_misses"] += 1
        if prefix == "host_resolution":
            self.cache_stats["dns_cache_misses"] += 1

    def _lookup_delegation(
        self, job: SourceJob, entry: ParsedDomainEntry
    ) -> DelegationResult:
        checker = build_checker(job.config)
        resolver_key = checker.resolver_key()
        now = utc_now()
        cached, source = self.cache_reader.get_fresh_delegation_sync_with_source(
            entry.registrable_domain, resolver_key, now
        )
        if cached is not None:
            self._record_cache_hit("delegation", source)
            return self._delegation_from_cache_record(cached)
        self._record_cache_miss("delegation")
        result = checker.delegation_lookup(entry.registrable_domain)
        if result.status in {"timeout", "servfail"}:
            return result
        ttl_config = self.config["cache"]["classification_ttl_days"]
        ttl_days = (
            int(ttl_config["dns_delegation_actionable"])
            if result.actionable
            else int(ttl_config["dns_delegation_unactionable"])
        )
        self.cache.put_delegation(
            domain=result.domain,
            resolver_key=resolver_key,
            ns_exists=result.ns_exists,
            ns_nodata=result.ns_nodata,
            ns_nxdomain=result.ns_nxdomain,
            ns_timeout=result.ns_timeout,
            ns_servfail=result.ns_servfail,
            no_nameservers=result.no_nameservers,
            nameservers=result.nameservers,
            checked_at=now,
            ttl_days=ttl_days,
        )
        return result

    def _lookup_host_resolution(
        self, job: SourceJob, entry: ParsedDomainEntry
    ) -> HostResolutionResult:
        """Run or cache-read the optional dns.host_resolution stage."""
        checker = build_checker(job.config)
        resolver_key = checker.resolver_key()
        now = utc_now()
        cached, source = self.cache_reader.get_fresh_dns_sync_with_source(
            entry.host, resolver_key, now
        )
        if cached is not None:
            self._record_cache_hit("host_resolution", source)
            return self._host_resolution_from_cache_record(cached)
        self._record_cache_miss("host_resolution")
        result = checker.host_resolution_lookup(entry.host)
        if result.status in {"timeout", "servfail"}:
            return result
        self.cache.put_dns(
            host=result.host,
            resolver_key=resolver_key,
            a_exists=result.a_exists,
            a_nodata=result.a_nodata,
            a_nxdomain=result.a_nxdomain,
            a_timeout=result.a_timeout,
            a_servfail=result.a_servfail,
            canonical_name=result.canonical_name or "",
            ipv4_addresses=result.ipv4_addresses,
            ipv6_addresses=result.ipv6_addresses,
            checked_at=now,
            ttl_days=int(self.config["cache"].get("dns_ttl_days", 1)),
        )
        return result

    def _lookup_geo(
        self, job: SourceJob, host_resolution_result: HostResolutionResult
    ) -> tuple[str, list[IPGeoResult], Any | None]:
        geo_config = job.config["geo"]
        provider_name = str(
            geo_config.get("effective_provider") or geo_config.get("provider")
        )
        now = utc_now()
        cached_results: dict[str, IPGeoResult] = {}
        missing_ips: list[str] = []
        seen_missing_ips: set[str] = set()
        for ip in host_resolution_result.resolved_ips:
            cached, source = self.cache_reader.get_fresh_geo_sync_with_source(
                provider_name, ip, now
            )
            if cached is not None:
                self._record_cache_hit("geo", source)
                cached_results[ip] = self._geo_from_cache_record(cached)
                continue
            if ip not in seen_missing_ips:
                self.cache_stats["geo_cache_misses"] += 1
                missing_ips.append(ip)
                seen_missing_ips.add(ip)
        try:
            fetched_results: list[IPGeoResult] = []
            if missing_ips:
                provider = build_geo_provider(
                    provider_name,
                    timeout=float(geo_config.get("timeout", 5.0)),
                    token=str(geo_config.get("token", "")),
                )
                fetched_results = provider.lookup_ips(missing_ips)
            fetched_by_ip = {result.ip: result for result in fetched_results}
            for result in fetched_results:
                if not result.usable or result.status == GEO_STATUS_CACHE_HIT:
                    continue
                self.cache.put_geo(
                    provider=provider_name,
                    ip=result.ip,
                    country_code=result.country_code,
                    region_code=result.region_code,
                    region_name=result.region_name,
                    checked_at=now,
                    ttl_days=int(geo_config.get("cache_ttl_days", 7)),
                )
            results = [
                cached_results[ip] if ip in cached_results else fetched_by_ip[ip]
                for ip in host_resolution_result.resolved_ips
                if ip in cached_results or ip in fetched_by_ip
            ]
            policy = evaluate_geo_policy(results, geo_config["policy"])
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.warning(
                "Geo lookup failed for %s: %s", host_resolution_result.host, exc
            )
            return CLASSIFICATION_GEO_LOOKUP_FAILED, [], None
        return (
            geo_policy_classification(policy, results, geo_config["policy"]),
            results,
            policy,
        )

    def _complete(
        self,
        *,
        job: SourceJob,
        entry: ParsedDomainEntry,
        classification: str,
        delegation_result: DelegationResult | None = None,
        host_resolution_result: HostResolutionResult | None = None,
        geo_results: list[IPGeoResult] | None = None,
        geo_policy: Any | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> None:
        provenance = provenance or {}
        row = build_base_row(
            job=job,
            entry=entry,
            classification=classification,
            delegation_result=delegation_result,
            host_resolution_result=host_resolution_result,
            geo_results=geo_results or [],
            geo_policy=geo_policy,
            source_id_override=provenance.get("source_id_override"),
            source_input_label_override=provenance.get("source_input_label_override"),
            source_ids=tuple(provenance.get("source_ids", ())),
            source_input_labels=tuple(provenance.get("source_input_labels", ())),
        )
        self.writer.add(
            CompletedHostResult(
                job=job,
                entry=entry,
                classification=classification,
                route=route_for_classification(classification),
                row=row,
                delegation_result=delegation_result,
                host_resolution_result=host_resolution_result,
                geo_results=geo_results or [],
                geo_policy=geo_policy,
            )
        )

    def _process_entry(
        self, job: SourceJob, entry: ParsedDomainEntry, provenance: dict[str, Any]
    ) -> None:
        if entry.is_public_suffix_input or not entry.registrable_domain:
            self._complete(
                job=job,
                entry=entry,
                classification=CLASSIFICATION_INPUT_PUBLIC_SUFFIX,
                provenance=provenance,
            )
            return
        delegation_result = self._lookup_delegation(job, entry)
        delegation_classification = classify_delegation(delegation_result)
        if not delegation_result.actionable:
            self._complete(
                job=job,
                entry=entry,
                classification=delegation_classification,
                delegation_result=delegation_result,
                provenance=provenance,
            )
            return
        if provenance.get("manual_filter_pass"):
            self._complete(
                job=job,
                entry=entry,
                classification=CLASSIFICATION_MANUAL_FILTER_PASSED,
                delegation_result=delegation_result,
                provenance=provenance,
            )
            return
        if provenance.get("manual_add"):
            self._complete(
                job=job,
                entry=entry,
                classification=CLASSIFICATION_MANUAL_ADD_ACTIONABLE,
                delegation_result=delegation_result,
                provenance=provenance,
            )
            return
        dns_config = job.config["dns"]
        if not bool(dns_config.get("host_resolution", {}).get("enabled", False)):
            self._complete(
                job=job,
                entry=entry,
                classification=host_resolution_skipped_classification(),
                delegation_result=delegation_result,
                provenance=provenance,
            )
            return
        host_resolution_result = self._lookup_host_resolution(job, entry)
        host_classification = classify_host_resolution(host_resolution_result)
        if route_for_classification(host_classification) == "review":
            self._complete(
                job=job,
                entry=entry,
                classification=host_classification,
                delegation_result=delegation_result,
                host_resolution_result=host_resolution_result,
                provenance=provenance,
            )
            return
        if not bool(job.config["geo"].get("enabled", False)):
            self._complete(
                job=job,
                entry=entry,
                classification=host_classification,
                delegation_result=delegation_result,
                host_resolution_result=host_resolution_result,
                provenance=provenance,
            )
            return
        geo_classification, geo_results, geo_policy = self._lookup_geo(
            job, host_resolution_result
        )
        self._complete(
            job=job,
            entry=entry,
            classification=geo_classification,
            delegation_result=delegation_result,
            host_resolution_result=host_resolution_result,
            geo_results=geo_results,
            geo_policy=geo_policy,
            provenance=provenance,
        )

    def run(self) -> int:
        """Run the prepared or config-sourced pipeline."""
        if self.prepared_metadata:
            jobs = [
                SourceJob(
                    source_id=str(source["id"]),
                    input_label=str(
                        source.get("input", {}).get("label")
                        or source["input"]["location"]
                    ),
                    output_stem=str(self.config["config_name"]),
                    lines=[],
                    config=source,
                )
                for source in self.config["sources"]
                if source.get("enabled", True)
            ]
        else:
            jobs = build_source_jobs(self.config)
        parser = DomainListParser()
        for job in jobs:
            prepared_entries = _prepared_entries(job, self.prepared_metadata)
            if prepared_entries:
                for entry, provenance in prepared_entries:
                    self._process_entry(job, entry, provenance)
                continue
            forced_format = job.config.get("input", {}).get("format", "auto")
            for entry in parser.process_entries(
                job.lines,
                source_name=job.input_label,
                forced_format=None if forced_format == "auto" else forced_format,
            ):
                self._process_entry(job, entry, {})
        writer_result = self.writer.write()
        logger.info(
            "Pipeline emitted counts=%s outputs=%s",
            dict(writer_result.counts),
            writer_result.output_paths,
        )
        return 0


async def run_prepared_pipeline_async(
    runtime_config: dict[str, Any],
    *,
    runtime_identity: dict[str, str] | None = None,
    max_runtime_seconds: float | None = None,
    prepared_metadata: dict[str, Any] | None = None,
) -> int:
    """Run one workflow-owned runtime payload."""
    runtime = AsyncPipelineRuntime.from_runtime_payload(
        runtime_config,
        runtime_identity=runtime_identity,
        prepared_metadata=prepared_metadata,
    )
    try:
        if max_runtime_seconds is None:
            return await asyncio.to_thread(runtime.run)
        return await asyncio.wait_for(
            asyncio.to_thread(runtime.run), timeout=max_runtime_seconds
        )
    finally:
        runtime.close()
