"""Synchronous helpers shared by preparation and compatibility tests."""

from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path
from typing import Any

import requests

from domain_pipeline.checking import (
    DEFAULT_ECS_FALLBACK_NAMESERVERS,
    DelegationResult,
    DomainChecker,
    HostResolutionResult,
    QUAD9_ECS_NAMESERVERS,
    dns_resolver_key,
    effective_dns_nameservers,
)
from domain_pipeline.io.parser import (
    DomainListParser,
    InputFileFormat,
    ParsedDomainEntry,
)
from domain_pipeline.runtime.contracts import CompletedHostResult
from domain_pipeline.runtime.pure_helpers import (
    build_base_row,
    classify_delegation,
    classify_host_resolution,
    host_resolution_skipped_classification,
    route_for_classification,
)
from domain_pipeline.runtime.writer import ResultCollectorWriter, WriterResult
from domain_pipeline.shared import SourceJob

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_ECS_FALLBACK_NAMESERVERS",
    "QUAD9_ECS_NAMESERVERS",
    "build_checker",
    "build_source_jobs",
    "classify_and_write_source",
    "classify_entry",
    "dns_resolver_key",
    "effective_dns_nameservers",
]


def _read_source_lines(source_config: dict[str, Any]) -> tuple[str, list[str]]:
    input_payload = source_config["input"]
    location = str(input_payload["location"])
    label = str(input_payload.get("label") or location)
    if input_payload["type"] == "file":
        return label, Path(location).read_text(encoding="utf-8").splitlines(
            keepends=True
        )
    response = requests.get(
        location, timeout=float(source_config["fetch"]["request_timeout"])
    )
    response.raise_for_status()
    return label, response.text.splitlines(keepends=True)


def build_source_jobs(
    config: dict[str, Any], *, source_root: Path | None = None
) -> list[SourceJob]:
    """Build source jobs from normalized config."""
    jobs: list[SourceJob] = []
    config_name = str(config["config_name"])
    root = source_root or Path(".")
    for source in config["sources"]:
        if not source.get("enabled", True):
            continue
        source_copy = dict(source)
        input_payload = dict(source_copy["input"])
        if input_payload["type"] == "file":
            location_path = Path(str(input_payload["location"]))
            if not location_path.is_absolute():
                input_payload["location"] = str(root / location_path)
            source_copy["input"] = input_payload
        label, lines = _read_source_lines(source_copy)
        jobs.append(
            SourceJob(
                source_id=str(source["id"]),
                input_label=label,
                output_stem=config_name,
                lines=lines,
                config=source,
            )
        )
    return jobs


def build_checker(source_config: dict[str, Any]) -> DomainChecker:
    """Build a DNS checker from one normalized source config."""
    dns_config = source_config["dns"]
    return DomainChecker(
        nameservers=effective_dns_nameservers(dns_config),
        timeout=float(dns_config.get("timeout", 5.0)),
        ecs=dns_config.get("ecs", {}),
        query_rate_limit=dns_config.get("query_rate_limit", {}),
        query_balancer=dns_config.get("query_balancer", {}),
        delegation_retry_attempts=int(
            dns_config.get("delegation", {}).get("retry_attempts", 3)
        ),
        host_retry_attempts=int(
            dns_config.get("host_resolution", {}).get("retry_attempts", 3)
        ),
    )


def _terminal_result(
    *,
    job: SourceJob,
    entry: ParsedDomainEntry,
    classification: str,
    delegation_result: DelegationResult | None,
    host_resolution_result: HostResolutionResult | None,
) -> CompletedHostResult:
    row = build_base_row(
        job=job,
        entry=entry,
        classification=classification,
        delegation_result=delegation_result,
        host_resolution_result=host_resolution_result,
    )
    return CompletedHostResult(
        job=job,
        entry=entry,
        classification=classification,
        route=route_for_classification(classification),
        row=row,
        delegation_result=delegation_result,
        host_resolution_result=host_resolution_result,
    )


def classify_entry(
    job: SourceJob, entry: ParsedDomainEntry, checker: DomainChecker
) -> CompletedHostResult:
    """Classify one parsed entry using DNS delegation and optional host resolution."""
    if entry.is_public_suffix_input or not entry.registrable_domain:
        return _terminal_result(
            job=job,
            entry=entry,
            classification="input_public_suffix",
            delegation_result=None,
            host_resolution_result=None,
        )

    delegation_result = checker.delegation_lookup(entry.registrable_domain)
    delegation_classification = classify_delegation(delegation_result)
    if not delegation_result.actionable:
        return _terminal_result(
            job=job,
            entry=entry,
            classification=delegation_classification,
            delegation_result=delegation_result,
            host_resolution_result=None,
        )

    dns_config = job.config["dns"]
    if not bool(dns_config.get("host_resolution", {}).get("enabled", False)):
        return _terminal_result(
            job=job,
            entry=entry,
            classification=host_resolution_skipped_classification(),
            delegation_result=delegation_result,
            host_resolution_result=None,
        )
    host_resolution_result = checker.host_resolution_lookup(entry.host)
    return _terminal_result(
        job=job,
        entry=entry,
        classification=classify_host_resolution(host_resolution_result),
        delegation_result=delegation_result,
        host_resolution_result=host_resolution_result,
    )


def classify_and_write_source(job: SourceJob) -> WriterResult:
    """Classify one source job synchronously and write grouped outputs."""
    checker = build_checker(job.config)
    writer = ResultCollectorWriter()
    stats: Counter[str] = Counter()
    parser = DomainListParser()
    forced_format = job.config.get("input", {}).get("format", "auto")
    for entry in parser.process_entries(
        job.lines,
        source_name=job.input_label,
        stats=stats,
        forced_format=(
            InputFileFormat(forced_format) if forced_format != "auto" else None
        ),
    ):
        writer.add(classify_entry(job, entry, checker))
    return writer.write()
