"""Shared preparation helpers for workflow-owned automation runs."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, replace
import json
import logging
from pathlib import Path
from typing import Any

from domain_pipeline.classifications import (
    CLASSIFICATION_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
)
from domain_pipeline.io.parser import (
    DomainListParser,
    InputFileFormat,
    ParsedDomainEntry,
)
from domain_pipeline.runtime.pipeline_runner import build_checker, build_source_jobs
from domain_pipeline.settings.config import load_config
from domain_pipeline.shared import SourceJob

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PreparedRootPlan:
    """Preparation-time RDAP metadata for one registrable domain."""

    registrable_domain: str
    status: str
    authoritative_base_url: str | None = None


@dataclass(frozen=True)
class PreparedHostEntry:  # pylint: disable=too-many-instance-attributes
    """One shared prepared host entry with canonical and aggregated provenance."""

    source_id: str
    source_index: int
    entry: ParsedDomainEntry
    raw_line: str
    line_index: int
    manual_filter_pass: bool = False
    source_ids: tuple[str, ...] = ()
    source_input_labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class PreparedInputSet:  # pylint: disable=too-many-instance-attributes
    """Prepared inputs shared across workflow preparation and worker runtime."""

    config: dict[str, Any]
    jobs: list[SourceJob]
    source_jobs_by_id: dict[str, SourceJob]
    prepared_entries: list[PreparedHostEntry]
    root_plans: dict[str, PreparedRootPlan]
    unmatched_review_rows: list[dict[str, Any]]
    unmatched_terminal_rows: list[dict[str, Any]]
    manual_filter_path: Path

    def runtime_payload(self) -> dict[str, Any]:
        """Serialize the prepared inputs into the runtime metadata shape."""
        sources_payload: dict[str, dict[str, Any]] = {}
        for prepared_entry in self.prepared_entries:
            source_payload = sources_payload.setdefault(
                prepared_entry.source_id,
                {
                    "source_index": prepared_entry.source_index,
                    "entries": [],
                },
            )
            source_payload["entries"].append(
                {
                    "host": prepared_entry.entry.host,
                    "input_name": prepared_entry.entry.input_name,
                    "registrable_domain": prepared_entry.entry.registrable_domain,
                    "public_suffix": prepared_entry.entry.public_suffix,
                    "is_public_suffix_input": prepared_entry.entry.is_public_suffix_input,
                    "input_kind": prepared_entry.entry.input_kind,
                    "apex_scope": prepared_entry.entry.apex_scope,
                    "source_format": prepared_entry.entry.source_format,
                    "raw_line": prepared_entry.raw_line,
                    "line_index": prepared_entry.line_index,
                    "manual_filter_pass": prepared_entry.manual_filter_pass,
                    "source_ids": list(prepared_entry.source_ids),
                    "source_input_labels": list(prepared_entry.source_input_labels),
                }
            )
        ordered_sources = dict(
            sorted(
                sources_payload.items(),
                key=lambda item: (int(item[1]["source_index"]), item[0]),
            )
        )
        return {
            "prepared_source_ids": [job.source_id for job in self.jobs],
            "sources": ordered_sources,
            "rdap_roots": {
                registrable_domain: {
                    "status": plan.status,
                    "authoritative_base_url": plan.authoritative_base_url,
                }
                for registrable_domain, plan in sorted(self.root_plans.items())
            },
            "terminal_rows": [dict(row) for row in self.unmatched_terminal_rows],
        }

    def split_entries_for_planning(
        self,
    ) -> tuple[dict[str, list[PreparedHostEntry]], list[PreparedHostEntry]]:
        """Split prepared entries into RDAP-root and public-suffix planning groups."""
        eligible_root_entries: dict[str, list[PreparedHostEntry]] = defaultdict(list)
        public_suffix_entries: list[PreparedHostEntry] = []
        for prepared_entry in self.prepared_entries:
            registrable_domain = prepared_entry.entry.registrable_domain
            if prepared_entry.entry.is_public_suffix_input or not registrable_domain:
                public_suffix_entries.append(prepared_entry)
                continue
            eligible_root_entries[registrable_domain].append(prepared_entry)
        return eligible_root_entries, public_suffix_entries


def _resolve_from_root(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def _execution_profile_fingerprint(source_config: dict[str, Any]) -> str:
    """Return the classification-relevant execution fingerprint for one source."""
    payload = {
        "dns": source_config["dns"],
        "rdap": source_config["rdap"],
        "geo": source_config["geo"],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _prepared_entries_for_job(
    *,
    parser: DomainListParser,
    job: SourceJob,
    source_index: int,
) -> list[PreparedHostEntry]:
    """Return parser-backed prepared entries for one source job."""
    records = list(
        parser.process_entry_records(
            job.lines,
            source_name=job.input_label,
        )
    )
    return [
        PreparedHostEntry(
            source_id=job.source_id,
            source_index=source_index,
            entry=record.entry,
            raw_line=record.raw_line,
            line_index=record.line_index,
            source_ids=(job.source_id,),
            source_input_labels=(job.input_label,),
        )
        for record in records
    ]


def load_manual_filter_pass_hosts(
    *,
    source_root: Path,
    config: dict[str, Any],
) -> tuple[Path, set[str]]:
    """Return the shared manual-pass file path and parsed host set."""
    manual_filter_path = (
        source_root / "input" / "manual_filter_pass" / f"{config['config_name']}.txt"
    )
    if not manual_filter_path.is_file():
        return manual_filter_path, set()

    enabled_sources = [source for source in config["sources"] if source["enabled"]]
    dns_enabled_values = {
        bool(source["dns"].get("enabled", True)) for source in enabled_sources
    }
    if len(dns_enabled_values) > 1:
        raise ValueError(
            "manual filter-pass file "
            f"{manual_filter_path} requires all enabled sources in one config "
            "to share dns.enabled because manual filter-pass behavior is config-scoped"
        )
    if not next(iter(dns_enabled_values), False):
        raise ValueError(
            "manual filter-pass file "
            f"{manual_filter_path} is not supported for RDAP-only mode "
            "(all enabled sources have dns.enabled=false)"
        )

    parser = DomainListParser()
    hosts = {
        entry.host
        for entry in parser.process_entries(
            manual_filter_path.read_text(encoding="utf-8").splitlines(keepends=True),
            source_name=str(manual_filter_path),
            stats=Counter(),
            forced_format=InputFileFormat.PLAIN,
        )
    }
    return manual_filter_path, hosts


def _unmatched_manual_filter_row(
    *,
    host: str,
    manual_filter_path: Path,
) -> dict[str, Any]:
    """Return one shared terminal review/audit row for a manual-pass host absent from sources."""
    manual_filter_path_str = str(manual_filter_path)
    return {
        "source_id": "manual_filter_pass_unmatched",
        "source_input_label": manual_filter_path_str,
        "source_ids": ["manual_filter_pass_unmatched"],
        "source_input_labels": [manual_filter_path_str],
        "input_name": host,
        "host": host,
        "registrable_domain": host,
        "public_suffix": "",
        "is_public_suffix_input": False,
        "input_kind": "exact_host",
        "apex_scope": "exact_only",
        "source_format": "plain",
        "classification": CLASSIFICATION_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
        "classification_reason": (
            "manual filter-pass host was not present in any configured source"
        ),
        "route": "review",
        "rdap_registration_status": "unavailable",
        "dns_status": "skipped",
        "canonical_name": "",
        "resolved_ips": [],
        "geo_status": "skipped",
        "geo_reason": "manual_filter_pass_not_in_sources",
        "geo_policy_status": "skipped",
        "geo_policy_reason": "manual_filter_pass_not_in_sources",
        "geo_provider": "",
        "geo_countries": [],
        "geo_region_codes": [],
        "geo_region_names": [],
    }


def prepare_inputs(
    *,
    source_root: Path,
    config_path: Path,
) -> PreparedInputSet:
    """Load shared prepared inputs for workflow preparation and worker runtime."""
    resolved_config_path = _resolve_from_root(source_root, config_path)
    config = load_config(resolved_config_path)
    jobs = build_source_jobs(config)
    if not jobs:
        raise ValueError(f"config {config_path} produced no runnable source jobs")

    manual_filter_path, manual_filter_hosts = load_manual_filter_pass_hosts(
        source_root=source_root,
        config=config,
    )
    parser = DomainListParser()
    source_jobs_by_id = {job.source_id: job for job in jobs}
    checker_cache: dict[str, Any] = {}
    collapsed_entries: dict[str, PreparedHostEntry] = {}
    execution_profiles_by_host: dict[str, str] = {}

    for source_index, job in enumerate(jobs):
        checker_cache[job.source_id] = build_checker(job.config)
        execution_profile = _execution_profile_fingerprint(job.config)
        prepared_entries = _prepared_entries_for_job(
            parser=parser,
            job=job,
            source_index=source_index,
        )
        logger.debug(
            "Shared preparation source=%s parsed_entries=%d",
            job.source_id,
            len(prepared_entries),
        )
        for prepared_entry in prepared_entries:
            host = prepared_entry.entry.host
            existing = collapsed_entries.get(host)
            if existing is None:
                collapsed_entries[host] = replace(
                    prepared_entry,
                    manual_filter_pass=host in manual_filter_hosts,
                )
                execution_profiles_by_host[host] = execution_profile
                continue
            if execution_profiles_by_host[host] != execution_profile:
                raise ValueError(
                    "duplicate host "
                    f"{host!r} appears in multiple enabled sources with different "
                    "effective runtime behavior; conflicting sources are "
                    f"{existing.source_id!r} and {job.source_id!r}"
                )
            collapsed_entries[host] = replace(
                existing,
                manual_filter_pass=existing.manual_filter_pass
                or host in manual_filter_hosts,
                source_ids=existing.source_ids + (job.source_id,),
                source_input_labels=existing.source_input_labels + (job.input_label,),
            )

    eligible_root_entries: dict[str, list[PreparedHostEntry]] = defaultdict(list)
    public_suffix_entries: list[PreparedHostEntry] = []
    for prepared_entry in collapsed_entries.values():
        registrable_domain = prepared_entry.entry.registrable_domain
        if prepared_entry.entry.is_public_suffix_input or not registrable_domain:
            public_suffix_entries.append(prepared_entry)
            continue
        eligible_root_entries[registrable_domain].append(prepared_entry)

    root_plans: dict[str, PreparedRootPlan] = {}
    for registrable_domain, entries in sorted(eligible_root_entries.items()):
        source_id = entries[0].source_id
        checker = checker_cache[source_id]
        try:
            authoritative_base_url = (
                checker._authoritative_base_url(  # pylint: disable=protected-access
                    registrable_domain
                )
            )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.warning(
                "RDAP preparation could not resolve authoritative server for "
                "root=%s source=%s: %s",
                registrable_domain,
                source_id,
                exc,
            )
            root_plans[registrable_domain] = PreparedRootPlan(
                registrable_domain=registrable_domain,
                status="unknown",
            )
            continue
        if authoritative_base_url is None:
            root_plans[registrable_domain] = PreparedRootPlan(
                registrable_domain=registrable_domain,
                status="unavailable",
            )
            continue
        root_plans[registrable_domain] = PreparedRootPlan(
            registrable_domain=registrable_domain,
            status="resolved",
            authoritative_base_url=authoritative_base_url,
        )

    matched_manual_hosts = {
        prepared_entry.entry.host
        for prepared_entry in collapsed_entries.values()
        if prepared_entry.manual_filter_pass
    }
    unmatched_manual_hosts = sorted(manual_filter_hosts - matched_manual_hosts)
    unmatched_rows = [
        _unmatched_manual_filter_row(
            host=host,
            manual_filter_path=manual_filter_path,
        )
        for host in unmatched_manual_hosts
    ]
    return PreparedInputSet(
        config=config,
        jobs=jobs,
        source_jobs_by_id=source_jobs_by_id,
        prepared_entries=list(collapsed_entries.values()),
        root_plans=root_plans,
        unmatched_review_rows=unmatched_rows,
        unmatched_terminal_rows=[dict(row) for row in unmatched_rows],
        manual_filter_path=manual_filter_path,
    )
