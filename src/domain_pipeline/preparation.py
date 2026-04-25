"""Shared preparation helpers for workflow-owned automation runs."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, replace
import json
import logging
from pathlib import Path
from typing import Any

from domain_pipeline.classifications import (
    CLASSIFICATION_MANUAL_FILTER_OUT,
    CLASSIFICATION_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
    CLASSIFICATION_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
)
from domain_pipeline.io.parser import (
    DomainListParser,
    InputFileFormat,
    ParsedDomainEntry,
    ParsedDomainEntryRecord,
)
from domain_pipeline.runtime.pure_helpers import row_identity_fields
from domain_pipeline.runtime.pipeline_runner import build_checker, build_source_jobs
from domain_pipeline.settings.config import load_config
from domain_pipeline.shared import SourceJob

logger = logging.getLogger(__name__)
MANUAL_ADD_SOURCE_ID = "manual_add"


@dataclass(frozen=True)
class PreparedRootPlan:
    """Preparation-time RDAP metadata for one registrable domain."""

    registrable_domain: str
    status: str
    authoritative_base_url: str | None = None


@dataclass(frozen=True)
class PreparedHostEntry:  # pylint: disable=too-many-instance-attributes
    """One shared prepared host entry with runtime ownership and output overrides."""

    source_id: str
    source_index: int
    entry: ParsedDomainEntry
    raw_line: str
    line_index: int
    manual_filter_pass: bool = False
    manual_add: bool = False
    source_id_override: str | None = None
    source_input_label_override: str | None = None
    source_ids: tuple[str, ...] = ()
    source_input_labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class PreparedInputSet:
    """Prepared inputs shared across workflow preparation and worker runtime."""

    config: dict[str, Any]
    jobs: list[SourceJob]
    source_jobs_by_id: dict[str, SourceJob]
    prepared_entries: list[PreparedHostEntry]
    root_plans: dict[str, PreparedRootPlan]
    preparation_review_rows: list[dict[str, Any]]
    preparation_terminal_rows: list[dict[str, Any]]

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
                    "manual_add": prepared_entry.manual_add,
                    "source_id_override": prepared_entry.source_id_override,
                    "source_input_label_override": (
                        prepared_entry.source_input_label_override
                    ),
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
            "terminal_rows": [dict(row) for row in self.preparation_terminal_rows],
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


def _rdap_profile_fingerprint(source_config: dict[str, Any]) -> str:
    """Return the RDAP-relevant fingerprint for one source."""
    return json.dumps(source_config["rdap"], sort_keys=True, separators=(",", ":"))


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


def _load_manual_filter_hosts(
    *,
    source_root: Path,
    config_name: str,
    directory_name: str,
) -> tuple[Path, set[str]]:
    manual_filter_path = source_root / "input" / directory_name / f"{config_name}.txt"
    if not manual_filter_path.is_file():
        return manual_filter_path, set()

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


def _load_manual_add_records(
    *,
    source_root: Path,
    config_name: str,
) -> tuple[Path, dict[str, ParsedDomainEntryRecord]]:
    """Return the manual-add file path and first-seen parsed entry records."""
    manual_add_path = source_root / "input" / "manual_add" / f"{config_name}.txt"
    if not manual_add_path.is_file():
        return manual_add_path, {}

    parser = DomainListParser()
    records_by_host: dict[str, ParsedDomainEntryRecord] = {}
    for record in parser.process_entry_records(
        manual_add_path.read_text(encoding="utf-8").splitlines(keepends=True),
        source_name=str(manual_add_path),
        stats=Counter(),
        forced_format=InputFileFormat.PLAIN,
    ):
        if record.entry.is_public_suffix_input:
            raise ValueError(
                "manual-add file "
                f"{manual_add_path} does not support public suffix inputs such as "
                f"{record.entry.host!r} because manual-add hosts must run through RDAP"
            )
        records_by_host.setdefault(record.entry.host, record)
    return manual_add_path, records_by_host


def load_manual_filter_pass_hosts(
    *,
    source_root: Path,
    config: dict[str, Any],
) -> tuple[Path, set[str]]:
    """Return the shared manual-pass file path and parsed host set."""
    manual_filter_path, hosts = _load_manual_filter_hosts(
        source_root=source_root,
        config_name=str(config["config_name"]),
        directory_name="manual_filter_pass",
    )
    _validate_manual_filter_pass_hosts(
        config=config,
        manual_filter_path=manual_filter_path,
        hosts=hosts,
    )
    return manual_filter_path, hosts


def _validate_manual_filter_pass_hosts(
    *,
    config: dict[str, Any],
    manual_filter_path: Path,
    hosts: set[str],
) -> None:
    """Validate config-scoped manual-pass semantics after file parsing."""
    if not hosts:
        return

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


def load_manual_filter_out_hosts(
    *,
    source_root: Path,
    config: dict[str, Any],
) -> tuple[Path, set[str]]:
    """Return the shared manual-reject file path and parsed host set."""
    return _load_manual_filter_hosts(
        source_root=source_root,
        config_name=str(config["config_name"]),
        directory_name="manual_filter_out",
    )


def _validate_manual_add_records(
    *,
    config: dict[str, Any],
    manual_add_path: Path,
    records_by_host: dict[str, ParsedDomainEntryRecord],
) -> None:
    """Validate config-scoped manual-add semantics after file parsing."""
    if not records_by_host:
        return

    enabled_sources = [source for source in config["sources"] if source["enabled"]]
    rdap_fingerprints = {
        _rdap_profile_fingerprint(source) for source in enabled_sources
    }
    if len(rdap_fingerprints) > 1:
        raise ValueError(
            "manual-add file "
            f"{manual_add_path} requires all enabled sources in one config "
            "to share RDAP settings because manual-add behavior is config-scoped"
        )


def _manual_add_override_entry(
    *,
    record: ParsedDomainEntryRecord,
    carrier_job: SourceJob,
    source_index: int,
    manual_add_path: Path,
) -> PreparedHostEntry:
    """Return one prepared manual-add entry owned by the carrier source job."""
    manual_add_path_str = str(manual_add_path)
    return PreparedHostEntry(
        source_id=carrier_job.source_id,
        source_index=source_index,
        entry=record.entry,
        raw_line=record.raw_line,
        line_index=record.line_index,
        manual_add=True,
        source_id_override=MANUAL_ADD_SOURCE_ID,
        source_input_label_override=manual_add_path_str,
        source_ids=(MANUAL_ADD_SOURCE_ID,),
        source_input_labels=(manual_add_path_str,),
    )


def _manual_filter_pass_not_in_sources_row(
    *,
    host: str,
    manual_filter_path: Path,
) -> dict[str, Any]:
    """Return one preparation-owned row for a manual-pass host absent from sources."""
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


def _matched_manual_filter_out_row(prepared_entry: PreparedHostEntry) -> dict[str, Any]:
    """Return one preparation-owned row for a matched manual-reject host."""
    entry = prepared_entry.entry
    source_input_labels = list(prepared_entry.source_input_labels)
    return {
        **row_identity_fields(
            source_id=prepared_entry.source_id,
            source_input_label=source_input_labels[0],
            source_ids=list(prepared_entry.source_ids),
            source_input_labels=source_input_labels,
            entry=entry,
        ),
        "classification": CLASSIFICATION_MANUAL_FILTER_OUT,
        "classification_reason": "manual filter-out host was explicitly rejected",
        "route": "review",
        "rdap_registration_status": "unavailable",
        "dns_status": "skipped",
        "canonical_name": "",
        "resolved_ips": [],
        "geo_status": "skipped",
        "geo_reason": "manual_filter_out",
        "geo_policy_status": "skipped",
        "geo_policy_reason": "manual_filter_out",
        "geo_provider": "",
        "geo_countries": [],
        "geo_region_codes": [],
        "geo_region_names": [],
    }


def _manual_filter_out_not_in_sources_row(
    *,
    host: str,
    manual_filter_path: Path,
) -> dict[str, Any]:
    """Return one preparation-owned row for a manual-reject host absent from sources."""
    manual_filter_path_str = str(manual_filter_path)
    parsed_entry = next(
        DomainListParser().process_entries(
            [f"{host}\n"],
            source_name=manual_filter_path_str,
            forced_format=InputFileFormat.PLAIN,
        )
    )
    return {
        "source_id": "manual_filter_out_unmatched",
        "source_input_label": manual_filter_path_str,
        "source_ids": ["manual_filter_out_unmatched"],
        "source_input_labels": [manual_filter_path_str],
        "input_name": host,
        "host": host,
        "registrable_domain": parsed_entry.registrable_domain,
        "public_suffix": parsed_entry.public_suffix,
        "is_public_suffix_input": parsed_entry.is_public_suffix_input,
        "input_kind": parsed_entry.input_kind,
        "apex_scope": parsed_entry.apex_scope,
        "source_format": parsed_entry.source_format,
        "classification": CLASSIFICATION_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
        "classification_reason": (
            "manual filter-out host was not present in any configured source"
        ),
        "route": "review",
        "rdap_registration_status": "unavailable",
        "dns_status": "skipped",
        "canonical_name": "",
        "resolved_ips": [],
        "geo_status": "skipped",
        "geo_reason": "manual_filter_out_not_in_sources",
        "geo_policy_status": "skipped",
        "geo_policy_reason": "manual_filter_out_not_in_sources",
        "geo_provider": "",
        "geo_countries": [],
        "geo_region_codes": [],
        "geo_region_names": [],
    }


def _resolve_root_plan(  # pylint: disable=protected-access,broad-exception-caught
    *,
    checker: Any,
    registrable_domain: str,
    source_id: str,
) -> PreparedRootPlan:
    """Return preparation-time RDAP metadata for one registrable domain."""
    try:
        authoritative_base_url = checker._authoritative_base_url(registrable_domain)
    except Exception as exc:
        logger.warning(
            "RDAP preparation could not resolve authoritative server for "
            "root=%s source=%s: %s",
            registrable_domain,
            source_id,
            exc,
        )
        return PreparedRootPlan(
            registrable_domain=registrable_domain,
            status="unknown",
        )
    if authoritative_base_url is None:
        return PreparedRootPlan(
            registrable_domain=registrable_domain,
            status="unavailable",
        )
    return PreparedRootPlan(
        registrable_domain=registrable_domain,
        status="resolved",
        authoritative_base_url=authoritative_base_url,
    )


def _manual_filter_preparation_rows(
    *,
    collapsed_entries: dict[str, PreparedHostEntry],
    manual_filter_pass_hosts: set[str],
    manual_filter_pass_path: Path,
    manual_filter_out_entries: dict[str, PreparedHostEntry],
    manual_filter_out_hosts: set[str],
    manual_filter_out_path: Path,
) -> list[dict[str, Any]]:
    """Build all preparation-owned review/raw rows from manual filter files."""
    matched_manual_hosts = {
        prepared_entry.entry.host
        for prepared_entry in collapsed_entries.values()
        if prepared_entry.manual_filter_pass
    }
    unmatched_manual_pass_hosts = sorted(
        manual_filter_pass_hosts - matched_manual_hosts
    )
    unmatched_manual_pass_rows = [
        _manual_filter_pass_not_in_sources_row(
            host=host,
            manual_filter_path=manual_filter_pass_path,
        )
        for host in unmatched_manual_pass_hosts
    ]
    matched_manual_filter_out_rows = [
        _matched_manual_filter_out_row(manual_filter_out_entries[host])
        for host in sorted(manual_filter_out_entries)
    ]
    unmatched_manual_filter_out_hosts = sorted(
        manual_filter_out_hosts - set(manual_filter_out_entries)
    )
    unmatched_manual_filter_out_rows = [
        _manual_filter_out_not_in_sources_row(
            host=host,
            manual_filter_path=manual_filter_out_path,
        )
        for host in unmatched_manual_filter_out_hosts
    ]
    return [
        *matched_manual_filter_out_rows,
        *unmatched_manual_filter_out_rows,
        *unmatched_manual_pass_rows,
    ]


# pylint: disable=too-many-statements
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
    carrier_job = jobs[0]
    source_index_by_id = {
        job.source_id: source_index for source_index, job in enumerate(jobs)
    }

    manual_filter_pass_path, manual_filter_pass_hosts = _load_manual_filter_hosts(
        source_root=source_root,
        config_name=str(config["config_name"]),
        directory_name="manual_filter_pass",
    )
    manual_filter_out_path, manual_filter_out_hosts = load_manual_filter_out_hosts(
        source_root=source_root,
        config=config,
    )
    manual_add_path, manual_add_records = _load_manual_add_records(
        source_root=source_root,
        config_name=str(config["config_name"]),
    )
    manual_add_hosts = set(manual_add_records)
    overlapping_manual_hosts = sorted(
        manual_filter_pass_hosts & manual_filter_out_hosts
    )
    if overlapping_manual_hosts:
        conflicting_host = overlapping_manual_hosts[0]
        raise ValueError(
            "host "
            f"{conflicting_host!r} appears in both manual filter files "
            f"{manual_filter_pass_path} and {manual_filter_out_path}"
        )
    overlapping_manual_add_pass_hosts = sorted(
        manual_add_hosts & manual_filter_pass_hosts
    )
    if overlapping_manual_add_pass_hosts:
        conflicting_host = overlapping_manual_add_pass_hosts[0]
        raise ValueError(
            "host "
            f"{conflicting_host!r} appears in both manual-add file "
            f"{manual_add_path} and manual filter-pass file {manual_filter_pass_path}"
        )
    overlapping_manual_add_out_hosts = sorted(
        manual_add_hosts & manual_filter_out_hosts
    )
    if overlapping_manual_add_out_hosts:
        conflicting_host = overlapping_manual_add_out_hosts[0]
        raise ValueError(
            "host "
            f"{conflicting_host!r} appears in both manual-add file "
            f"{manual_add_path} and manual filter-out file {manual_filter_out_path}"
        )
    _validate_manual_filter_pass_hosts(
        config=config,
        manual_filter_path=manual_filter_pass_path,
        hosts=manual_filter_pass_hosts,
    )
    _validate_manual_add_records(
        config=config,
        manual_add_path=manual_add_path,
        records_by_host=manual_add_records,
    )
    parser = DomainListParser()
    source_jobs_by_id = {job.source_id: job for job in jobs}
    checker_cache: dict[str, Any] = {}
    collapsed_entries: dict[str, PreparedHostEntry] = {}
    manual_filter_out_entries: dict[str, PreparedHostEntry] = {}
    execution_profiles_by_host: dict[str, str] = {}
    rdap_profiles_by_host: dict[str, str] = {}
    first_source_id_by_host: dict[str, str] = {}
    manual_add_entries = {
        host: _manual_add_override_entry(
            record=record,
            carrier_job=carrier_job,
            source_index=source_index_by_id[carrier_job.source_id],
            manual_add_path=manual_add_path,
        )
        for host, record in manual_add_records.items()
    }

    for source_index, job in enumerate(jobs):
        checker_cache[job.source_id] = build_checker(job.config)
        execution_profile = _execution_profile_fingerprint(job.config)
        rdap_profile = _rdap_profile_fingerprint(job.config)
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
            if host in manual_filter_out_hosts:
                existing = manual_filter_out_entries.get(host)
                if existing is None:
                    manual_filter_out_entries[host] = prepared_entry
                    continue
                manual_filter_out_entries[host] = replace(
                    existing,
                    source_ids=existing.source_ids + (job.source_id,),
                    source_input_labels=existing.source_input_labels
                    + (job.input_label,),
                )
                continue
            if host in manual_add_entries:
                existing = collapsed_entries.get(host)
                if existing is None:
                    collapsed_entries[host] = manual_add_entries[host]
                    rdap_profiles_by_host[host] = rdap_profile
                    first_source_id_by_host[host] = job.source_id
                    continue
                if rdap_profiles_by_host[host] != rdap_profile:
                    raise ValueError(
                        "duplicate host "
                        f"{host!r} appears in multiple enabled sources with different "
                        "effective RDAP behavior while manual-add overrides it; "
                        "conflicting sources are "
                        f"{first_source_id_by_host[host]!r} and {job.source_id!r}"
                    )
                continue
            existing = collapsed_entries.get(host)
            if existing is None:
                collapsed_entries[host] = replace(
                    prepared_entry,
                    manual_filter_pass=host in manual_filter_pass_hosts,
                )
                execution_profiles_by_host[host] = execution_profile
                first_source_id_by_host[host] = job.source_id
                continue
            if execution_profiles_by_host[host] != execution_profile:
                raise ValueError(
                    "duplicate host "
                    f"{host!r} appears in multiple enabled sources with different "
                    "effective runtime behavior; conflicting sources are "
                    f"{first_source_id_by_host[host]!r} and {job.source_id!r}"
                )
            collapsed_entries[host] = replace(
                existing,
                manual_filter_pass=existing.manual_filter_pass
                or host in manual_filter_pass_hosts,
                source_ids=existing.source_ids + (job.source_id,),
                source_input_labels=existing.source_input_labels + (job.input_label,),
            )
    for host, manual_add_entry in manual_add_entries.items():
        collapsed_entries.setdefault(host, manual_add_entry)

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
        root_plans[registrable_domain] = _resolve_root_plan(
            checker=checker_cache[source_id],
            registrable_domain=registrable_domain,
            source_id=source_id,
        )

    preparation_rows = _manual_filter_preparation_rows(
        collapsed_entries=collapsed_entries,
        manual_filter_pass_hosts=manual_filter_pass_hosts,
        manual_filter_pass_path=manual_filter_pass_path,
        manual_filter_out_entries=manual_filter_out_entries,
        manual_filter_out_hosts=manual_filter_out_hosts,
        manual_filter_out_path=manual_filter_out_path,
    )
    return PreparedInputSet(
        config=config,
        jobs=jobs,
        source_jobs_by_id=source_jobs_by_id,
        prepared_entries=list(collapsed_entries.values()),
        root_plans=root_plans,
        preparation_review_rows=preparation_rows,
        preparation_terminal_rows=[dict(row) for row in preparation_rows],
    )
