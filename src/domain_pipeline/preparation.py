"""Shared input preparation for workflow-owned automation runs."""

# pylint: disable=too-many-instance-attributes,too-many-statements

from __future__ import annotations

import dataclasses
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from domain_pipeline.classifications import (
    CLASSIFICATION_INPUT_PUBLIC_SUFFIX,
    CLASSIFICATION_MANUAL_FILTER_OUT,
    CLASSIFICATION_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
    CLASSIFICATION_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
)
from domain_pipeline.checking.domain_checker import (
    delegation_dns_profile,
    host_resolution_dns_profile,
)
from domain_pipeline.io.parser import DomainListParser, ParsedDomainEntry
from domain_pipeline.runtime.pipeline_runner import build_source_jobs
from domain_pipeline.runtime.pure_helpers import build_base_row
from domain_pipeline.settings.config import load_config_without_runtime_credentials
from domain_pipeline.shared import SourceJob

MANUAL_ADD_SOURCE_ID = "manual_add"


@dataclasses.dataclass(frozen=True)
class PreparedRootPlan:
    """Preparation-time delegation metadata for one registrable domain."""

    registrable_domain: str
    status: str = "pending"


@dataclasses.dataclass(frozen=True)
class PreparedHostEntry:
    """One prepared parsed entry and its source provenance."""

    source_id: str
    source_index: int
    line_index: int
    raw_line: str
    entry: ParsedDomainEntry
    manual_filter_pass: bool = False
    manual_add: bool = False
    source_id_override: str | None = None
    source_input_label_override: str | None = None
    source_ids: tuple[str, ...] = ()
    source_input_labels: tuple[str, ...] = ()


@dataclasses.dataclass
class PreparedInputSet:
    """Prepared entries, root plans, and preparation-owned terminal rows."""

    config: dict[str, Any]
    source_jobs_by_id: dict[str, SourceJob]
    entries_by_source: dict[str, list[PreparedHostEntry]]
    root_plans: dict[str, PreparedRootPlan]
    preparation_review_rows: list[dict[str, Any]]
    preparation_terminal_rows: list[dict[str, Any]]

    def split_entries_for_planning(
        self,
    ) -> tuple[dict[str, list[PreparedHostEntry]], list[PreparedHostEntry]]:
        """Split prepared entries into delegation-root and public-suffix groups."""
        root_entries: dict[str, list[PreparedHostEntry]] = defaultdict(list)
        public_suffix_entries: list[PreparedHostEntry] = []
        for entries in self.entries_by_source.values():
            for entry in entries:
                if (
                    entry.entry.is_public_suffix_input
                    or not entry.entry.registrable_domain
                ):
                    public_suffix_entries.append(entry)
                else:
                    root_entries[entry.entry.registrable_domain].append(entry)
        return dict(root_entries), public_suffix_entries


def root_plan_runtime_payload(plan: PreparedRootPlan) -> dict[str, Any]:
    """Serialize prepared delegation root metadata for worker runtime."""
    return dataclasses.asdict(plan)


def _resolve_from_root(source_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else source_root / path


def _manual_path(source_root: Path, directory: str, config_name: str) -> Path:
    return source_root / "input" / directory / f"{config_name}.txt"


def _load_manual_entries(path: Path) -> dict[str, ParsedDomainEntry]:
    if not path.is_file():
        return {}
    parser = DomainListParser()
    entries: dict[str, ParsedDomainEntry] = {}
    for entry in parser.process_entries(
        path.read_text(encoding="utf-8").splitlines(keepends=True)
    ):
        entries[entry.host] = entry
    return entries


def _manual_review_row(
    *,
    job: SourceJob,
    entry: ParsedDomainEntry,
    classification: str,
    input_label: str,
    source_ids: tuple[str, ...] | None = None,
    source_input_labels: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    return build_base_row(
        job=job,
        entry=entry,
        classification=classification,
        source_id_override=classification,
        source_input_label_override=input_label,
        source_ids=source_ids or (classification,),
        source_input_labels=source_input_labels or (input_label,),
    )


def _public_suffix_review_row(
    *,
    job: SourceJob,
    prepared_entry: PreparedHostEntry,
) -> dict[str, Any]:
    """Return the prepare-owned terminal row for one public suffix input."""
    return build_base_row(
        job=job,
        entry=prepared_entry.entry,
        classification=CLASSIFICATION_INPUT_PUBLIC_SUFFIX,
        source_id_override=prepared_entry.source_id_override,
        source_input_label_override=prepared_entry.source_input_label_override,
        source_ids=prepared_entry.source_ids,
        source_input_labels=prepared_entry.source_input_labels,
    )


def _canonical_delegation_dns_behavior(dns_config: dict[str, Any]) -> dict[str, Any]:
    delegation_config = dict(dns_config["delegation"])
    return {
        **delegation_dns_profile(dns_config),
        "retry_attempts": delegation_config["retry_attempts"],
    }


def _canonical_host_resolution_dns_behavior(
    dns_config: dict[str, Any],
) -> dict[str, Any]:
    host_resolution_config = dict(dns_config["host_resolution"])
    return {
        **host_resolution_dns_profile(dns_config),
        "enabled": host_resolution_config["enabled"],
        "retry_attempts": host_resolution_config["retry_attempts"],
    }


def _canonical_dns_behavior(dns_config: dict[str, Any]) -> dict[str, Any]:
    return {
        "delegation": _canonical_delegation_dns_behavior(dns_config),
        "host_resolution": _canonical_host_resolution_dns_behavior(dns_config),
    }


def _source_behavior_fingerprint(source_config: dict[str, Any]) -> str:
    payload = {
        "dns": _canonical_dns_behavior(source_config["dns"]),
        "geo": source_config["geo"],
        "output": source_config["output"],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _manual_add_behavior_fingerprint(source_config: dict[str, Any]) -> str:
    """Return the delegation/output behavior used by config-scoped manual_add."""
    dns_config = source_config["dns"]
    payload = {
        "dns": {"delegation": _canonical_delegation_dns_behavior(dns_config)},
        "output": source_config["output"],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _stable_unique_merge(
    first: tuple[str, ...], second: tuple[str, ...]
) -> tuple[str, ...]:
    """Return first-seen unique values from two provenance tuples."""
    merged: list[str] = []
    seen: set[str] = set()
    for value in (*first, *second):
        if value in seen:
            continue
        seen.add(value)
        merged.append(value)
    return tuple(merged)


def _merge_prepared_entries(
    current: PreparedHostEntry, incoming: PreparedHostEntry
) -> PreparedHostEntry:
    """Merge same-host prepared entries while preserving the earliest ordering."""
    return dataclasses.replace(
        current,
        manual_filter_pass=current.manual_filter_pass or incoming.manual_filter_pass,
        manual_add=current.manual_add or incoming.manual_add,
        source_ids=_stable_unique_merge(current.source_ids, incoming.source_ids),
        source_input_labels=_stable_unique_merge(
            current.source_input_labels, incoming.source_input_labels
        ),
    )


def _merge_entry_by_host(
    entries_by_host: dict[str, PreparedHostEntry],
    incoming: PreparedHostEntry,
) -> None:
    """Insert or merge one prepared entry by final output host."""
    host = incoming.entry.host
    current = entries_by_host.get(host)
    if current is None:
        entries_by_host[host] = incoming
        return
    entries_by_host[host] = _merge_prepared_entries(current, incoming)


def prepare_inputs(
    *,
    source_root: Path,
    config_path: Path,
) -> PreparedInputSet:
    """Load config and prepare worker entries plus prepare-owned terminal rows."""
    resolved_config_path = _resolve_from_root(source_root, config_path)
    config = load_config_without_runtime_credentials(resolved_config_path)
    config_name = str(config["config_name"])
    jobs = build_source_jobs(config, source_root=source_root)
    source_jobs_by_id = {job.source_id: job for job in jobs}
    if not jobs:
        raise ValueError("config produced no enabled source jobs")

    manual_pass_path = _manual_path(source_root, "manual_filter_pass", config_name)
    manual_out_path = _manual_path(source_root, "manual_filter_out", config_name)
    manual_add_path = _manual_path(source_root, "manual_add", config_name)
    manual_pass_entries = _load_manual_entries(manual_pass_path)
    manual_out_entries = _load_manual_entries(manual_out_path)
    manual_add_entries = _load_manual_entries(manual_add_path)
    if set(manual_add_entries) & set(manual_pass_entries):
        raise ValueError(
            f"{manual_add_path} conflicts with manual filter-pass file {manual_pass_path}"
        )
    if set(manual_add_entries) & set(manual_out_entries):
        raise ValueError(
            f"{manual_add_path} conflicts with manual filter-out file {manual_out_path}"
        )

    parser = DomainListParser()
    entries_by_host: dict[str, PreparedHostEntry] = {}
    manual_out_by_host: dict[str, PreparedHostEntry] = {}
    preparation_review_rows: list[dict[str, Any]] = []
    preparation_terminal_rows: list[dict[str, Any]] = []
    host_fingerprints: dict[str, str] = {}
    manual_add_fingerprints_by_host: dict[str, str] = {}
    matched_hosts: set[str] = set()

    for source_index, job in enumerate(jobs):
        source_format = job.config.get("input", {}).get("format", "auto")
        for record in parser.process_entry_records(
            job.lines,
            source_name=job.input_label,
            forced_format=None if source_format == "auto" else source_format,
        ):
            host = record.entry.host
            matched_hosts.add(host)
            if host in manual_add_entries:
                fingerprint = _manual_add_behavior_fingerprint(job.config)
                previous = manual_add_fingerprints_by_host.get(host)
                if previous is not None and previous != fingerprint:
                    raise ValueError(
                        f"manual-add host {host!r} appears in multiple enabled "
                        "sources with different delegation/output behavior"
                    )
                manual_add_fingerprints_by_host[host] = fingerprint
            else:
                fingerprint = _source_behavior_fingerprint(job.config)
                previous = host_fingerprints.get(host)
                if previous is not None and previous != fingerprint:
                    raise ValueError(
                        f"duplicate host {host!r} has conflicting dns/geo/output behavior"
                    )
                host_fingerprints[host] = fingerprint
            prepared_entry = PreparedHostEntry(
                source_id=job.source_id,
                source_index=source_index,
                line_index=record.line_index,
                raw_line=record.raw_line,
                entry=record.entry,
                manual_filter_pass=host in manual_pass_entries,
                source_ids=(job.source_id,),
                source_input_labels=(job.input_label,),
            )
            if host in manual_out_entries:
                _merge_entry_by_host(manual_out_by_host, prepared_entry)
                continue
            _merge_entry_by_host(entries_by_host, prepared_entry)

    for host in sorted(manual_out_by_host):
        prepared_entry = manual_out_by_host[host]
        source_ids = _stable_unique_merge(
            (CLASSIFICATION_MANUAL_FILTER_OUT,), prepared_entry.source_ids
        )
        source_input_labels = _stable_unique_merge(
            (str(manual_out_path),), prepared_entry.source_input_labels
        )
        row = _manual_review_row(
            job=source_jobs_by_id[prepared_entry.source_id],
            entry=prepared_entry.entry,
            classification=CLASSIFICATION_MANUAL_FILTER_OUT,
            input_label=str(manual_out_path),
            source_ids=source_ids,
            source_input_labels=source_input_labels,
        )
        preparation_review_rows.append(row)
        preparation_terminal_rows.append({**row, "route": "review"})

    primary_job = jobs[0]
    manual_add_config_fingerprints = {
        _manual_add_behavior_fingerprint(job.config) for job in jobs
    }
    for host, entry in sorted(manual_add_entries.items()):
        incoming = PreparedHostEntry(
            source_id=primary_job.source_id,
            source_index=0,
            line_index=10_000_000,
            raw_line=host,
            entry=entry,
            manual_add=True,
            source_id_override=MANUAL_ADD_SOURCE_ID,
            source_input_label_override=str(manual_add_path),
            source_ids=(MANUAL_ADD_SOURCE_ID,),
            source_input_labels=(str(manual_add_path),),
        )
        current = entries_by_host.get(host)
        if current is None:
            if len(manual_add_config_fingerprints) > 1:
                raise ValueError(
                    f"manual-add file {manual_add_path} contains unmatched host "
                    f"{host!r}; unmatched manual_add requires all enabled sources "
                    "to share delegation/output behavior"
                )
            entries_by_host[host] = incoming
        else:
            entries_by_host[host] = dataclasses.replace(
                current,
                manual_add=True,
                source_id_override=MANUAL_ADD_SOURCE_ID,
                source_input_label_override=str(manual_add_path),
                source_ids=_stable_unique_merge(
                    current.source_ids, (MANUAL_ADD_SOURCE_ID,)
                ),
                source_input_labels=_stable_unique_merge(
                    current.source_input_labels, (str(manual_add_path),)
                ),
            )
        matched_hosts.add(host)

    entries_by_source: dict[str, list[PreparedHostEntry]] = defaultdict(list)
    for prepared_entry in sorted(
        entries_by_host.values(),
        key=lambda current: (
            current.source_index,
            current.line_index,
            current.entry.host,
        ),
    ):
        if (
            prepared_entry.entry.is_public_suffix_input
            or not prepared_entry.entry.registrable_domain
        ):
            row = _public_suffix_review_row(
                job=source_jobs_by_id[prepared_entry.source_id],
                prepared_entry=prepared_entry,
            )
            preparation_review_rows.append(row)
            preparation_terminal_rows.append({**row, "route": "review"})
            continue
        entries_by_source[prepared_entry.source_id].append(prepared_entry)

    for host, entry in sorted(manual_pass_entries.items()):
        if host in matched_hosts:
            continue
        row = _manual_review_row(
            job=primary_job,
            entry=entry,
            classification=CLASSIFICATION_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
            input_label=str(manual_pass_path),
        )
        preparation_review_rows.append(row)
        preparation_terminal_rows.append({**row, "route": "review"})

    for host, entry in sorted(manual_out_entries.items()):
        if host in manual_out_by_host:
            continue
        row = _manual_review_row(
            job=primary_job,
            entry=entry,
            classification=CLASSIFICATION_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
            input_label=str(manual_out_path),
        )
        preparation_review_rows.append(row)
        preparation_terminal_rows.append({**row, "route": "review"})

    root_plans = {
        entry.entry.registrable_domain: PreparedRootPlan(entry.entry.registrable_domain)
        for entries in entries_by_source.values()
        for entry in entries
        if entry.entry.registrable_domain
    }
    return PreparedInputSet(
        config=config,
        source_jobs_by_id=source_jobs_by_id,
        entries_by_source=dict(entries_by_source),
        root_plans=root_plans,
        preparation_review_rows=preparation_review_rows,
        preparation_terminal_rows=preparation_terminal_rows,
    )
