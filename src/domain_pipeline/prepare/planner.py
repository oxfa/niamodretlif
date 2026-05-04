"""Prepare-step planning owner."""

# pylint: disable=import-outside-toplevel,too-many-statements

from __future__ import annotations

import dataclasses
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from domain_pipeline.prepare.classifications import (
    PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
    PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
)
from domain_pipeline.routing import route_for_pipeline_result_code
from domain_pipeline.prepare.config.loader import (
    load_config_without_runtime_credentials,
)
from domain_pipeline.prepare.sources.jobs import SourceJob, SourceJobFactory
from domain_pipeline.prepare.sources.parser import DomainListParser, ParsedDomainEntry
from domain_pipeline.worker.dns import (
    delegation_dns_profile,
    host_resolution_dns_profile,
)
from domain_pipeline.prepare.manual_inputs import ManualInputLoader
from domain_pipeline.prepare.merger import PreparedEntryMerger
from domain_pipeline.prepare.models import (
    MANUAL_ADD_SOURCE_ID,
    PreparedHostEntry,
    PreparedInputSet,
    PreparedRootPlan,
)


def _resolve_from_root(source_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else source_root / path


def _source_context_from_job(job: SourceJob) -> Any:
    from domain_pipeline.worker.runtime.contracts import WorkerSourceContext

    return WorkerSourceContext(
        source_id=job.source_id,
        input_label=job.input_label,
        output_stem=job.output_stem,
        config=job.config,
    )


def _manual_review_row(
    *,
    job: SourceJob,
    entry: ParsedDomainEntry,
    pipeline_result_code: str,
    input_label: str,
    source_ids: tuple[str, ...] | None = None,
    source_input_labels: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    from domain_pipeline.worker.output.rows import build_base_row

    return build_base_row(
        source_context=_source_context_from_job(job),
        entry=entry,
        pipeline_result_code=pipeline_result_code,
        source_id_override=pipeline_result_code,
        source_input_label_override=input_label,
        source_ids=source_ids or (pipeline_result_code,),
        source_input_labels=source_input_labels or (input_label,),
    )


def _public_suffix_review_row(
    *,
    job: SourceJob,
    prepared_entry: PreparedHostEntry,
) -> dict[str, Any]:
    from domain_pipeline.worker.output.rows import build_base_row

    return build_base_row(
        source_context=_source_context_from_job(job),
        entry=prepared_entry.entry,
        pipeline_result_code=PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX,
        source_id_override=prepared_entry.source_id_override,
        source_input_label_override=prepared_entry.source_input_label_override,
        source_ids=prepared_entry.source_ids,
        source_input_labels=prepared_entry.source_input_labels,
    )


def _preparation_terminal_row(
    *,
    row: dict[str, Any],
    pipeline_result_code: str,
) -> dict[str, Any]:
    """Return a prepare-owned terminal row with the canonical route policy."""
    return {
        **row,
        "route": route_for_pipeline_result_code(pipeline_result_code),
    }


class PreparationPlanner:
    """Prepare worker entries and prepare-owned terminal rows."""

    def __init__(
        self,
        *,
        source_root: Path,
        entry_merger: PreparedEntryMerger | None = None,
        manual_loader: ManualInputLoader | None = None,
    ) -> None:
        self.source_root = source_root
        self.entry_merger = entry_merger or PreparedEntryMerger()
        self.manual_loader = manual_loader or ManualInputLoader(source_root=source_root)

    def prepare(self, *, config_path: Path) -> PreparedInputSet:
        """Load config and prepare worker entries plus terminal rows."""
        resolved_config_path = _resolve_from_root(self.source_root, config_path)
        config = load_config_without_runtime_credentials(resolved_config_path)
        config_name = str(config["config_name"])
        jobs = SourceJobFactory().build_jobs(config, source_root=self.source_root)
        source_jobs_by_id = {job.source_id: job for job in jobs}
        if not jobs:
            raise ValueError("config produced no enabled source jobs")

        manual_inputs = self.manual_loader.load(config_name)

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
                if host in manual_inputs.add_entries:
                    fingerprint = self._manual_add_behavior_fingerprint(job.config)
                    previous = manual_add_fingerprints_by_host.get(host)
                    if previous is not None and previous != fingerprint:
                        raise ValueError(
                            f"manual-add host {host!r} appears in multiple enabled "
                            "sources with different delegation/output behavior"
                        )
                    manual_add_fingerprints_by_host[host] = fingerprint
                else:
                    fingerprint = self._source_behavior_fingerprint(job.config)
                    previous = host_fingerprints.get(host)
                    if previous is not None and previous != fingerprint:
                        raise ValueError(
                            f"duplicate host {host!r} has conflicting "
                            "dns/geo/output behavior"
                        )
                    host_fingerprints[host] = fingerprint
                prepared_entry = PreparedHostEntry(
                    source_id=job.source_id,
                    source_index=source_index,
                    line_index=record.line_index,
                    raw_line=record.raw_line,
                    entry=record.entry,
                    manual_filter_pass=host in manual_inputs.pass_entries,
                    source_ids=(job.source_id,),
                    source_input_labels=(job.input_label,),
                )
                if host in manual_inputs.out_entries:
                    self.entry_merger.merge_entry_by_host(
                        manual_out_by_host, prepared_entry
                    )
                    continue
                self.entry_merger.merge_entry_by_host(entries_by_host, prepared_entry)

        for host in sorted(manual_out_by_host):
            prepared_entry = manual_out_by_host[host]
            source_ids = self.entry_merger.stable_unique_merge(
                (PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT,), prepared_entry.source_ids
            )
            source_input_labels = self.entry_merger.stable_unique_merge(
                (str(manual_inputs.out_path),), prepared_entry.source_input_labels
            )
            row = _manual_review_row(
                job=source_jobs_by_id[prepared_entry.source_id],
                entry=prepared_entry.entry,
                pipeline_result_code=PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT,
                input_label=str(manual_inputs.out_path),
                source_ids=source_ids,
                source_input_labels=source_input_labels,
            )
            preparation_review_rows.append(row)
            preparation_terminal_rows.append(
                _preparation_terminal_row(
                    row=row,
                    pipeline_result_code=PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT,
                )
            )

        primary_job = jobs[0]
        manual_add_config_fingerprints = {
            self._manual_add_behavior_fingerprint(job.config) for job in jobs
        }
        for host, entry in sorted(manual_inputs.add_entries.items()):
            incoming = PreparedHostEntry(
                source_id=primary_job.source_id,
                source_index=0,
                line_index=10_000_000,
                raw_line=host,
                entry=entry,
                manual_add=True,
                source_id_override=MANUAL_ADD_SOURCE_ID,
                source_input_label_override=str(manual_inputs.add_path),
                source_ids=(MANUAL_ADD_SOURCE_ID,),
                source_input_labels=(str(manual_inputs.add_path),),
            )
            current = entries_by_host.get(host)
            if current is None:
                if len(manual_add_config_fingerprints) > 1:
                    raise ValueError(
                        f"manual-add file {manual_inputs.add_path} contains "
                        f"unmatched host {host!r}; unmatched manual_add requires "
                        "all enabled sources to share delegation/output behavior"
                    )
                entries_by_host[host] = incoming
            else:
                entries_by_host[host] = dataclasses.replace(
                    current,
                    manual_add=True,
                    source_id_override=MANUAL_ADD_SOURCE_ID,
                    source_input_label_override=str(manual_inputs.add_path),
                    source_ids=self.entry_merger.stable_unique_merge(
                        current.source_ids, (MANUAL_ADD_SOURCE_ID,)
                    ),
                    source_input_labels=self.entry_merger.stable_unique_merge(
                        current.source_input_labels, (str(manual_inputs.add_path),)
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
                preparation_terminal_rows.append(
                    _preparation_terminal_row(
                        row=row,
                        pipeline_result_code=PIPELINE_RESULT_CODE_INPUT_PUBLIC_SUFFIX,
                    )
                )
                continue
            entries_by_source[prepared_entry.source_id].append(prepared_entry)

        for host, entry in sorted(manual_inputs.pass_entries.items()):
            if host in matched_hosts:
                continue
            row = _manual_review_row(
                job=primary_job,
                entry=entry,
                pipeline_result_code=PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
                input_label=str(manual_inputs.pass_path),
            )
            preparation_review_rows.append(row)
            preparation_terminal_rows.append(
                _preparation_terminal_row(
                    row=row,
                    pipeline_result_code=PIPELINE_RESULT_CODE_MANUAL_FILTER_PASS_NOT_IN_SOURCES,
                )
            )

        for host, entry in sorted(manual_inputs.out_entries.items()):
            if host in manual_out_by_host:
                continue
            row = _manual_review_row(
                job=primary_job,
                entry=entry,
                pipeline_result_code=PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
                input_label=str(manual_inputs.out_path),
            )
            preparation_review_rows.append(row)
            preparation_terminal_rows.append(
                _preparation_terminal_row(
                    row=row,
                    pipeline_result_code=PIPELINE_RESULT_CODE_MANUAL_FILTER_OUT_NOT_IN_SOURCES,
                )
            )

        root_plans = {
            entry.entry.registrable_domain: PreparedRootPlan(
                entry.entry.registrable_domain
            )
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

    def _canonical_delegation_dns_behavior(
        self, dns_config: dict[str, Any]
    ) -> dict[str, Any]:
        delegation_config = dict(dns_config["delegation"])
        return {
            **delegation_dns_profile(dns_config),
            "retry_attempts": delegation_config["retry_attempts"],
        }

    def _canonical_host_resolution_dns_behavior(
        self, dns_config: dict[str, Any]
    ) -> dict[str, Any]:
        host_resolution_config = dict(dns_config["host_resolution"])
        return {
            **host_resolution_dns_profile(dns_config),
            "enabled": host_resolution_config["enabled"],
            "retry_attempts": host_resolution_config["retry_attempts"],
        }

    def _canonical_dns_behavior(self, dns_config: dict[str, Any]) -> dict[str, Any]:
        return {
            "delegation": self._canonical_delegation_dns_behavior(dns_config),
            "host_resolution": self._canonical_host_resolution_dns_behavior(dns_config),
        }

    def _source_behavior_fingerprint(self, source_config: dict[str, Any]) -> str:
        payload = {
            "dns": self._canonical_dns_behavior(source_config["dns"]),
            "geo": source_config["geo"],
            "output": source_config["output"],
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def _manual_add_behavior_fingerprint(self, source_config: dict[str, Any]) -> str:
        dns_config = source_config["dns"]
        payload = {
            "dns": {"delegation": self._canonical_delegation_dns_behavior(dns_config)},
            "output": source_config["output"],
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))
