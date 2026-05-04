"""Worker runtime item loading from prepared metadata or source config."""

from __future__ import annotations

from typing import Any

from domain_pipeline.prepare.sources.jobs import SourceJob, SourceJobFactory
from domain_pipeline.prepare.sources.parser import DomainListParser, ParsedDomainEntry
from domain_pipeline.worker.runtime.contracts import ParsedHostItem, WorkerSourceContext


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


def _source_context_from_config(
    source: dict[str, Any], *, config_name: str
) -> WorkerSourceContext:
    return WorkerSourceContext(
        source_id=str(source["id"]),
        input_label=str(
            source.get("input", {}).get("label") or source["input"]["location"]
        ),
        output_stem=config_name,
        config=source,
    )


def _source_context_from_job(job: SourceJob) -> WorkerSourceContext:
    return WorkerSourceContext(
        source_id=job.source_id,
        input_label=job.input_label,
        output_stem=job.output_stem,
        config=job.config,
    )


class RuntimeItemLoader:
    """Build worker-local runtime items from prepared metadata or config sources."""

    def __init__(
        self,
        *,
        config: dict[str, Any],
        prepared_metadata: dict[str, Any] | None = None,
    ) -> None:
        self.config = config
        self.prepared_metadata = prepared_metadata or {}

    def source_contexts(self) -> list[WorkerSourceContext]:
        """Return worker-local source contexts for prepared workflow mode."""
        return [
            _source_context_from_config(
                source, config_name=str(self.config["config_name"])
            )
            for source in self.config["sources"]
            if source.get("enabled", True)
        ]

    def prepared_entries(
        self, source_context: WorkerSourceContext
    ) -> list[tuple[ParsedDomainEntry, dict[str, Any]]]:
        """Return prepared entries for one worker source context."""
        if not self.prepared_metadata:
            return []
        source_payload = self.prepared_metadata.get("sources", {}).get(
            source_context.source_id
        )
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

    def runtime_items(self) -> list[ParsedHostItem]:
        """Build worker-local items that seed the delegation input queue."""
        parser = DomainListParser()
        item_payloads: list[
            tuple[WorkerSourceContext, ParsedDomainEntry, dict[str, Any]]
        ] = []
        if self.prepared_metadata:
            for source_context in self.source_contexts():
                for entry, provenance in self.prepared_entries(source_context):
                    item_payloads.append((source_context, entry, provenance))
        else:
            for job in SourceJobFactory().build_jobs(self.config):
                source_context = _source_context_from_job(job)
                forced_format = job.config.get("input", {}).get("format", "auto")
                for entry in parser.process_entries(
                    job.lines,
                    source_name=job.input_label,
                    forced_format=None if forced_format == "auto" else forced_format,
                ):
                    item_payloads.append((source_context, entry, {}))
        total = len(item_payloads)
        return [
            ParsedHostItem(
                source_context=source_context,
                entry=entry,
                sequence=index,
                total=total,
                manual_filter_pass=bool(provenance.get("manual_filter_pass", False)),
                manual_add=bool(provenance.get("manual_add", False)),
                source_id_override=provenance.get("source_id_override"),
                source_input_label_override=provenance.get(
                    "source_input_label_override"
                ),
                source_ids=tuple(provenance.get("source_ids", ())),
                source_input_labels=tuple(provenance.get("source_input_labels", ())),
            )
            for index, (source_context, entry, provenance) in enumerate(item_payloads)
        ]
