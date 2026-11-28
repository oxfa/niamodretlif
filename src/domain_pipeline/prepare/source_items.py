"""Prepare-owned source-item records and aggregate lookup collections."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from domain_pipeline.handoff_io import read_strict_json, write_json
from domain_pipeline.prepare.models import PreparedInputSet
from domain_pipeline.prepare.sources.jobs import SourceJob
from domain_pipeline.prepare.sources.parser import (
    DomainListParser,
    InputFileFormat,
    ParsedSourceItem,
)

_BY_INPUT_DOMAIN = "valid_source_items_by_input_domain"
_WITHOUT_REGISTRABLE_DOMAIN = (
    "valid_source_items_without_extractable_registrable_domain"
)
_ADBLOCK_METADATA = "adblock_metadata"


@dataclass(frozen=True)
class SourceItemHandoff:
    """Validated in-memory contents for the prepare-to-aggregate source handoff."""

    batch_id: str
    item_records: tuple[dict[str, Any], ...]
    index_payload: dict[str, Any]
    diagnostic_records: tuple[dict[str, Any], ...]
    parsed_items_by_id: Mapping[str, ParsedSourceItem] = field(default_factory=dict)

    @property
    def retained_line_count(self) -> int:
        """Count original lines that carry metadata, a rule, or a valid target."""
        return sum(
            record["is_metadata"]
            or record["no_target_reason"] is not None
            or any(
                association["error_reason"] is None
                for association in record["target_associations"]
            )
            for record in self.item_records
        )

    @property
    def valid_source_hosts(self) -> frozenset[str]:
        """Return error-free source hosts, including suffixes and exclusions."""
        return frozenset(
            association["host"]
            for record in self.item_records
            for association in record["target_associations"]
            if association["error_reason"] is None
        )

    @classmethod
    def build(
        cls,
        *,
        batch_id: str,
        prepared_inputs: PreparedInputSet,
    ) -> SourceItemHandoff:
        """Build indexed source-item records from prepare's parsed source jobs."""
        excluded_hosts = prepared_inputs.excluded_source_hosts
        source_metadata: list[dict[str, Any]] = []
        records: list[dict[str, Any]] = []
        parsed_items: dict[str, ParsedSourceItem] = {}
        diagnostics: list[dict[str, Any]] = []

        for source_ordinal, job in enumerate(prepared_inputs.source_jobs_by_id.values()):
            parsed_source_file = prepared_inputs.parsed_source_files.get(job.source_id)
            if parsed_source_file is None:
                raise ValueError(
                    "prepare parse results are missing for configured source "
                    f"{job.source_id!r}"
                )
            input_format = parsed_source_file.file_format
            source_metadata.append(
                {
                    "source_ordinal": source_ordinal,
                    "source_id": job.source_id,
                    "source_label": job.input_label,
                    "input_format": input_format.value,
                }
            )
            if input_format in {InputFileFormat.UNKNOWN, InputFileFormat.MIXED}:
                for source_line in parsed_source_file.lines:
                    line_number = source_line.line_number
                    raw_line = source_line.raw_line
                    if source_line.is_ignored:
                        continue
                    diagnostics.append(
                        _diagnostic(
                            batch_id=batch_id,
                            source_ordinal=source_ordinal,
                            job=job,
                            line_number=line_number,
                            input_format=input_format,
                            raw_text=raw_line,
                            reason=f"source_file_format_{input_format.value}",
                        )
                    )
                continue

            for source_line in parsed_source_file.lines:
                line_number = source_line.line_number
                raw_line = source_line.raw_line
                parsed = source_line.parsed_item
                if parsed is None:
                    continue
                item_id = f"{job.source_id}:{line_number}"
                if parsed.error_reason is not None:
                    diagnostics.append(
                        _diagnostic(
                            batch_id=batch_id,
                            source_ordinal=source_ordinal,
                            job=job,
                            line_number=line_number,
                            input_format=input_format,
                            raw_text=raw_line,
                            reason=parsed.error_reason,
                        )
                    )
                    continue

                target_associations: list[dict[str, Any]] = []
                for target_ordinal, target in enumerate(parsed.targets, start=1):
                    target_associations.append(
                        {
                            "association_id": f"{item_id}:target:{target_ordinal}",
                            "target_ordinal": target_ordinal,
                            "host": target.host,
                            "registrable_domain": target.registrable_domain,
                            "role": target.role,
                            "error_reason": target.error_reason,
                            "excluded_from_sources": target.host in excluded_hosts,
                        }
                    )
                    if target.error_reason is not None:
                        diagnostics.append(
                            _diagnostic(
                                batch_id=batch_id,
                                source_ordinal=source_ordinal,
                                job=job,
                                line_number=line_number,
                                input_format=input_format,
                                raw_text=raw_line,
                                reason=target.error_reason,
                                target_ordinal=target_ordinal,
                            )
                        )

                is_metadata = parsed.is_metadata
                no_target_reason = parsed.no_target_reason
                if not target_associations and not no_target_reason and not is_metadata:
                    continue
                record = {
                    "item_id": item_id,
                    "source_ordinal": source_ordinal,
                    "source_id": job.source_id,
                    "source_label": job.input_label,
                    "source_line_number": line_number,
                    "input_format": input_format.value,
                    "original_text": raw_line,
                    "item_kind": parsed.item_kind,
                    "target_associations": target_associations,
                    "no_target_reason": no_target_reason,
                    "is_metadata": is_metadata,
                }
                records.append(record)
                parsed_items[item_id] = parsed

        by_domain, without_domain, adblock_metadata = _index_occurrences(records)
        index_payload = {
            "batch_id": batch_id,
            "sources": source_metadata,
            _BY_INPUT_DOMAIN: dict(sorted(by_domain.items())),
            _WITHOUT_REGISTRABLE_DOMAIN: without_domain,
            _ADBLOCK_METADATA: adblock_metadata,
        }
        handoff = cls(
            batch_id=batch_id,
            item_records=tuple(records),
            index_payload=index_payload,
            diagnostic_records=tuple(diagnostics),
            parsed_items_by_id=parsed_items,
        )
        handoff.validate()
        return handoff

    @classmethod
    def load(
        cls,
        *,
        batch_id: str,
        items_path: Path,
        index_path: Path,
        diagnostics_path: Path,
        validate_semantics: bool = False,
        excluded_source_hosts: set[str] | None = None,
    ) -> SourceItemHandoff:
        """Load the prepare-owned aggregate source handoff.

        Semantic reparsing is optional because staging also loads this handoff
        after prepare has already validated its source inputs. Aggregate
        readiness enables it at the cross-job trust boundary.
        """
        try:
            item_records = tuple(_read_jsonl(items_path))
            diagnostic_records = tuple(_read_jsonl(diagnostics_path))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"unable to read source-item handoff: {exc}") from exc
        handoff = cls(
            batch_id=batch_id,
            item_records=item_records,
            index_payload=read_strict_json(index_path),
            diagnostic_records=diagnostic_records,
        )
        handoff.validate()
        handoff = replace(
            handoff,
            item_records=tuple(
                sorted(
                    handoff.item_records,
                    key=lambda item: (
                        item["source_ordinal"],
                        item["source_line_number"],
                    ),
                )
            ),
        )
        if validate_semantics:
            if excluded_source_hosts is None:
                raise ValueError(
                    "source-item semantic validation requires prepare exclusions"
                )
            parsed_items = handoff.validate_source_semantics(
                excluded_source_hosts=excluded_source_hosts
            )
            handoff = replace(handoff, parsed_items_by_id=parsed_items)
        return handoff

    def write(
        self,
        *,
        items_path: Path,
        index_path: Path,
        diagnostics_path: Path,
    ) -> tuple[Path, Path, Path]:
        """Write the three declared prepare-to-aggregate source artifacts."""
        # The final diagnostics path marks completion of all three files.
        diagnostics_path.unlink(missing_ok=True)
        self.validate()
        _write_jsonl(items_path, self.item_records)
        write_json(index_path, self.index_payload)
        diagnostics_path.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(
            dir=diagnostics_path.parent,
            prefix=f".{diagnostics_path.name}.",
            delete=False,
        ) as temporary_file:
            temporary_diagnostics = Path(temporary_file.name)
        try:
            _write_jsonl(temporary_diagnostics, self.diagnostic_records)
            temporary_diagnostics.replace(diagnostics_path)
        finally:
            temporary_diagnostics.unlink(missing_ok=True)
        return items_path, index_path, diagnostics_path

    def validate(self) -> None:
        """Validate schema, identities, and exact index-to-record membership."""
        payload = self.index_payload
        expected_keys = {
            "batch_id",
            "sources",
            _BY_INPUT_DOMAIN,
            _WITHOUT_REGISTRABLE_DOMAIN,
            _ADBLOCK_METADATA,
        }
        if not isinstance(payload, dict) or set(payload) != expected_keys:
            raise ValueError("source-item index has unsupported or missing fields")
        if payload["batch_id"] != self.batch_id:
            raise ValueError("source-item index batch identity mismatch")
        sources = payload["sources"]
        if not isinstance(sources, list):
            raise ValueError("source-item index sources must be a list")
        source_ids: set[str] = set()
        for ordinal, source in enumerate(sources):
            if (
                not isinstance(source, dict)
                or set(source)
                != {"source_ordinal", "source_id", "source_label", "input_format"}
                or type(source["source_ordinal"]) is not int
                or source["source_ordinal"] != ordinal
                or any(
                    not isinstance(source.get(key), str) or not source[key]
                    for key in ("source_id", "source_label", "input_format")
                )
            ):
                raise ValueError("source-item index contains invalid source metadata")
            source_id = source["source_id"]
            if source_id in source_ids:
                raise ValueError(
                    f"source-item index contains duplicate source ID: {source_id}"
                )
            source_ids.add(source_id)
            try:
                InputFileFormat(source["input_format"])
            except ValueError as exc:
                raise ValueError("source-item index contains unknown format") from exc

        item_ids: set[str] = set()
        for record in self.item_records:
            _validate_item_record(record, sources)
            item_id = record["item_id"]
            if item_id in item_ids:
                raise ValueError(f"duplicate source item identity: {item_id}")
            item_ids.add(item_id)

        expected_by_domain, expected_without_domain, expected_metadata = (
            _index_occurrences(self.item_records)
        )
        actual_by_domain = payload[_BY_INPUT_DOMAIN]
        if not isinstance(actual_by_domain, dict) or (
            actual_by_domain.keys() != expected_by_domain.keys()
        ):
            raise ValueError(
                "source-item domain index does not match item associations"
            )
        for domain, references in actual_by_domain.items():
            _validate_reference_membership(
                references, expected_by_domain[domain], collection=f"domain {domain}"
            )
        _validate_reference_membership(
            payload[_WITHOUT_REGISTRABLE_DOMAIN],
            expected_without_domain,
            collection="no-domain index",
        )
        _validate_reference_membership(
            payload[_ADBLOCK_METADATA], expected_metadata, collection="metadata index"
        )

        for diagnostic in self.diagnostic_records:
            _validate_diagnostic(diagnostic, self.batch_id, sources)

    def validate_source_semantics(
        self,
        *,
        excluded_source_hosts: set[str],
        parser: DomainListParser | None = None,
    ) -> dict[str, ParsedSourceItem]:
        """Verify the carried associations and return the validated parse facts."""
        parser = parser or DomainListParser()
        target_error_diagnostics = Counter(
            (
                diagnostic["source_ordinal"],
                diagnostic["source_line_number"],
                diagnostic["target_ordinal"],
                diagnostic["reason"],
                diagnostic["original_text"],
            )
            for diagnostic in self.diagnostic_records
            if diagnostic["target_ordinal"] is not None
        )
        expected_target_error_diagnostics: list[tuple[int, int, int, str, str]] = []
        parsed_items: dict[str, ParsedSourceItem] = {}
        for record in self.item_records:
            input_format = InputFileFormat(record["input_format"])
            parsed = parser.parse_source_item(
                record["original_text"], file_format=input_format
            )
            if parsed is None or parsed.error_reason is not None:
                raise ValueError(
                    "source-item record does not parse as a valid source item: "
                    f"{record['item_id']}"
                )
            if (
                parsed.item_kind != record["item_kind"]
                or parsed.is_metadata != record["is_metadata"]
            ):
                raise ValueError(
                    f"source-item parse classification mismatch: {record['item_id']}"
                )

            expected_associations: list[dict[str, Any]] = []
            for target_ordinal, target in enumerate(parsed.targets, start=1):
                if target.error_reason is not None:
                    expected_target_error_diagnostics.append(
                        (
                            record["source_ordinal"],
                            record["source_line_number"],
                            target_ordinal,
                            target.error_reason,
                            record["original_text"],
                        )
                    )
                expected_associations.append(
                    {
                        "association_id": (
                            f"{record['item_id']}:target:{target_ordinal}"
                        ),
                        "target_ordinal": target_ordinal,
                        "host": target.host,
                        "registrable_domain": target.registrable_domain,
                        "role": target.role,
                        "error_reason": target.error_reason,
                    }
                )

            actual_associations = [
                {
                    key: association[key]
                    for key in (
                        "association_id",
                        "target_ordinal",
                        "host",
                        "registrable_domain",
                        "role",
                        "error_reason",
                    )
                }
                for association in record["target_associations"]
            ]
            if actual_associations != expected_associations:
                raise ValueError(
                    "source-item target associations do not match parsed strict-PSL "
                    f"targets: {record['item_id']}"
                )
            for association, target in zip(
                record["target_associations"], parsed.targets, strict=True
            ):
                if association["excluded_from_sources"] != (
                    target.host in excluded_source_hosts
                ):
                    raise ValueError(
                        "source-item exclusion decision does not match prepare "
                        f"exclusions: {record['item_id']}"
                    )
            expected_no_target_reason = (
                None if parsed.targets else parsed.no_target_reason
            )
            if record["no_target_reason"] != expected_no_target_reason:
                raise ValueError(
                    f"source-item no-target classification mismatch: {record['item_id']}"
                )
            parsed_items[record["item_id"]] = parsed

        if target_error_diagnostics != Counter(expected_target_error_diagnostics):
            raise ValueError(
                "source-item target errors do not match target diagnostics"
            )
        return parsed_items


def _validate_physical_line(value: Any) -> None:
    if not isinstance(value, str) or (value and value.splitlines() != [value]):
        raise ValueError("source-item original text must be one physical line")


def _index_occurrences(
    records: Iterable[dict[str, Any]],
) -> tuple[
    dict[str, list[dict[str, str]]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    by_domain: dict[str, list[dict[str, str]]] = {}
    without_domain: list[dict[str, Any]] = []
    metadata: list[dict[str, Any]] = []
    for record in records:
        item_id = record["item_id"]
        associations = record["target_associations"]
        if record["is_metadata"]:
            metadata.append({"item_id": item_id, "association_id": None})
        elif not associations:
            without_domain.append(
                {
                    "item_id": item_id,
                    "association_id": None,
                    "reason": record["no_target_reason"],
                }
            )
        for association in associations:
            if (
                association["error_reason"] is not None
                or association["excluded_from_sources"]
            ):
                continue
            reference = {
                "item_id": item_id,
                "association_id": association["association_id"],
            }
            if association["registrable_domain"] is None:
                without_domain.append({**reference, "reason": "public_suffix_only"})
            else:
                by_domain.setdefault(association["host"], []).append(reference)
    return by_domain, without_domain, metadata


def _validate_reference_membership(
    actual: Any,
    expected: Sequence[Mapping[str, Any]],
    *,
    collection: str,
) -> None:
    message = f"source-item {collection} references do not match item records"
    if not isinstance(actual, list) or len(actual) != len(expected):
        raise ValueError(message)
    if not expected:
        return
    fields = expected[0].keys()
    remaining = {tuple(reference[field] for field in fields) for reference in expected}
    for reference in actual:
        if not isinstance(reference, dict) or reference.keys() != fields:
            raise ValueError(message)
        values = tuple(reference[field] for field in fields)
        if any(value is not None and not isinstance(value, str) for value in values):
            raise ValueError(message)
        if values not in remaining:
            raise ValueError(message)
        remaining.remove(values)


def _diagnostic(
    *,
    batch_id: str,
    source_ordinal: int,
    job: SourceJob,
    line_number: int,
    input_format: InputFileFormat,
    raw_text: str,
    reason: str,
    target_ordinal: int | None = None,
) -> dict[str, Any]:
    return {
        "batch_id": batch_id,
        "source_ordinal": source_ordinal,
        "source_id": job.source_id,
        "source_label": job.input_label,
        "source_line_number": line_number,
        "input_format": input_format.value,
        "original_text": raw_text,
        "reason": reason,
        "target_ordinal": target_ordinal,
    }


def _validate_item_record(record: Any, sources: list[dict[str, Any]]) -> None:
    fields = {
        "item_id",
        "source_ordinal",
        "source_id",
        "source_label",
        "source_line_number",
        "input_format",
        "original_text",
        "item_kind",
        "target_associations",
        "no_target_reason",
        "is_metadata",
    }
    if not isinstance(record, dict) or set(record) != fields:
        raise ValueError("source-item record has unsupported or missing fields")
    ordinal = record["source_ordinal"]
    if (
        not isinstance(ordinal, int)
        or isinstance(ordinal, bool)
        or ordinal < 0
        or ordinal >= len(sources)
        or record["source_id"] != sources[ordinal]["source_id"]
        or record["source_label"] != sources[ordinal]["source_label"]
        or record["input_format"] != sources[ordinal]["input_format"]
    ):
        raise ValueError("source-item record source identity mismatch")
    line_number = record["source_line_number"]
    if (
        not isinstance(record["item_id"], str)
        or not record["item_id"]
        or record["item_id"] != f"{record['source_id']}:{line_number}"
        or not isinstance(line_number, int)
        or isinstance(line_number, bool)
        or line_number < 1
        or any(
            not isinstance(record[key], str) or not record[key]
            for key in ("source_id", "source_label", "input_format", "item_kind")
        )
        or not isinstance(record["target_associations"], list)
        or not isinstance(record["is_metadata"], bool)
        or (
            record["no_target_reason"] is not None
            and (not isinstance(record["no_target_reason"], str) or not record["no_target_reason"])
        )
    ):
        raise ValueError("source-item record has invalid values")
    _validate_physical_line(record["original_text"])
    if record["is_metadata"]:
        if (
            record["input_format"] != InputFileFormat.ADBLOCK.value
            or record["item_kind"] != "metadata"
            or record["target_associations"]
            or record["no_target_reason"] != "format_metadata"
        ):
            raise ValueError("invalid AdBlock metadata source item")
    elif record["target_associations"] and record["no_target_reason"] is not None:
        raise ValueError("targeted source item cannot have a no-target reason")
    elif not record["target_associations"] and not record["no_target_reason"]:
        raise ValueError("source item without targets requires a reason")

    target_ordinals: set[int] = set()
    for association in record["target_associations"]:
        association_fields = {
            "association_id",
            "target_ordinal",
            "host",
            "registrable_domain",
            "role",
            "error_reason",
            "excluded_from_sources",
        }
        if not isinstance(association, dict) or set(association) != association_fields:
            raise ValueError("source-item target association has invalid fields")
        target_ordinal = association["target_ordinal"]
        if (
            not isinstance(target_ordinal, int)
            or isinstance(target_ordinal, bool)
            or target_ordinal < 1
            or target_ordinal in target_ordinals
            or association["association_id"]
            != f"{record['item_id']}:target:{target_ordinal}"
            or not isinstance(association["host"], str)
            or not association["host"]
            or (
                association["registrable_domain"] is not None
                and (
                    not isinstance(association["registrable_domain"], str)
                    or not association["registrable_domain"]
                )
            )
            or not isinstance(association["role"], str)
            or not association["role"]
            or (
                association["error_reason"] is not None
                and (
                    not isinstance(association["error_reason"], str)
                    or not association["error_reason"]
                    or association["registrable_domain"] is not None
                )
            )
            or not isinstance(association["excluded_from_sources"], bool)
        ):
            raise ValueError("source-item target association has invalid values")
        target_ordinals.add(target_ordinal)


def _validate_diagnostic(
    diagnostic: Any, batch_id: str, sources: list[dict[str, Any]]
) -> None:
    fields = {
        "batch_id",
        "source_ordinal",
        "source_id",
        "source_label",
        "source_line_number",
        "input_format",
        "original_text",
        "reason",
        "target_ordinal",
    }
    if not isinstance(diagnostic, dict) or set(diagnostic) != fields:
        raise ValueError("source-item diagnostic has unsupported or missing fields")
    ordinal = diagnostic["source_ordinal"]
    if (
        diagnostic["batch_id"] != batch_id
        or not isinstance(ordinal, int)
        or isinstance(ordinal, bool)
        or ordinal < 0
        or ordinal >= len(sources)
        or diagnostic["source_id"] != sources[ordinal]["source_id"]
        or diagnostic["source_label"] != sources[ordinal]["source_label"]
        or diagnostic["input_format"] != sources[ordinal]["input_format"]
        or not isinstance(diagnostic["source_line_number"], int)
        or isinstance(diagnostic["source_line_number"], bool)
        or diagnostic["source_line_number"] < 1
        or not isinstance(diagnostic["reason"], str)
        or not diagnostic["reason"]
        or (
            diagnostic["target_ordinal"] is not None
            and (
                not isinstance(diagnostic["target_ordinal"], int)
                or isinstance(diagnostic["target_ordinal"], bool)
                or diagnostic["target_ordinal"] < 1
            )
        )
    ):
        raise ValueError("source-item diagnostic identity or values are invalid")
    _validate_physical_line(diagnostic["original_text"])


def _write_jsonl(path: Path, records: tuple[dict[str, Any], ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        for record in records:
            handle.write(
                json.dumps(record, ensure_ascii=False, allow_nan=False, sort_keys=True)
            )
            handle.write("\n")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    def reject_constant(value: str) -> None:
        raise ValueError(f"invalid JSON constant {value}")

    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                raise ValueError(f"blank JSONL record at {path}:{line_number}")
            record = json.loads(line, parse_constant=reject_constant)
            if not isinstance(record, dict):
                raise ValueError(f"JSONL record must be an object at {path}:{line_number}")
            records.append(record)
    return records
