"""Prepare-owned source-item records and aggregate lookup collections."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain_pipeline.handoff_io import read_json, write_json
from domain_pipeline.pipeline_run.format_version import (
    PIPELINE_RUN_FORMAT_VERSION,
    has_current_pipeline_run_format,
)
from domain_pipeline.prepare.models import PreparedInputSet
from domain_pipeline.prepare.sources.jobs import SourceJob
from domain_pipeline.prepare.sources.parser import (
    DomainListParser,
    InputFileFormat,
)


@dataclass(frozen=True)
class SourceItemHandoff:
    """Validated in-memory contents for the prepare-to-aggregate source handoff."""

    batch_id: str
    item_records: tuple[dict[str, Any], ...]
    index_payload: dict[str, Any]
    diagnostic_records: tuple[dict[str, Any], ...]

    @classmethod
    def build(
        cls,
        *,
        batch_id: str,
        prepared_inputs: PreparedInputSet,
    ) -> "SourceItemHandoff":
        """Build indexed source-item records from prepare's parsed source jobs."""
        excluded_hosts = prepared_inputs.excluded_source_hosts
        source_metadata: list[dict[str, Any]] = []
        records: list[dict[str, Any]] = []
        diagnostics: list[dict[str, Any]] = []
        by_domain: dict[str, list[dict[str, str]]] = {}
        without_domain: list[dict[str, Any]] = []
        adblock_metadata: list[dict[str, Any]] = []

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
                    if _is_ignored_line(raw_line):
                        continue
                    diagnostics.append(
                        _diagnostic(
                            batch_id=batch_id,
                            source_ordinal=source_ordinal,
                            job=job,
                            line_number=line_number,
                            input_format=input_format,
                            raw_text=_source_text(raw_line),
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
                            raw_text=_source_text(raw_line),
                            reason=parsed.error_reason,
                        )
                    )
                    continue

                target_associations: list[dict[str, Any]] = []
                for target_ordinal, target in enumerate(parsed.targets, start=1):
                    association_id = f"{item_id}:target:{target_ordinal}"
                    excluded = target.host in excluded_hosts
                    association = {
                        "association_id": association_id,
                        "target_ordinal": target_ordinal,
                        "host": target.host,
                        "registrable_domain": target.registrable_domain,
                        "role": target.role,
                        "error_reason": target.error_reason,
                        "excluded_from_sources": excluded,
                    }
                    target_associations.append(association)
                    if target.error_reason is not None:
                        diagnostics.append(
                            _diagnostic(
                                batch_id=batch_id,
                                source_ordinal=source_ordinal,
                                job=job,
                                line_number=line_number,
                                input_format=input_format,
                                raw_text=_source_text(raw_line),
                                reason=target.error_reason,
                                target_ordinal=target_ordinal,
                            )
                        )
                        continue
                    if excluded:
                        continue
                    reference = {
                        "item_id": item_id,
                        "association_id": association_id,
                    }
                    if target.registrable_domain is None:
                        without_domain.append(
                            {**reference, "reason": "public_suffix_only"}
                        )
                    else:
                        by_domain.setdefault(target.registrable_domain, []).append(
                            reference
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
                    "original_text": _source_text(raw_line),
                    "item_kind": parsed.item_kind,
                    "target_associations": target_associations,
                    "no_target_reason": no_target_reason,
                    "is_metadata": is_metadata,
                }
                records.append(record)
                if is_metadata:
                    adblock_metadata.append(
                        {"item_id": item_id, "association_id": None}
                    )
                elif not target_associations and no_target_reason:
                    without_domain.append(
                        {
                            "item_id": item_id,
                            "association_id": None,
                            "reason": no_target_reason,
                        }
                    )

        records.sort(key=lambda item: (item["source_ordinal"], item["source_line_number"]))
        index_payload = {
            "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
            "batch_id": batch_id,
            "sources": source_metadata,
            "valid_source_items_by_registrable_domain": {
                domain: sorted(
                    references,
                    key=lambda item: (item["item_id"], item["association_id"]),
                )
                for domain, references in sorted(by_domain.items())
            },
            "valid_source_items_without_extractable_registrable_domain": sorted(
                without_domain,
                key=lambda item: (
                    item["item_id"],
                    item["association_id"] or "",
                    item["reason"],
                ),
            ),
            "adblock_metadata": sorted(
                adblock_metadata, key=lambda item: item["item_id"]
            ),
        }
        handoff = cls(
            batch_id=batch_id,
            item_records=tuple(records),
            index_payload=index_payload,
            diagnostic_records=tuple(diagnostics),
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
    ) -> "SourceItemHandoff":
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
            index_payload=read_json(index_path),
            diagnostic_records=diagnostic_records,
        )
        handoff.validate()
        if validate_semantics:
            if excluded_source_hosts is None:
                raise ValueError(
                    "source-item semantic validation requires prepare exclusions"
                )
            handoff.validate_source_semantics(
                excluded_source_hosts=excluded_source_hosts
            )
        return handoff

    def write(
        self,
        *,
        items_path: Path,
        index_path: Path,
        diagnostics_path: Path,
    ) -> tuple[Path, Path, Path]:
        """Write the three declared prepare-to-aggregate source artifacts."""
        self.validate()
        _write_jsonl(items_path, self.item_records)
        write_json(index_path, self.index_payload)
        _write_jsonl(diagnostics_path, self.diagnostic_records)
        return items_path, index_path, diagnostics_path

    def validate(self) -> None:
        """Validate schema, identities, and exact index-to-record membership."""
        payload = self.index_payload
        expected_keys = {
            "automation_format_version",
            "batch_id",
            "sources",
            "valid_source_items_by_registrable_domain",
            "valid_source_items_without_extractable_registrable_domain",
            "adblock_metadata",
        }
        if not isinstance(payload, dict) or set(payload) != expected_keys:
            raise ValueError("source-item index has unsupported or missing fields")
        if (
            not has_current_pipeline_run_format(
                payload["automation_format_version"]
            )
            or payload["batch_id"] != self.batch_id
        ):
            raise ValueError("source-item index version or batch identity mismatch")
        sources = payload["sources"]
        if not isinstance(sources, list):
            raise ValueError("source-item index sources must be a list")
        for ordinal, source in enumerate(sources):
            if (
                not isinstance(source, dict)
                or set(source)
                != {"source_ordinal", "source_id", "source_label", "input_format"}
                or source.get("source_ordinal") != ordinal
                or any(
                    not isinstance(source.get(key), str) or not source[key]
                    for key in ("source_id", "source_label", "input_format")
                )
            ):
                raise ValueError("source-item index contains invalid source metadata")
            try:
                InputFileFormat(source["input_format"])
            except ValueError as exc:
                raise ValueError("source-item index contains unknown format") from exc

        records_by_id: dict[str, dict[str, Any]] = {}
        associations_by_id: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
        expected_by_domain: dict[str, list[dict[str, str]]] = {}
        expected_without_domain: list[dict[str, Any]] = []
        expected_metadata: list[dict[str, Any]] = []
        for record in self.item_records:
            _validate_item_record(record, self.batch_id, sources)
            item_id = record["item_id"]
            if item_id in records_by_id:
                raise ValueError(f"duplicate source item identity: {item_id}")
            records_by_id[item_id] = record
            for association in record["target_associations"]:
                association_id = association["association_id"]
                if association_id in associations_by_id:
                    raise ValueError(f"duplicate target association: {association_id}")
                associations_by_id[association_id] = (record, association)
                if (
                    association["error_reason"] is not None
                    or association["excluded_from_sources"]
                ):
                    continue
                reference = {"item_id": item_id, "association_id": association_id}
                domain = association["registrable_domain"]
                if domain is None:
                    expected_without_domain.append(
                        {**reference, "reason": "public_suffix_only"}
                    )
                else:
                    expected_by_domain.setdefault(domain, []).append(reference)
            if record["is_metadata"]:
                expected_metadata.append({"item_id": item_id, "association_id": None})
            elif not record["target_associations"]:
                expected_without_domain.append(
                    {
                        "item_id": item_id,
                        "association_id": None,
                        "reason": record["no_target_reason"],
                    }
                )

        actual_by_domain = payload["valid_source_items_by_registrable_domain"]
        if not isinstance(actual_by_domain, dict):
            raise ValueError("valid_source_items_by_registrable_domain must be an object")
        normalized_by_domain: dict[str, list[dict[str, str]]] = {}
        for domain, references in actual_by_domain.items():
            if not isinstance(domain, str) or not domain or not isinstance(references, list):
                raise ValueError("source-item domain collection is invalid")
            normalized_by_domain[domain] = [
                _validate_association_reference(
                    reference,
                    records_by_id=records_by_id,
                    associations_by_id=associations_by_id,
                    expected_domain=domain,
                )
                for reference in references
            ]
        if _sort_refs(normalized_by_domain) != _sort_refs(expected_by_domain):
            raise ValueError("source-item domain index does not match item associations")

        actual_without_domain = payload[
            "valid_source_items_without_extractable_registrable_domain"
        ]
        if not isinstance(actual_without_domain, list):
            raise ValueError(
                "valid_source_items_without_extractable_registrable_domain must be a list"
            )
        normalized_without_domain = [
            _validate_no_domain_reference(
                reference,
                records_by_id=records_by_id,
                associations_by_id=associations_by_id,
            )
            for reference in actual_without_domain
        ]
        if _sort_no_domain(normalized_without_domain) != _sort_no_domain(
            expected_without_domain
        ):
            raise ValueError("source-item no-domain index does not match item records")

        actual_metadata = payload["adblock_metadata"]
        if not isinstance(actual_metadata, list):
            raise ValueError("source-item AdBlock metadata index must be a list")
        normalized_metadata = [
            _validate_metadata_reference(reference, records_by_id)
            for reference in actual_metadata
        ]
        if sorted(normalized_metadata, key=lambda item: item["item_id"]) != sorted(
            expected_metadata, key=lambda item: item["item_id"]
        ):
            raise ValueError("source-item metadata index does not match item records")

        for diagnostic in self.diagnostic_records:
            _validate_diagnostic(diagnostic, self.batch_id, sources)

    def validate_source_semantics(
        self,
        *,
        excluded_source_hosts: set[str],
        parser: DomainListParser | None = None,
    ) -> None:
        """Reparse items and verify PSL results and prepare exclusion decisions."""
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

        if target_error_diagnostics != Counter(expected_target_error_diagnostics):
            raise ValueError(
                "source-item target errors do not match target diagnostics"
            )


def _is_ignored_line(raw_line: str) -> bool:
    value = raw_line.strip()
    if not value or value.startswith("!"):
        return True
    if value.startswith("#") and not any(
        marker in value for marker in ("##", "#@#", "#@?#", "#?#", "#$#", "#%#")
    ):
        return True
    return False


def _source_text(raw_line: str) -> str:
    return raw_line.rstrip("\r\n")


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


def _validate_item_record(
    record: Any, batch_id: str, sources: list[dict[str, Any]]
) -> None:
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
        or not isinstance(record["original_text"], str)
        or not isinstance(record["target_associations"], list)
        or not isinstance(record["is_metadata"], bool)
        or (
            record["no_target_reason"] is not None
            and (not isinstance(record["no_target_reason"], str) or not record["no_target_reason"])
        )
    ):
        raise ValueError("source-item record has invalid values")
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


def _validate_association_reference(
    reference: Any,
    *,
    records_by_id: dict[str, dict[str, Any]],
    associations_by_id: dict[str, tuple[dict[str, Any], dict[str, Any]]],
    expected_domain: str,
) -> dict[str, str]:
    if (
        not isinstance(reference, dict)
        or set(reference) != {"item_id", "association_id"}
        or not all(isinstance(reference.get(key), str) for key in ("item_id", "association_id"))
    ):
        raise ValueError("source-item domain reference is invalid")
    if reference["item_id"] not in records_by_id:
        raise ValueError("source-item domain reference targets an unknown item")
    pair = associations_by_id.get(reference["association_id"])
    if (
        pair is None
        or pair[0]["item_id"] != reference["item_id"]
        or pair[1]["registrable_domain"] != expected_domain
        or pair[1]["error_reason"] is not None
        or pair[1]["excluded_from_sources"]
    ):
        raise ValueError("source-item domain reference does not match a valid association")
    return {"item_id": reference["item_id"], "association_id": reference["association_id"]}


def _validate_no_domain_reference(
    reference: Any,
    *,
    records_by_id: dict[str, dict[str, Any]],
    associations_by_id: dict[str, tuple[dict[str, Any], dict[str, Any]]],
) -> dict[str, Any]:
    fields = {"item_id", "association_id", "reason"}
    if (
        not isinstance(reference, dict)
        or set(reference) != fields
        or not isinstance(reference.get("item_id"), str)
        or not reference["item_id"]
        or not isinstance(reference.get("reason"), str)
        or not reference["reason"]
        or reference["item_id"] not in records_by_id
    ):
        raise ValueError("source-item no-domain reference is invalid")
    association_id = reference["association_id"]
    if association_id is None:
        record = records_by_id[reference["item_id"]]
        if (
            record["is_metadata"]
            or record["target_associations"]
            or record["no_target_reason"] != reference["reason"]
        ):
            raise ValueError("source-item no-target reference does not match an item")
    elif isinstance(association_id, str):
        pair = associations_by_id.get(association_id)
        if (
            pair is None
            or pair[0]["item_id"] != reference["item_id"]
            or pair[1]["registrable_domain"] is not None
            or pair[1]["error_reason"] is not None
            or pair[1]["excluded_from_sources"]
            or reference["reason"] != "public_suffix_only"
        ):
            raise ValueError("source-item no-domain reference does not match an association")
    else:
        raise ValueError("source-item no-domain reference has invalid association identity")
    return {
        "item_id": reference["item_id"],
        "association_id": association_id,
        "reason": reference["reason"],
    }


def _validate_metadata_reference(
    reference: Any, records_by_id: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    if (
        not isinstance(reference, dict)
        or set(reference) != {"item_id", "association_id"}
        or not isinstance(reference.get("item_id"), str)
        or reference.get("association_id") is not None
        or reference["item_id"] not in records_by_id
        or not records_by_id[reference["item_id"]]["is_metadata"]
    ):
        raise ValueError("source-item metadata reference is invalid")
    return {"item_id": reference["item_id"], "association_id": None}


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
        or not isinstance(diagnostic["original_text"], str)
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


def _sort_refs(values: dict[str, list[dict[str, str]]]) -> dict[str, list[dict[str, str]]]:
    return {
        domain: sorted(refs, key=lambda item: (item["item_id"], item["association_id"]))
        for domain, refs in sorted(values.items())
    }


def _sort_no_domain(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        values,
        key=lambda item: (
            item["item_id"],
            item["association_id"] or "",
            item["reason"],
        ),
    )


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
