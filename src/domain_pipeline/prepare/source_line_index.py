"""Prepare-owned index from registrable domains to archived source lines."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain_pipeline.handoff_io import read_csv, write_csv


@dataclass(frozen=True, order=True)
class SourceLineReference:
    """One line in one ordinal source archive file."""

    source_ordinal: int
    line_number: int

    def __post_init__(self) -> None:
        if self.source_ordinal < 0:
            raise ValueError(
                "source line reference source_ordinal must be non-negative"
            )
        if self.line_number < 1:
            raise ValueError("source line reference line_number must be positive")


@dataclass(frozen=True)
class SourceLineIndex:
    """Source format metadata and registrable-domain line references."""

    source_formats: tuple[str, ...]
    registrable_domain_lines: dict[str, tuple[SourceLineReference, ...]]

    def to_payload(self) -> dict[str, Any]:
        """Return the index as an in-memory mapping."""
        return {
            "source_formats": list(self.source_formats),
            "registrable_domain_lines": {
                domain: [
                    {
                        "source_ordinal": reference.source_ordinal,
                        "line_number": reference.line_number,
                    }
                    for reference in references
                ]
                for domain, references in sorted(self.registrable_domain_lines.items())
            },
        }

    @classmethod
    def from_payload(cls, payload: Any) -> "SourceLineIndex":
        """Validate and load one persisted source-line index."""
        if not isinstance(payload, dict):
            raise ValueError("source line index must be a mapping")
        if set(payload) != {"source_formats", "registrable_domain_lines"}:
            raise ValueError("source line index has unsupported or missing fields")
        formats = payload["source_formats"]
        refs_by_domain = payload["registrable_domain_lines"]
        if not isinstance(formats, list) or not all(
            isinstance(value, str) and value for value in formats
        ):
            raise ValueError("source line index source_formats must be strings")
        if not isinstance(refs_by_domain, dict):
            raise ValueError(
                "source line index registrable_domain_lines must be an object"
            )

        parsed: dict[str, tuple[SourceLineReference, ...]] = {}
        for domain, references in refs_by_domain.items():
            if not isinstance(domain, str) or not domain:
                raise ValueError("source line index domains must be non-empty strings")
            parsed[domain] = _parse_references(domain, references, len(formats))
        return cls(
            source_formats=tuple(formats),
            registrable_domain_lines=parsed,
        )


def _parse_references(
    domain: str, references: Any, format_count: int
) -> tuple[SourceLineReference, ...]:
    if not isinstance(references, list):
        raise ValueError(f"source line index references for {domain!r} must be a list")
    parsed: list[SourceLineReference] = []
    for reference in references:
        if not isinstance(reference, dict) or set(reference) != {
            "source_ordinal",
            "line_number",
        }:
            raise ValueError(f"source line index reference for {domain!r} is invalid")
        source_ordinal = reference["source_ordinal"]
        line_number = reference["line_number"]
        if (
            not isinstance(source_ordinal, int)
            or isinstance(source_ordinal, bool)
            or not isinstance(line_number, int)
            or isinstance(line_number, bool)
        ):
            raise ValueError(
                f"source line index reference for {domain!r} must use integers"
            )
        parsed.append(SourceLineReference(source_ordinal, line_number))
    if len(set(parsed)) != len(parsed):
        raise ValueError(
            f"source line index references for {domain!r} contain duplicates"
        )
    for reference in parsed:
        if reference.source_ordinal >= format_count:
            raise ValueError(
                f"source line index reference for {domain!r} has an "
                "unknown source ordinal"
            )
    return tuple(sorted(parsed))


def load_source_line_index(path: Path, formats_path: Path) -> SourceLineIndex:
    """Read the tabular source formats and line references."""
    formats_rows = read_csv(formats_path, ("source_ordinal", "source_format"))
    formats: list[str] = []
    for ordinal, row in enumerate(formats_rows):
        if row["source_ordinal"] != str(ordinal) or not row["source_format"]:
            raise ValueError("invalid source format ordinal or value")
        formats.append(row["source_format"])
    refs: dict[str, list[dict[str, int]]] = {}
    empty_domains: set[str] = set()
    for row in read_csv(path, ("registrable_domain", "source_ordinal", "line_number")):
        domain = row["registrable_domain"]
        if not row["source_ordinal"] and not row["line_number"]:
            if domain in refs:
                raise ValueError("duplicate or mixed empty source line index row")
            refs[domain] = []
            empty_domains.add(domain)
            continue
        if domain in empty_domains:
            raise ValueError("duplicate or mixed empty source line index row")
        try:
            ordinal, line = int(row["source_ordinal"]), int(row["line_number"])
        except ValueError as exc:
            raise ValueError("invalid source line index integer") from exc
        refs.setdefault(domain, []).append(
            {"source_ordinal": ordinal, "line_number": line}
        )
    return SourceLineIndex.from_payload(
        {"source_formats": formats, "registrable_domain_lines": refs}
    )


def write_source_line_index(
    index: SourceLineIndex, path: Path, formats_path: Path
) -> None:
    """Persist source formats and line references as CSV tables."""
    write_csv(
        formats_path,
        ("source_ordinal", "source_format"),
        [
            {"source_ordinal": ordinal, "source_format": value}
            for ordinal, value in enumerate(index.source_formats)
        ],
    )
    write_csv(
        path,
        ("registrable_domain", "source_ordinal", "line_number"),
        [
            {
                "registrable_domain": domain,
                "source_ordinal": ref.source_ordinal,
                "line_number": ref.line_number,
            }
            for domain, refs in sorted(index.registrable_domain_lines.items())
            for ref in refs
        ]
        + [
            {"registrable_domain": domain, "source_ordinal": "", "line_number": ""}
            for domain, refs in sorted(index.registrable_domain_lines.items())
            if not refs
        ],
    )
