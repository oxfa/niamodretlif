"""Prepare-owned index from registrable domains to archived source lines."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, order=True)
class SourceLineReference:
    """One line in one ordinal source archive file."""

    source_ordinal: int
    line_number: int

    def __post_init__(self) -> None:
        if self.source_ordinal < 0:
            raise ValueError("source line reference source_ordinal must be non-negative")
        if self.line_number < 1:
            raise ValueError("source line reference line_number must be positive")


@dataclass(frozen=True)
class SourceLineIndex:
    """Source format metadata and registrable-domain line references."""

    source_formats: tuple[str, ...]
    registrable_domain_lines: dict[str, tuple[SourceLineReference, ...]]

    def to_payload(self) -> dict[str, Any]:
        """Return the persisted JSON representation."""
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
                for domain, references in sorted(
                    self.registrable_domain_lines.items()
                )
            },
        }

    @classmethod
    def from_payload(cls, payload: Any) -> "SourceLineIndex":
        """Validate and load one persisted source-line index."""
        if not isinstance(payload, dict):
            raise ValueError("source line index must be a JSON object")
        if set(payload) != {"source_formats", "registrable_domain_lines"}:
            raise ValueError("source line index has unsupported or missing fields")
        formats = payload["source_formats"]
        refs_by_domain = payload["registrable_domain_lines"]
        if not isinstance(formats, list) or not all(
            isinstance(value, str) and value for value in formats
        ):
            raise ValueError("source line index source_formats must be strings")
        if not isinstance(refs_by_domain, dict):
            raise ValueError("source line index registrable_domain_lines must be an object")

        parsed: dict[str, tuple[SourceLineReference, ...]] = {}
        for domain, references in refs_by_domain.items():
            if not isinstance(domain, str) or not domain:
                raise ValueError("source line index domains must be non-empty strings")
            if not isinstance(references, list):
                raise ValueError(
                    f"source line index references for {domain!r} must be a list"
                )
            parsed_references: list[SourceLineReference] = []
            for reference in references:
                if not isinstance(reference, dict) or set(reference) != {
                    "source_ordinal",
                    "line_number",
                }:
                    raise ValueError(
                        f"source line index reference for {domain!r} is invalid"
                    )
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
                parsed_references.append(
                    SourceLineReference(
                        source_ordinal=source_ordinal,
                        line_number=line_number,
                    )
                )
            if len(set(parsed_references)) != len(parsed_references):
                raise ValueError(
                    f"source line index references for {domain!r} contain duplicates"
                )
            for reference in parsed_references:
                if reference.source_ordinal >= len(formats):
                    raise ValueError(
                        f"source line index reference for {domain!r} has an "
                        "unknown source ordinal"
                    )
            parsed[domain] = tuple(sorted(parsed_references))
        return cls(
            source_formats=tuple(formats),
            registrable_domain_lines=parsed,
        )


def load_source_line_index(path: Path) -> SourceLineIndex:
    """Read and validate one source-line index file."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read source line index {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"source line index {path} is not valid JSON: {exc}") from exc
    return SourceLineIndex.from_payload(payload)


def write_source_line_index(index: SourceLineIndex, path: Path) -> None:
    """Persist one source-line index file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(index.to_payload(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
