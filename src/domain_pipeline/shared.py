"""Neutral shared pipeline types and file-format constants."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

OUTPUT_SUFFIXES = {"txt": "txt", "audit": "jsonl"}
REVIEW_OUTPUT_FORMAT = "csv"


@dataclass(frozen=True)
class SourceJob:
    """Concrete input job derived from one configured source."""

    source_id: str
    input_label: str
    output_stem: str
    lines: list[str]
    config: dict[str, Any]
