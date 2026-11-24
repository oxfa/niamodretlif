"""Regression tests for tabular source index preservation."""

from pathlib import Path

import pytest

from domain_pipeline.prepare.source_line_index import (
    SourceLineIndex,
    load_source_line_index,
    write_source_line_index,
)


def test_empty_reference_list_round_trips(tmp_path: Path) -> None:
    """Empty reference list round trips."""
    original = SourceLineIndex.from_payload(
        {
            "source_formats": ["plain"],
            "registrable_domain_lines": {
                "empty.example": [],
                "used.example": [{"source_ordinal": 0, "line_number": 1}],
            },
        }
    )
    index_path, formats_path = tmp_path / "index.csv", tmp_path / "formats.csv"
    write_source_line_index(original, index_path, formats_path)
    assert load_source_line_index(index_path, formats_path) == original


def test_empty_reference_list_without_source_formats_round_trips(
    tmp_path: Path,
) -> None:
    """Empty reference list without source formats round trips."""
    original = SourceLineIndex.from_payload(
        {"source_formats": [], "registrable_domain_lines": {"empty.example": []}}
    )
    index_path, formats_path = tmp_path / "index.csv", tmp_path / "formats.csv"
    write_source_line_index(original, index_path, formats_path)
    assert load_source_line_index(index_path, formats_path) == original


@pytest.mark.parametrize(
    "rows",
    [
        "empty.example,,\nempty.example,,\n",
        "empty.example,,\nempty.example,0,1\n",
        "empty.example,0,1\nempty.example,,\n",
        "empty.example,0,\n",
        "empty.example,,1\n",
    ],
)
def test_invalid_empty_reference_rows_are_rejected(tmp_path: Path, rows: str) -> None:
    """Invalid empty reference rows are rejected."""
    index_path, formats_path = tmp_path / "index.csv", tmp_path / "formats.csv"
    index_path.write_text("registrable_domain,source_ordinal,line_number\n" + rows)
    formats_path.write_text("source_ordinal,source_format\n0,plain\n")
    with pytest.raises(ValueError):
        load_source_line_index(index_path, formats_path)
