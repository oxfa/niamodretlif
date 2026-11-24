"""Exercise the data encodings used by the inter-job handoffs."""

import json
from pathlib import Path

import pytest

from domain_pipeline.handoff_io import read_csv, read_yaml, write_csv, write_yaml


def test_yaml_roundtrip_preserves_nested_values(tmp_path: Path) -> None:
    """Preserve nulls, nested records and strings that resemble YAML scalars."""
    path = tmp_path / "records.yaml"
    value = [{"root": "on", "date": "2024-01-02", "items": [None, True, 7, "域"]}]
    write_yaml(path, value)
    assert read_yaml(path) == value


def test_empty_yaml_sequence_has_an_explicit_yaml_document(tmp_path: Path) -> None:
    """An empty result remains YAML rather than a renamed JSON document."""
    path = tmp_path / "empty.yaml"
    write_yaml(path, [])
    assert read_yaml(path) == []
    with pytest.raises(json.JSONDecodeError):
        json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("text", ["date: 2024-01-02\n", "root: &node [*node]\n"])
def test_yaml_rejects_non_json_value_trees(tmp_path: Path, text: str) -> None:
    """Reject timestamp objects and recursive aliases from YAML input."""
    path = tmp_path / "records.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError):
        read_yaml(path)


def test_csv_roundtrip_preserves_quoted_values(tmp_path: Path) -> None:
    """Preserve commas, Unicode, quotes and embedded newlines in CSV fields."""
    path = tmp_path / "rows.csv"
    fields = ("name", "value")
    rows = [{"name": "域,\"example\"", "value": "first\nsecond"}]
    write_csv(path, fields, rows)
    assert read_csv(path, fields) == rows
