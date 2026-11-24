"""Typed CSV and YAML primitives for prepare handoff data."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Any

import yaml


def ensure_csv_field_capacity(input_bytes: int) -> None:
    """Allow a field as large as the input, without reducing the process limit."""
    if input_bytes > csv.field_size_limit():
        csv.field_size_limit(input_bytes)


def validate_yaml_tree(value: Any, active: set[int] | None = None) -> None:
    """Reject cycles and types outside the JSON value domain."""
    if value is None or isinstance(value, (str, bool, int, float)):
        return
    if not isinstance(value, (list, dict)):
        raise ValueError("YAML contains a value outside the JSON domain")
    active = set() if active is None else active
    identity = id(value)
    if identity in active:
        raise ValueError("YAML contains a cycle")
    active.add(identity)
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("YAML mapping keys must be strings")
            validate_yaml_tree(item, active)
    else:
        for item in value:
            validate_yaml_tree(item, active)
    active.remove(identity)


def write_yaml(path: Path, value: Any) -> None:
    """Write a JSON-domain value as YAML."""
    validate_yaml_tree(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(
            value,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
            explicit_start=True,
        ),
        encoding="utf-8",
    )


def read_yaml(path: Path) -> Any:
    """Read a YAML document restricted to the JSON value domain."""
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        validate_yaml_tree(value)
        return value
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"unable to read YAML handoff {path}: {exc}") from exc


def write_json(path: Path, value: Any) -> None:
    """Write a JSON-domain value as UTF-8 JSON."""
    validate_yaml_tree(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def read_json(path: Path) -> Any:
    """Read one strict JSON handoff value."""
    def reject_constant(value: str) -> None:
        raise ValueError(f"invalid JSON constant {value}")

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), parse_constant=reject_constant
        )
        validate_yaml_tree(value)
        return value
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"unable to read JSON handoff {path}: {exc}") from exc


def write_csv(path: Path, fields: tuple[str, ...], rows: list[dict[str, Any]]) -> None:
    """Write rows under an exact CSV header."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="raise")
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path: Path, fields: tuple[str, ...]) -> list[dict[str, str]]:
    """Read CSV rows with the expected header and complete fields."""
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            ensure_csv_field_capacity(os.fstat(handle.fileno()).st_size)
            reader = csv.DictReader(handle, strict=True)
            if reader.fieldnames != list(fields):
                raise ValueError(f"invalid CSV columns in {path}")
            rows = list(reader)
    except (OSError, csv.Error) as exc:
        raise ValueError(f"unable to read CSV handoff {path}: {exc}") from exc
    if any(None in row or any(value is None for value in row.values()) for row in rows):
        raise ValueError(f"invalid CSV row in {path}")
    return rows
