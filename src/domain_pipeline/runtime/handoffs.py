"""Phase handoff validation and persistence helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
REQUIRED_NEXT_PHASE_KEYS = {
    "phase",
    "goal",
    "repo_inputs",
    "external_inputs",
    "locked_decisions",
    "interfaces_to_trust",
    "files_to_modify",
    "files_to_inspect",
    "tests_to_add_or_update",
    "verification_to_run",
    "work_required",
    "must_not_do",
    "open_risks",
}
REQUIRED_PRODUCED_KEYS = {
    "artifacts_produced",
    "verification_done",
    "status",
}
VALID_PHASE_STATUSES = {"passed", "passed_with_risks", "failed"}


def handoff_path(phase_name: str) -> Path:
    """Return the canonical path for a phase handoff."""
    return Path("plan") / "handoffs" / f"{phase_name}.json"


def validate_handoff_payload(payload: dict[str, Any]) -> None:
    """Raise ValueError when a handoff payload does not meet the required schema."""
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"handoff schema_version must be {SCHEMA_VERSION}, got {payload.get('schema_version')!r}"
        )
    if not isinstance(payload.get("inputs_read"), list):
        raise ValueError("handoff inputs_read must be a list")
    next_phase = payload.get("for_next_phase")
    if not isinstance(next_phase, dict):
        raise ValueError("handoff for_next_phase must be an object")
    missing_next_phase = REQUIRED_NEXT_PHASE_KEYS.difference(next_phase)
    if missing_next_phase:
        raise ValueError(
            "handoff for_next_phase is missing required keys: "
            + ", ".join(sorted(missing_next_phase))
        )
    produced = payload.get("produced_by_phase")
    if not isinstance(produced, dict):
        raise ValueError("handoff produced_by_phase must be an object")
    missing_produced = REQUIRED_PRODUCED_KEYS.difference(produced)
    if missing_produced:
        raise ValueError(
            "handoff produced_by_phase is missing required keys: "
            + ", ".join(sorted(missing_produced))
        )
    if produced.get("status") not in VALID_PHASE_STATUSES:
        raise ValueError(
            "handoff produced_by_phase.status must be one of "
            + ", ".join(sorted(VALID_PHASE_STATUSES))
        )


def read_and_validate_handoff(path: Path, *, expected_phase: str | None = None) -> dict[str, Any]:
    """Load a handoff from disk and validate the required schema."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"handoff {path} must be a JSON object")
    validate_handoff_payload(payload)
    if expected_phase is not None and payload.get("phase") != expected_phase:
        raise ValueError(
            f"handoff {path} phase must be {expected_phase!r}, got {payload.get('phase')!r}"
        )
    return payload


def write_handoff(path: Path, payload: dict[str, Any]) -> None:
    """Validate and persist a handoff JSON file."""
    validate_handoff_payload(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

