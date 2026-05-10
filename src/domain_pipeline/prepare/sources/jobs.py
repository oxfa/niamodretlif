"""Prepare-owned source reading and source-job construction."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import requests


@dataclass(frozen=True)
class SourceJob:
    """Concrete input job derived from one configured source."""

    source_id: str
    input_label: str
    output_stem: str
    lines: list[str]
    config: dict[str, Any]


SourceLineReader = Callable[[dict[str, Any]], tuple[str, list[str]]]


def read_source_lines(source_config: dict[str, Any]) -> tuple[str, list[str]]:
    """Return configured source input lines from files or URLs."""
    input_payload = source_config["input"]
    location = str(input_payload["location"])
    label = str(input_payload.get("label") or location)
    if input_payload["type"] == "file":
        return label, Path(location).read_text(encoding="utf-8").splitlines(
            keepends=True
        )
    response = requests.get(
        location, timeout=float(source_config["fetch"]["request_timeout"])
    )
    response.raise_for_status()
    return label, response.text.splitlines(keepends=True)


class SourceJobFactory:
    """Build enabled source jobs from normalized config."""

    def __init__(self, reader: SourceLineReader | None = None) -> None:
        self.reader = reader or read_source_lines

    def build_job(
        self,
        *,
        config_name: str,
        source: dict[str, Any],
        source_root: Path | None = None,
    ) -> SourceJob | None:
        """Build one enabled source job, or return None for a disabled source."""
        if not source.get("enabled", True):
            return None
        root = source_root or Path(".")
        source_copy = dict(source)
        input_payload = dict(source_copy["input"])
        if input_payload["type"] == "file":
            location_path = Path(str(input_payload["location"]))
            if not location_path.is_absolute():
                input_payload["location"] = str(root / location_path)
            source_copy["input"] = input_payload
        label, lines = self.reader(source_copy)
        return SourceJob(
            source_id=str(source["id"]),
            input_label=label,
            output_stem=config_name,
            lines=lines,
            config=source,
        )

    def build_jobs(
        self, config: dict[str, Any], *, source_root: Path | None = None
    ) -> list[SourceJob]:
        """Build enabled source jobs while preserving current config behavior."""
        jobs: list[SourceJob] = []
        config_name = str(config["config_name"])
        for source in config["sources"]:
            job = self.build_job(
                config_name=config_name,
                source=source,
                source_root=source_root,
            )
            if job is not None:
                jobs.append(job)
        return jobs
