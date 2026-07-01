"""Manual prepare-input loading."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from domain_pipeline.prepare.sources.parser import DomainListParser, ParsedDomainEntry


@dataclass(frozen=True)
class ManualInputSet:
    """Prepared operator input entries and their source paths."""

    manually_selected_for_filtered_path: Path
    manually_excluded_from_sources_path: Path
    manually_added_path: Path
    manually_selected_for_filtered_entries: dict[str, ParsedDomainEntry]
    manually_excluded_from_sources_entries: dict[str, ParsedDomainEntry]
    manually_added_entries: dict[str, ParsedDomainEntry]


class ManualInputLoader:
    """Load supported operator input files."""

    def __init__(self, *, source_root: Path) -> None:
        self.source_root = source_root

    def path(self, directory: str, config_name: str) -> Path:
        """Return one config-scoped manual input path."""
        return self.source_root / "input" / directory / f"{config_name}.txt"

    def load_file(self, path: Path) -> dict[str, ParsedDomainEntry]:
        """Load manual entries from one optional file."""
        if not path.is_file():
            return {}
        parser = DomainListParser()
        entries: dict[str, ParsedDomainEntry] = {}
        for entry in parser.process_entries(
            path.read_text(encoding="utf-8").splitlines(keepends=True)
        ):
            entries[entry.host] = entry
        return entries

    def load(self, config_name: str) -> ManualInputSet:
        """Load and validate all manual inputs for one config."""
        manually_selected_for_filtered_path = self.path(
            "manually_selected_for_filtered", config_name
        )
        manually_excluded_from_sources_path = self.path(
            "manually_excluded_from_sources", config_name
        )
        manually_added_path = self.path("manually_added", config_name)
        manually_selected_for_filtered_entries = self.load_file(
            manually_selected_for_filtered_path
        )
        manually_excluded_from_sources_entries = self.load_file(
            manually_excluded_from_sources_path
        )
        manually_added_entries = self.load_file(manually_added_path)
        if set(manually_added_entries) & set(manually_selected_for_filtered_entries):
            raise ValueError(
                f"{manually_added_path} conflicts with manually selected file "
                f"{manually_selected_for_filtered_path}"
            )
        if set(manually_added_entries) & set(manually_excluded_from_sources_entries):
            raise ValueError(
                f"{manually_added_path} conflicts with manually excluded file "
                f"{manually_excluded_from_sources_path}"
            )
        if set(manually_selected_for_filtered_entries) & set(
            manually_excluded_from_sources_entries
        ):
            raise ValueError(
                f"{manually_selected_for_filtered_path} conflicts with manually "
                f"excluded file {manually_excluded_from_sources_path}"
            )
        return ManualInputSet(
            manually_selected_for_filtered_path=manually_selected_for_filtered_path,
            manually_excluded_from_sources_path=manually_excluded_from_sources_path,
            manually_added_path=manually_added_path,
            manually_selected_for_filtered_entries=(
                manually_selected_for_filtered_entries
            ),
            manually_excluded_from_sources_entries=(
                manually_excluded_from_sources_entries
            ),
            manually_added_entries=manually_added_entries,
        )
