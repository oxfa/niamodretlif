"""Manual prepare-input loading."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from domain_pipeline.prepare.sources.parser import DomainListParser, ParsedDomainEntry


@dataclass(frozen=True)
class ManualInputSet:
    """Prepared manual add/pass/out entries and their source paths."""

    manual_filter_pass_path: Path
    manual_filter_out_path: Path
    manual_add_path: Path
    manual_filter_pass_entries: dict[str, ParsedDomainEntry]
    manual_filter_out_entries: dict[str, ParsedDomainEntry]
    manual_add_entries: dict[str, ParsedDomainEntry]


class ManualInputLoader:
    """Load manual add, filter-pass, and filter-out input files."""

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
        manual_filter_pass_path = self.path("manual_filter_pass", config_name)
        manual_filter_out_path = self.path("manual_filter_out", config_name)
        manual_add_path = self.path("manual_add", config_name)
        manual_filter_pass_entries = self.load_file(manual_filter_pass_path)
        manual_filter_out_entries = self.load_file(manual_filter_out_path)
        manual_add_entries = self.load_file(manual_add_path)
        if set(manual_add_entries) & set(manual_filter_pass_entries):
            raise ValueError(
                f"{manual_add_path} conflicts with manual filter-pass file "
                f"{manual_filter_pass_path}"
            )
        if set(manual_add_entries) & set(manual_filter_out_entries):
            raise ValueError(
                f"{manual_add_path} conflicts with manual filter-out file "
                f"{manual_filter_out_path}"
            )
        return ManualInputSet(
            manual_filter_pass_path=manual_filter_pass_path,
            manual_filter_out_path=manual_filter_out_path,
            manual_add_path=manual_add_path,
            manual_filter_pass_entries=manual_filter_pass_entries,
            manual_filter_out_entries=manual_filter_out_entries,
            manual_add_entries=manual_add_entries,
        )
