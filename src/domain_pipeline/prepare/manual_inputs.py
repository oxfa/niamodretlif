"""Manual prepare-input loading."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from domain_pipeline.prepare.sources.parser import DomainListParser, ParsedDomainEntry


@dataclass(frozen=True)
class ManualInputSet:
    """Prepared manual add/pass/out entries and their source paths."""

    pass_path: Path
    out_path: Path
    add_path: Path
    pass_entries: dict[str, ParsedDomainEntry]
    out_entries: dict[str, ParsedDomainEntry]
    add_entries: dict[str, ParsedDomainEntry]


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
        pass_path = self.path("manual_filter_pass", config_name)
        out_path = self.path("manual_filter_out", config_name)
        add_path = self.path("manual_add", config_name)
        pass_entries = self.load_file(pass_path)
        out_entries = self.load_file(out_path)
        add_entries = self.load_file(add_path)
        if set(add_entries) & set(pass_entries):
            raise ValueError(
                f"{add_path} conflicts with manual filter-pass file {pass_path}"
            )
        if set(add_entries) & set(out_entries):
            raise ValueError(
                f"{add_path} conflicts with manual filter-out file {out_path}"
            )
        return ManualInputSet(
            pass_path=pass_path,
            out_path=out_path,
            add_path=add_path,
            pass_entries=pass_entries,
            out_entries=out_entries,
            add_entries=add_entries,
        )
