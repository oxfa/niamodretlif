"""Aggregate log merge owner."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable


class AggregateLogMerger:
    """Merge embedded worker log payloads into the aggregate runtime log."""

    def non_empty_sections(self, log_texts: Iterable[str]) -> list[str]:
        """Return stripped non-empty log sections in input order."""
        return [log_text.strip() for log_text in log_texts if log_text.strip()]

    def merge_texts(
        self,
        *,
        log_texts: Iterable[str],
        target_path: Path,
    ) -> None:
        """Merge embedded non-empty worker log sections into one final log file."""
        sections = self.non_empty_sections(log_texts)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        if sections:
            target_path.write_text("\n\n".join(sections) + "\n", encoding="utf-8")
            return
        target_path.write_text("", encoding="utf-8")
