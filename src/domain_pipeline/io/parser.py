"""Domain list parsing and normalization.

This module provides ``DomainListParser``, the mandatory first stage of the
root-filter plus host-processing pipeline. It inspects each input source,
determines which predefined file format it uses, and then parses the file with
the corresponding extractor before runtime checks begin.

Supported input formats:

* **Plain text** — one domain per line (for example ``example.com``).
* **Hosts files** — lines prefixed with an IP address such as
  ``0.0.0.0 example.com`` or ``127.0.0.1 example.com``.
* **AdBlock / uBlock network filters** — rules like ``||example.com^``
  or exception rules like ``@@||example.com^``. Cosmetic filters
  (containing ``##`` or ``#@#``) are discarded.
* **dnsmasq server rules** — lines like ``server=/example.com/8.8.8.8``.
* **Comments** — lines starting with ``#`` or ``!`` are ignored.

Processing steps applied to each file:

1. Strip blank lines, comments, and cosmetic filters.
2. Detect one predefined file format for the entire file.
3. Extract domains using that format's parser only.
4. Lowercase and remove trailing dots.
5. Encode IDN labels to Punycode (IDNA).
6. Validate structural syntax (RFC 1035 label limits).
7. Extract the registrable domain (eTLD+1) via ``publicsuffix2``.
8. Deduplicate exact hosts while preserving their registrable domain.

Files that are mixed-format or unrecognized are skipped.

Dependencies:
    - ``publicsuffix2`` (mandatory) for accurate registrable-domain
      extraction, including complex suffixes like ``.eu.org``.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import logging
import re
from collections.abc import MutableMapping
from enum import Enum
from typing import Iterable, Iterator, Optional, Set

import publicsuffix2  # type: ignore

log = logging.getLogger(__name__)


# The parsed record intentionally keeps a stable, explicit shape for runtime
# output and test assertions.
# pylint: disable=too-many-instance-attributes
@dataclasses.dataclass(frozen=True)
class ParsedDomainEntry:
    """A normalized host entry paired with its registrable domain."""

    host: str
    registrable_domain: str
    input_name: str = ""
    public_suffix: str = ""
    is_public_suffix_input: bool = False
    input_kind: str = "exact_host"
    apex_scope: str = "exact_only"
    source_format: str = "plain"


@dataclasses.dataclass(frozen=True)
class ParsedDomainEntryRecord:
    """One parsed entry paired with its surviving source-line provenance."""

    entry: ParsedDomainEntry
    raw_line: str
    line_index: int


class InputFileFormat(str, Enum):
    """Supported whole-file input formats."""

    PLAIN = "plain"
    HOSTS = "hosts"
    ADBLOCK = "adblock"
    DNSMASQ = "dnsmasq"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class DomainListParser:
    """Parses, cleans, and extracts hosts from various list formats.

    Each input source must match one predefined format before any host extraction
    runs. Supported formats are plain domain lists, classic hosts files, AdBlock
    network filters, and dnsmasq server rules. Extracted hosts are normalized,
    validated, converted to registrable domains with publicsuffix2, and deduplicated.
    """

    # Basic RFC 1035 labels (at least one dot required).
    _DOMAIN_REGEX = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
    )
    _SINGLE_LABEL_REGEX = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
    _PLAIN_LINE_REGEX = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
    )
    _DNSMASQ_LINE_REGEX = re.compile(r"^server=/([^/\s]+)/([^\s]+)$")
    _ADBLOCK_LINE_REGEX = re.compile(r"^(?:@@)?\|\|[^^\s]+\^$")

    def _is_valid_hosts_address(self, value: str) -> bool:
        """Return whether a hosts-file address token is a valid IP literal."""
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return False
        return True

    def is_valid_syntax(self, domain: str) -> bool:
        """Validate the structural syntax of a domain name.

        Args:
            domain: The normalized domain string to check.

        Returns:
            True if it looks like a valid domain, False otherwise.
        """
        if len(domain) > 253 or not domain:
            return False
        return bool(
            self._DOMAIN_REGEX.match(domain) or self._SINGLE_LABEL_REGEX.match(domain)
        )

    def _strip_comments_and_cosmetics(self, raw_line: str) -> str:
        """Remove comments and cosmetic AdBlock filters.

        Args:
            raw_line: A raw list entry.

        Returns:
            String with comments stripped, or empty if it's cosmetic.
        """
        line = raw_line.split("#", 1)[0].split("!", 1)[0].strip()
        # Drop cosmetic adblock rules (##, #@#) and empty lines
        if not line or "##" in raw_line or "#@#" in raw_line:
            return ""
        return line

    def _detect_line_format(self, line: str) -> InputFileFormat:
        """Return the predefined format matched by a cleaned line."""
        if self._DNSMASQ_LINE_REGEX.match(line):
            return InputFileFormat.DNSMASQ
        if self._ADBLOCK_LINE_REGEX.match(line):
            return InputFileFormat.ADBLOCK

        parts = line.split()
        if len(parts) >= 2:
            first = parts[0]
            if self._is_valid_hosts_address(first):
                return InputFileFormat.HOSTS

        # Plain text is intentionally checked after the structured formats so
        # trailing dots and IDNs can be normalized before validation.
        if self._looks_like_plain_domain(line):
            return InputFileFormat.PLAIN
        return InputFileFormat.UNKNOWN

    def _looks_like_plain_domain(self, line: str) -> bool:
        """Return True when a cleaned line normalizes to a valid domain."""
        normalized = self.normalize(line)
        return bool(normalized) and self.is_valid_syntax(normalized)

    def detect_file_format(self, lines: Iterable[str]) -> InputFileFormat:
        """Classify a whole input source into one predefined format.

        Blank lines, comment lines, and cosmetic AdBlock rules are ignored.
        Files with conflicting recognized formats are classified as mixed.
        """
        detected_formats: set[InputFileFormat] = set()
        saw_content = False
        for raw_line in lines:
            line = self._strip_comments_and_cosmetics(raw_line)
            if not line:
                continue
            saw_content = True
            line_format = self._detect_line_format(line)
            if line_format is InputFileFormat.UNKNOWN:
                return InputFileFormat.UNKNOWN
            detected_formats.add(line_format)
            if len(detected_formats) > 1:
                return InputFileFormat.MIXED

        if not saw_content:
            return InputFileFormat.UNKNOWN
        return next(iter(detected_formats))

    def _extract_from_hosts(self, line: str) -> str:
        """Extract domains from hosts-file lines like '0.0.0.0 example.com'.

        Args:
            line: A partially cleaned list entry.

        Returns:
            The parsed domain string.
        """
        parts = line.split()
        if len(parts) >= 2:
            first = parts[0]
            if self._is_valid_hosts_address(first):
                return parts[1]
        return line

    def _clean_adblock_markers(self, line: str) -> str:
        """Remove AdBlock markers like ||, @@, ^.

        Args:
            line: A partially cleaned list entry.

        Returns:
            The parsed domain string.
        """
        return line.lstrip("@|").rstrip("^")

    def _split_rule_name(self, name: str) -> tuple[str, str]:
        """Return the semantic apex scope and normalized rule target token."""
        if name.startswith("*."):
            return "exclude_apex", name[2:]
        if name.startswith("."):
            return "exclude_apex", name[1:]
        return "include_apex", name

    def _extract_from_dnsmasq(self, line: str) -> str:
        """Extract the host from dnsmasq lines like 'server=/example.com/8.8.8.8'."""
        match = self._DNSMASQ_LINE_REGEX.match(line)
        if match is None:
            return line
        return match.group(1)

    def _entry_semantics(
        self,
        raw_line: str,
        input_format: InputFileFormat,
    ) -> tuple[str, str, str]:
        """Return the extracted input token, input kind, and apex scope."""
        extracted = self._extract_host(raw_line, input_format)
        if input_format in {InputFileFormat.ADBLOCK, InputFileFormat.DNSMASQ}:
            apex_scope, input_name = self._split_rule_name(extracted)
            return input_name, "suffix_rule", apex_scope
        return extracted, "exact_host", "exact_only"

    def _extract_host(self, raw_line: str, input_format: InputFileFormat) -> str:
        """Extract a host from a raw line using a single predefined format."""
        line = self._strip_comments_and_cosmetics(raw_line)
        if not line:
            return ""
        if input_format is InputFileFormat.PLAIN:
            return line
        if input_format is InputFileFormat.HOSTS:
            return self._extract_from_hosts(line)
        if input_format is InputFileFormat.ADBLOCK:
            return self._clean_adblock_markers(line)
        if input_format is InputFileFormat.DNSMASQ:
            return self._extract_from_dnsmasq(line)
        return ""

    def normalize(self, host: str) -> str:
        """Normalize a pre-extracted host.

        Args:
            host: A host extracted using a format-specific parser.

        Returns:
            A lowercase, stripped ascii domain, or empty string if invalid.
        """
        host = host.lower().rstrip(".")
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError:
            return ""

    def process_entries(
        self,
        lines: Iterable[str],
        *,
        source_name: str = "<input>",
        stats: Optional[MutableMapping[str, int]] = None,
        forced_format: InputFileFormat | str | None = None,
    ) -> Iterator[ParsedDomainEntry]:
        """Process lines into unique normalized host entries.

        Args:
            lines: Iterable of raw configurations.
            stats: Optional mutable mapping populated with cache counters.

        Yields:
            Unique normalized hosts with their registrable domain.
        """
        for record in self.process_entry_records(
            lines,
            source_name=source_name,
            stats=stats,
            forced_format=forced_format,
        ):
            yield record.entry

    def process_entry_records(
        self,
        lines: Iterable[str],
        *,
        source_name: str = "<input>",
        stats: Optional[MutableMapping[str, int]] = None,
        forced_format: InputFileFormat | str | None = None,
    ) -> Iterator[ParsedDomainEntryRecord]:
        """Process lines into unique normalized entries with source provenance."""
        lines = list(lines)
        if forced_format is None or forced_format == "auto":
            file_format = self.detect_file_format(lines)
        else:
            file_format = (
                forced_format
                if isinstance(forced_format, InputFileFormat)
                else InputFileFormat(str(forced_format))
            )
        if stats is not None:
            stats[f"format_{file_format.value}"] = (
                stats.get(f"format_{file_format.value}", 0) + 1
            )
        if file_format in {InputFileFormat.UNKNOWN, InputFileFormat.MIXED}:
            log.warning(
                "Skipped input source %s: detected %s file format",
                source_name,
                file_format.value,
            )
            return

        log.info("Detected %s input format for %s", file_format.value, source_name)

        seen_entries: Set[tuple[str, str, str]] = set()
        for line_index, raw_line in enumerate(lines):
            input_name, input_kind, apex_scope = self._entry_semantics(
                raw_line, file_format
            )
            normalized = self.normalize(input_name)
            if not normalized:
                log.debug("Skipped (empty after normalization): %r", raw_line.strip())
                continue
            if not self.is_valid_syntax(normalized):
                log.debug("Skipped (invalid syntax): %r", normalized)
                continue

            try:
                public_suffix = publicsuffix2.get_tld(normalized, strict=True)
                root = publicsuffix2.get_sld(normalized, strict=True)
            except (ValueError, TypeError) as exc:
                log.debug("Skipped (publicsuffix2 error for %r): %s", normalized, exc)
                continue

            if public_suffix is None:
                log.debug("Skipped (no strict public suffix match): %s", normalized)
                continue

            registrable_domain = "" if normalized == public_suffix else str(root)
            entry_key = (normalized, input_kind, apex_scope)
            if entry_key in seen_entries:
                log.debug(
                    "Skipped (duplicate entry): %s kind=%s apex=%s",
                    normalized,
                    input_kind,
                    apex_scope,
                )
                continue
            seen_entries.add(entry_key)
            yield ParsedDomainEntryRecord(
                entry=ParsedDomainEntry(
                    host=normalized,
                    registrable_domain=registrable_domain,
                    input_name=input_name,
                    public_suffix=str(public_suffix),
                    is_public_suffix_input=normalized == public_suffix,
                    input_kind=input_kind,
                    apex_scope=apex_scope,
                    source_format=file_format.value,
                ),
                raw_line=raw_line,
                line_index=line_index,
            )

    def process(
        self,
        lines: Iterable[str],
        *,
        source_name: str = "<input>",
        stats: Optional[MutableMapping[str, int]] = None,
    ) -> Iterator[str]:
        """Process lines into unique registrable domains.

        This compatibility wrapper preserves the original root-domain-oriented
        parser API for callers that only need registrable domains.
        """
        seen_roots: Set[str] = set()
        for entry in self.process_entries(
            lines,
            source_name=source_name,
            stats=stats,
        ):
            root = entry.registrable_domain or entry.host
            if root in seen_roots:
                continue
            seen_roots.add(root)
            yield root
