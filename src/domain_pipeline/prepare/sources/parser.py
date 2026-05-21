"""Domain list parsing and normalization.

This module provides ``DomainListParser``, the prepare-stage parser for the
source-to-worker pipeline. It inspects each input source,
determines which predefined file format it uses, and then parses the file with
the corresponding extractor before worker runtime checks begin.

Supported input formats:

Explicitly configurable formats:

* **Plain text** - one domain per line (for example ``example.com``).
* **Hosts files** - lines prefixed with an IP address such as
  ``0.0.0.0 example.com`` or ``127.0.0.1 example.com``.
* **AdBlock / uBlock network filters** - rules like ``||example.com^``
  or exception rules like ``@@||example.com^``. Cosmetic filters
  (containing ``##`` or ``#@#``) are discarded.
* **dnsmasq server rules** - lines like ``server=/example.com/8.8.8.8``.

Auto-detected-only formats:

* **Surge RULE-SET domain declarations** - concrete ``DOMAIN`` and
  ``DOMAIN-SUFFIX`` declarations without policy. Unsupported Surge rule types
  are not partially parsed; the source remains unrecognized.
* **Surge DOMAIN-SET lists** - domain-list entries where leading-dot names map
  to suffix semantics including the apex domain.

Comments - lines starting with ``#`` or ``!`` are ignored.

Processing steps applied to each file:

1. Strip blank lines, comments, and cosmetic filters.
2. Detect one predefined file format for the entire file.
3. Extract domains using that format's parser only.
4. Lowercase and remove trailing dots.
5. Encode IDN labels to Punycode (IDNA).
6. Validate structural syntax (RFC 1035 label limits).
7. Extract the DNS delegation target (ICANN eTLD+1) via ``publicsuffix2``.
8. Deduplicate normalized entries by host, input kind, and apex scope while
   preserving their registrable domain.

Files that are mixed-format or unrecognized are skipped.

Dependencies:
    - ``publicsuffix2`` (mandatory) for accurate ICANN registrable-domain
      extraction, including complex suffixes like ``.co.uk``.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import logging
import re
from collections.abc import MutableMapping
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Iterator, Optional, Set

import publicsuffix2  # type: ignore

log = logging.getLogger(__name__)
_PRIVATE_SUFFIX_SECTION_MARKER = "// ===BEGIN PRIVATE DOMAINS==="


@lru_cache(maxsize=1)
def _icann_public_suffix_list() -> publicsuffix2.PublicSuffixList:
    """Return a cached PSL view excluding private delegated suffixes."""
    suffix_list_path = Path(publicsuffix2.__file__).with_name("public_suffix_list.dat")
    icann_lines: list[str] = []
    for line in suffix_list_path.read_text(encoding="utf-8").splitlines():
        if line.strip() == _PRIVATE_SUFFIX_SECTION_MARKER:
            break
        icann_lines.append(line)
    return publicsuffix2.PublicSuffixList(icann_lines)


# The parsed record intentionally keeps a stable, explicit shape for runtime
# output and test assertions.


@dataclasses.dataclass(frozen=True)
class ParsedInputSemantics:
    """Input-origin semantics attached to a normalized parsed domain entry."""

    input_name: str = ""
    public_suffix: str = ""
    is_public_suffix_input: bool = False
    input_kind: str = "exact_host"
    apex_scope: str = "exact_only"
    source_format: str = "plain"


@dataclasses.dataclass(frozen=True)
class ParsedDomainEntry:
    """A normalized host entry paired with its registrable domain."""

    host: str
    registrable_domain: str
    semantics: ParsedInputSemantics = dataclasses.field(
        default_factory=ParsedInputSemantics
    )


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
    SURGE_RULESET = "surge_ruleset"
    SURGE_DOMAIN_SET = "surge_domain_set"
    MIXED = "mixed"
    UNKNOWN = "unknown"


@dataclasses.dataclass(frozen=True)
class ParsedFormatLine:
    """Format-specific input token and source semantics for one cleaned line."""

    input_name: str
    input_kind: str
    apex_scope: str


class DomainSyntax:
    """Shared domain syntax and normalization helpers for source-format handlers."""

    domain_regex = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
    )
    single_label_regex = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

    def normalize(self, host: str) -> str:
        """Return a lowercase ASCII domain token or an empty string."""
        host = host.lower().rstrip(".")
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError:
            return ""

    def is_valid_syntax(self, domain: str) -> bool:
        """Return whether a normalized domain has valid label structure."""
        if len(domain) > 253 or not domain:
            return False
        return bool(
            self.domain_regex.match(domain) or self.single_label_regex.match(domain)
        )

    def looks_like_domain(self, value: str) -> bool:
        """Return whether a raw token normalizes to a valid domain."""
        normalized = self.normalize(value)
        return bool(normalized) and self.is_valid_syntax(normalized)


class SourceFormatHandler:
    """Single-format line matcher and extractor."""

    format: InputFileFormat

    def matches_line(self, line: str, syntax: DomainSyntax) -> bool:
        """Return whether this handler recognizes one cleaned source line."""
        raise NotImplementedError

    def parse_line(self, line: str, syntax: DomainSyntax) -> ParsedFormatLine:
        """Return the extracted input token and semantics for one cleaned line."""
        raise NotImplementedError

    @staticmethod
    def _split_rule_name(name: str) -> tuple[str, str]:
        """Return the semantic apex scope and normalized rule target token."""
        if name.startswith("*."):
            return "exclude_apex", name[2:]
        if name.startswith("."):
            return "exclude_apex", name[1:]
        return "include_apex", name


class DnsmasqFormatHandler(SourceFormatHandler):
    """Matcher and extractor for dnsmasq server rules."""

    format = InputFileFormat.DNSMASQ
    line_regex = re.compile(r"^server=/([^/\s]+)/([^\s]+)$")

    def matches_line(self, line: str, syntax: DomainSyntax) -> bool:
        """Return whether the line has dnsmasq server-rule shape."""
        _ = syntax
        return self.line_regex.match(line) is not None

    def parse_line(self, line: str, syntax: DomainSyntax) -> ParsedFormatLine:
        """Extract dnsmasq rule target and suffix semantics."""
        _ = syntax
        match = self.line_regex.match(line)
        input_name = line if match is None else match.group(1)
        apex_scope, input_name = self._split_rule_name(input_name)
        return ParsedFormatLine(input_name, "suffix_rule", apex_scope)


class AdblockFormatHandler(SourceFormatHandler):
    """Matcher and extractor for AdBlock/uBlock network filters."""

    format = InputFileFormat.ADBLOCK
    line_regex = re.compile(r"^(?:@@)?\|\|[^^\s]+\^$")

    def matches_line(self, line: str, syntax: DomainSyntax) -> bool:
        """Return whether the line has AdBlock network-filter shape."""
        _ = syntax
        return self.line_regex.match(line) is not None

    def parse_line(self, line: str, syntax: DomainSyntax) -> ParsedFormatLine:
        """Extract AdBlock rule target and suffix semantics."""
        _ = syntax
        input_name = line.lstrip("@|").rstrip("^")
        apex_scope, input_name = self._split_rule_name(input_name)
        return ParsedFormatLine(input_name, "suffix_rule", apex_scope)


class HostsFormatHandler(SourceFormatHandler):
    """Matcher and extractor for hosts-file address mappings."""

    format = InputFileFormat.HOSTS

    def matches_line(self, line: str, syntax: DomainSyntax) -> bool:
        """Return whether the line begins with a hosts-file IP literal."""
        _ = syntax
        parts = line.split()
        return len(parts) >= 2 and self._is_valid_hosts_address(parts[0])

    def parse_line(self, line: str, syntax: DomainSyntax) -> ParsedFormatLine:
        """Extract the hostname token from a hosts-file line."""
        _ = syntax
        parts = line.split()
        input_name = parts[1] if len(parts) >= 2 else line
        return ParsedFormatLine(input_name, "exact_host", "exact_only")

    @staticmethod
    def _is_valid_hosts_address(value: str) -> bool:
        """Return whether a hosts-file address token is a valid IP literal."""
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return False
        return True


class PlainFormatHandler(SourceFormatHandler):
    """Matcher and extractor for plain one-domain-per-line lists."""

    format = InputFileFormat.PLAIN

    def matches_line(self, line: str, syntax: DomainSyntax) -> bool:
        """Return whether one cleaned line looks like a plain domain."""
        return syntax.looks_like_domain(line)

    def parse_line(self, line: str, syntax: DomainSyntax) -> ParsedFormatLine:
        """Return exact-host semantics for a plain domain line."""
        _ = syntax
        return ParsedFormatLine(line, "exact_host", "exact_only")


class SurgeRuleSetFormatHandler(SourceFormatHandler):
    """Matcher and extractor for supported Surge RULE-SET domain rules."""

    format = InputFileFormat.SURGE_RULESET
    supported_rule_types = {"DOMAIN", "DOMAIN-SUFFIX"}

    def matches_line(self, line: str, syntax: DomainSyntax) -> bool:
        """Return whether one line is a supported concrete-domain Surge rule."""
        parts = self._parts(line)
        if parts is None:
            return False
        rule_type, value = parts
        return rule_type in self.supported_rule_types and syntax.looks_like_domain(
            value
        )

    def parse_line(self, line: str, syntax: DomainSyntax) -> ParsedFormatLine:
        """Extract supported Surge RULE-SET domain semantics."""
        _ = syntax
        rule_type, value = self._parts(line) or ("", "")
        if rule_type == "DOMAIN-SUFFIX":
            return ParsedFormatLine(value, "suffix_rule", "include_apex")
        return ParsedFormatLine(value, "exact_host", "exact_only")

    @staticmethod
    def _parts(line: str) -> tuple[str, str] | None:
        """Return the normalized rule type and value for a two-part Surge rule."""
        parts = [part.strip() for part in line.split(",")]
        if len(parts) != 2:
            return None
        rule_type, value = parts
        return rule_type.upper(), value


class SurgeDomainSetFormatHandler(SourceFormatHandler):
    """Matcher and extractor for supported Surge DOMAIN-SET entries."""

    format = InputFileFormat.SURGE_DOMAIN_SET

    def matches_line(self, line: str, syntax: DomainSyntax) -> bool:
        """Return whether one line is a supported Surge DOMAIN-SET entry."""
        if "," in line or "/" in line or len(line.split()) != 1:
            return False
        value = line[1:] if line.startswith(".") else line
        return bool(value) and syntax.looks_like_domain(value)

    def parse_line(self, line: str, syntax: DomainSyntax) -> ParsedFormatLine:
        """Extract exact-host or include-apex suffix semantics."""
        _ = syntax
        if line.startswith("."):
            return ParsedFormatLine(line[1:], "suffix_rule", "include_apex")
        return ParsedFormatLine(line, "exact_host", "exact_only")


class DomainListParser:
    """Parses, cleans, and extracts hosts from various list formats.

    Each input source must match one predefined format before any host extraction
    runs. Supported explicit formats are plain domain lists, classic hosts
    files, AdBlock network filters, and dnsmasq server rules. Auto-detected-only
    formats include supported Surge RULE-SET domain declarations and Surge
    DOMAIN-SET domain lists. Extracted hosts are normalized, validated,
    converted to ICANN registrable domains with publicsuffix2, and deduplicated.
    """

    def __init__(self) -> None:
        """Initialize source-format handlers and shared syntax helpers."""
        self.syntax = DomainSyntax()
        self._handlers: tuple[SourceFormatHandler, ...] = (
            DnsmasqFormatHandler(),
            AdblockFormatHandler(),
            HostsFormatHandler(),
            PlainFormatHandler(),
            SurgeRuleSetFormatHandler(),
            SurgeDomainSetFormatHandler(),
        )
        self._handlers_by_format = {
            handler.format: handler for handler in self._handlers
        }

    def is_valid_syntax(self, domain: str) -> bool:
        """Validate the structural syntax of a domain name.

        Args:
            domain: The normalized domain string to check.

        Returns:
            True if it looks like a valid domain, False otherwise.
        """
        return self.syntax.is_valid_syntax(domain)

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

    def _looks_like_plain_domain(self, line: str) -> bool:
        """Return True when a cleaned line normalizes to a valid domain."""
        return self.syntax.looks_like_domain(line)

    def detect_file_format(self, lines: Iterable[str]) -> InputFileFormat:
        """Classify a whole input source into one predefined format.

        Blank lines, comment lines, and cosmetic AdBlock rules are ignored.
        Files with conflicting recognized formats are classified as mixed.
        """
        cleaned_lines = [
            line
            for raw_line in lines
            if (line := self._strip_comments_and_cosmetics(raw_line))
        ]
        if not cleaned_lines:
            return InputFileFormat.UNKNOWN

        domain_set_handler = self._handlers_by_format[InputFileFormat.SURGE_DOMAIN_SET]
        if self._is_surge_domain_set_file(cleaned_lines, domain_set_handler):
            return InputFileFormat.SURGE_DOMAIN_SET

        detected_formats: set[InputFileFormat] = set()
        for line in cleaned_lines:
            line_formats = self._matching_line_formats(line)
            if not line_formats:
                return InputFileFormat.UNKNOWN
            detected_formats.update(line_formats)
            if len(detected_formats) > 1:
                return InputFileFormat.MIXED

        return next(iter(detected_formats))

    def _is_surge_domain_set_file(
        self,
        lines: list[str],
        handler: SourceFormatHandler,
    ) -> bool:
        """Return whether cleaned lines form a Surge DOMAIN-SET source."""
        return any(line.startswith(".") for line in lines) and all(
            handler.matches_line(line, self.syntax) for line in lines
        )

    def _matching_line_formats(self, line: str) -> set[InputFileFormat]:
        """Return effective source formats that recognize one cleaned line."""
        matched = {
            handler.format
            for handler in self._handlers
            if handler.format is not InputFileFormat.SURGE_DOMAIN_SET
            and handler.matches_line(line, self.syntax)
        }
        if matched:
            return matched

        domain_set_handler = self._handlers_by_format[InputFileFormat.SURGE_DOMAIN_SET]
        if domain_set_handler.matches_line(line, self.syntax):
            return {InputFileFormat.SURGE_DOMAIN_SET}
        return set()

    def _entry_semantics(
        self,
        raw_line: str,
        input_format: InputFileFormat,
    ) -> tuple[str, str, str]:
        """Return the extracted input token, input kind, and apex scope."""
        line = self._strip_comments_and_cosmetics(raw_line)
        if not line:
            return "", "exact_host", "exact_only"
        handler = self._handlers_by_format.get(input_format)
        if handler is None:
            return "", "exact_host", "exact_only"
        parsed = handler.parse_line(line, self.syntax)
        return parsed.input_name, parsed.input_kind, parsed.apex_scope

    def normalize(self, host: str) -> str:
        """Normalize a pre-extracted host.

        Args:
            host: A host extracted using a format-specific parser.

        Returns:
            A lowercase, stripped ascii domain, or empty string if invalid.
        """
        return self.syntax.normalize(host)

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
            lines: Iterable of raw input lines.
            stats: Optional mutable mapping populated with detected-format counters.

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
        file_format = self._resolve_file_format(lines, forced_format)
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
            parsed_record = self._parse_record(raw_line, line_index, file_format)
            if parsed_record is None:
                continue
            entry_key, record = parsed_record
            if entry_key in seen_entries:
                log.debug(
                    "Skipped (duplicate entry): %s kind=%s apex=%s",
                    entry_key[0],
                    entry_key[1],
                    entry_key[2],
                )
                continue
            seen_entries.add(entry_key)
            yield record

    def _resolve_file_format(
        self,
        lines: list[str],
        forced_format: InputFileFormat | str | None,
    ) -> InputFileFormat:
        """Return the detected or explicitly forced source file format."""
        if forced_format is None or forced_format == "auto":
            return self.detect_file_format(lines)
        if isinstance(forced_format, InputFileFormat):
            return forced_format
        return InputFileFormat(str(forced_format))

    def _parse_record(
        self,
        raw_line: str,
        line_index: int,
        file_format: InputFileFormat,
    ) -> tuple[tuple[str, str, str], ParsedDomainEntryRecord] | None:
        """Return a deduplication key and parsed record for one raw source line."""
        input_name, input_kind, apex_scope = self._entry_semantics(
            raw_line, file_format
        )
        normalized = self.normalize(input_name)
        if not normalized:
            log.debug("Skipped (empty after normalization): %r", raw_line.strip())
            return None
        if not self.is_valid_syntax(normalized):
            log.debug("Skipped (invalid syntax): %r", normalized)
            return None

        public_suffix_parts = self._public_suffix_parts(normalized)
        if public_suffix_parts is None:
            return None
        public_suffix, root = public_suffix_parts
        entry_key = (normalized, input_kind, apex_scope)
        return entry_key, ParsedDomainEntryRecord(
            entry=ParsedDomainEntry(
                host=normalized,
                registrable_domain="" if normalized == public_suffix else root,
                semantics=ParsedInputSemantics(
                    input_name=input_name,
                    public_suffix=public_suffix,
                    is_public_suffix_input=normalized == public_suffix,
                    input_kind=input_kind,
                    apex_scope=apex_scope,
                    source_format=file_format.value,
                ),
            ),
            raw_line=raw_line,
            line_index=line_index,
        )

    def _public_suffix_parts(self, normalized: str) -> tuple[str, str] | None:
        """Return the strict ICANN public suffix and registrable root."""
        try:
            public_suffix_list = _icann_public_suffix_list()
            public_suffix = public_suffix_list.get_tld(normalized, strict=True)
            root = public_suffix_list.get_sld(normalized, strict=True)
        except (ValueError, TypeError) as exc:
            log.debug("Skipped (publicsuffix2 error for %r): %s", normalized, exc)
            return None

        if public_suffix is None:
            log.debug("Skipped (no strict public suffix match): %s", normalized)
            return None
        return str(public_suffix), str(root)
