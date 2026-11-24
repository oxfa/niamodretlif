"""Domain list parsing and normalization.

This module provides ``DomainListParser``, the prepare-stage parser for the
source-to-worker pipeline. It inspects each input source, determines which
predefined file format it uses, and then extracts normalized hosts before
worker runtime checks begin.

Supported input formats:

Explicitly configurable formats:

* **Plain text** - one domain per line (for example ``example.com``).
* **Hosts files** - lines prefixed with an IP address such as
  ``0.0.0.0 example.com`` or ``127.0.0.1 example.com``.
* **AdBlock / uBlock filters** - exact blocking domain rules like
  ``||example.com^``. Other valid rules are retained as source lines without
  being treated as domain targets.
* **dnsmasq server rules** - lines like ``server=/example.com/8.8.8.8``.

Auto-detected-only formats:

* **Surge RULE-SET domain declarations** - concrete ``DOMAIN`` and
  ``DOMAIN-SUFFIX`` declarations without policy. Unsupported Surge rule types
  are not partially parsed; the source remains unrecognized.
* **Surge DOMAIN-SET lists** - domain-list entries where leading-dot names map
  to suffix semantics including the apex domain.

Comments - lines starting with ``#`` or ``!`` are removed. AdBlock cosmetic
filters are retained as valid non-domain source lines.

Processing steps applied to each file:

1. Remove blank lines and comments.
2. Detect one predefined file format for the entire file.
3. Extract domains using that format's parser only.
4. Lowercase and remove trailing dots.
5. Encode IDN labels to Punycode (IDNA).
6. Validate structural syntax (RFC 1035 label limits).
7. Extract the DNS delegation target (PSL eTLD+1, including PRIVATE rules).
8. Deduplicate normalized entries by host while preserving their registrable
   domain.

Files that are mixed-format or unrecognized are skipped.

Dependencies:
    - ``publicsuffix2`` (mandatory) for accurate PSL registrable-domain
      extraction, including complex suffixes like ``.co.uk`` and PRIVATE rules.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import logging
import re
import subprocess
from collections.abc import MutableMapping
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Iterator, Optional, Set

import publicsuffix2

log = logging.getLogger(__name__)

_ECMASCRIPT_REGEX_VALIDATOR = """
let source = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", chunk => { source += chunk; });
process.stdin.on("end", () => {
  const pattern = JSON.parse(source);
  try {
    new RegExp(pattern);
  } catch (error) {
    if (error instanceof SyntaxError) {
      process.stdout.write("invalid");
      return;
    }
    throw error;
  }
  process.stdout.write("valid");
});
"""


ECMASCRIPT_REGEX_VALIDATION_TIMEOUT_SECONDS = 10


@lru_cache(maxsize=128)
def _is_valid_ecmascript_regex(pattern: str) -> bool:
    """Validate one regex using the hosted Node runtime's RegExp parser."""
    try:
        result = subprocess.run(
            ["node", "-e", _ECMASCRIPT_REGEX_VALIDATOR],
            input=json.dumps(pattern),
            text=True,
            capture_output=True,
            check=False,
            timeout=ECMASCRIPT_REGEX_VALIDATION_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "Node.js ECMAScript regular-expression validator timed out after "
            f"{ECMASCRIPT_REGEX_VALIDATION_TIMEOUT_SECONDS} seconds"
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            "unable to run Node.js ECMAScript regular-expression validator"
        ) from exc

    if result.returncode != 0:
        details = result.stderr.strip()
        detail_suffix = f": {details}" if details else ""
        raise RuntimeError(
            "Node.js ECMAScript regular-expression validator exited with "
            f"status {result.returncode}{detail_suffix}"
        )
    if result.stdout == "valid":
        return True
    if result.stdout == "invalid":
        return False
    raise RuntimeError(
        "Node.js ECMAScript regular-expression validator returned unexpected output"
    )


@lru_cache(maxsize=1)
def _full_public_suffix_list() -> publicsuffix2.PublicSuffixList:
    """Return the project-owned full PSL snapshot, including PRIVATE rules."""
    suffix_list_path = Path(__file__).with_name("public_suffix_list.dat")
    return publicsuffix2.PublicSuffixList(
        suffix_list_path.read_text(encoding="utf-8").splitlines()
    )


@dataclasses.dataclass(frozen=True)
class DomainEntry:
    """A normalized host entry paired with its registrable domain."""

    host: str
    registrable_domain: str | None


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
    """Format-specific host token for one cleaned line."""

    host: str


@dataclasses.dataclass(frozen=True)
class PreparedSourceLine:
    """One retained source line and its extracted domain targets."""

    content: str
    entries: tuple[DomainEntry, ...]


@dataclasses.dataclass(frozen=True)
class SourceTargetCandidate:
    """One format-extracted domain target before PSL validation."""

    host: str
    role: str


@dataclasses.dataclass(frozen=True)
class SourceItemSyntax:
    """One format-valid item's structural parse before target validation."""

    item_kind: str
    targets: tuple[SourceTargetCandidate, ...] = ()
    no_target_reason: str | None = None
    is_metadata: bool = False
    error_reason: str | None = None


@dataclasses.dataclass(frozen=True)
class ParsedSourceTarget:
    """One normalized target and its strict-PSL outcome."""

    host: str
    registrable_domain: str | None
    role: str
    error_reason: str | None = None


@dataclasses.dataclass(frozen=True)
class ParsedSourceItem:
    """Format-valid source item with target extraction kept separate."""

    item_kind: str
    targets: tuple[ParsedSourceTarget, ...] = ()
    no_target_reason: str | None = None
    is_metadata: bool = False
    error_reason: str | None = None


@dataclasses.dataclass(frozen=True)
class ParsedSourceLine:
    """One physical source line and its already-computed item parse."""

    line_number: int
    raw_line: str
    parsed_item: ParsedSourceItem | None


@dataclasses.dataclass(frozen=True)
class ParsedSourceFile:
    """Whole-file format and per-line parses shared by prepare consumers."""

    file_format: InputFileFormat
    lines: tuple[ParsedSourceLine, ...]


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

    def parse_hosts(self, line: str, syntax: DomainSyntax) -> list[str]:
        """Return domain tokens carried by one valid source line."""
        parsed = self.parse_line(line, syntax)
        return [parsed.host] if parsed.host else []

    @staticmethod
    def _rule_host(name: str) -> str:
        """Return the host token carried by a rule-like entry."""
        if name.startswith("*."):
            return name[2:]
        if name.startswith("."):
            return name[1:]
        return name


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
        host = line if match is None else match.group(1)
        return ParsedFormatLine(self._rule_host(host))


class AdblockFormatHandler(SourceFormatHandler):
    """Parse the bounded AdBlock syntax profile."""

    format = InputFileFormat.ADBLOCK
    metadata_header = "[Adblock Plus 2.0]"
    cosmetic_markers = ("#@#", "##")
    unsupported_cosmetic_markers = ("#@?#", "#?#", "#$#", "#%#")
    _modifier_names = {"third-party", "dnstype", "denyallow", "domain"}

    def matches_line(self, line: str, syntax: DomainSyntax) -> bool:
        """Recognize a valid single-line AdBlock rule."""
        parsed = self.parse_syntax(line, syntax)
        return parsed is not None and parsed.error_reason is None

    def parse_line(self, line: str, syntax: DomainSyntax) -> ParsedFormatLine:
        """Return the first concrete request-host target, when present."""
        parsed = self.parse_syntax(line, syntax)
        if parsed is None or not parsed.targets:
            return ParsedFormatLine("")
        return ParsedFormatLine(parsed.targets[0].host)

    def parse_syntax(
        self, line: str, syntax: DomainSyntax
    ) -> SourceItemSyntax | None:
        """Parse one rule without treating target extraction as validity."""
        value = line.strip()
        if not value or value.startswith("!"):
            return None
        if value == self.metadata_header:
            return SourceItemSyntax(
                item_kind="metadata",
                no_target_reason="format_metadata",
                is_metadata=True,
            )
        if any(marker in value for marker in self.unsupported_cosmetic_markers):
            return SourceItemSyntax(
                item_kind="unsupported_cosmetic_filter",
                error_reason="unsupported_cosmetic_filter_syntax",
            )
        for marker in self.cosmetic_markers:
            if marker in value:
                return self._parse_cosmetic(value, marker, syntax)

        is_exception = value.startswith("@@")
        pattern_and_options = value[2:] if is_exception else value
        if not pattern_and_options or any(char.isspace() for char in pattern_and_options):
            return SourceItemSyntax(
                item_kind="invalid_network_filter",
                error_reason="empty_or_whitespace_network_filter",
            )

        if pattern_and_options.startswith("/"):
            closing = self._regex_closing_delimiter(pattern_and_options)
            if closing is None:
                return SourceItemSyntax(
                    item_kind="invalid_regex_filter",
                    error_reason="unterminated_regular_expression_filter",
                )
            pattern = pattern_and_options[: closing + 1]
            trailing = pattern_and_options[closing + 1 :]
            option_text: str | None = None
            if trailing:
                if not trailing.startswith("$") or len(trailing) == 1:
                    return SourceItemSyntax(
                        item_kind="invalid_regex_filter",
                        error_reason="unexpected_text_after_regular_expression",
                    )
                option_text = trailing[1:]
            option_error = self._validate_options(option_text)
            if option_error:
                return SourceItemSyntax(
                    item_kind="invalid_regex_filter",
                    error_reason=option_error,
                )
            regex_body = pattern[1:-1]
            if not _is_valid_ecmascript_regex(regex_body):
                return SourceItemSyntax(
                    item_kind="invalid_regex_filter",
                    error_reason="invalid_regular_expression_filter",
                )
            return SourceItemSyntax(
                item_kind=("exception_regex_filter" if is_exception else "regex_filter"),
                no_target_reason="regular_expression_has_no_literal_request_host",
            )

        pattern, option_text, option_error = self._split_options(pattern_and_options)
        if option_error:
            return SourceItemSyntax(
                item_kind="invalid_network_filter",
                error_reason=option_error,
            )
        option_error = self._validate_options(option_text)
        if option_error:
            return SourceItemSyntax(
                item_kind="invalid_network_filter",
                error_reason=option_error,
            )

        if not pattern:
            return SourceItemSyntax(
                item_kind="invalid_network_filter",
                error_reason="empty_network_filter_pattern",
            )
        if len(pattern) < 4:
            return SourceItemSyntax(
                item_kind="invalid_network_filter",
                error_reason="network_filter_pattern_too_short",
            )
        if pattern.startswith("||"):
            anchored_host = self._anchored_host_pattern(pattern)
            if not anchored_host:
                return SourceItemSyntax(
                    item_kind="invalid_network_filter",
                    error_reason="host_anchored_filter_requires_host",
                )
            if "*" not in anchored_host and not syntax.looks_like_domain(
                anchored_host
            ):
                return SourceItemSyntax(
                    item_kind="invalid_network_filter",
                    error_reason="invalid_host_anchored_request_host",
                )
        target = self._literal_request_host(pattern, syntax)
        if target is not None:
            return SourceItemSyntax(
                item_kind=("exception_network_filter" if is_exception else "network_filter"),
                targets=(target,),
            )
        return SourceItemSyntax(
            item_kind=("exception_network_filter" if is_exception else "network_filter"),
            no_target_reason=self._no_target_reason(pattern),
        )

    def _parse_cosmetic(
        self, value: str, marker: str, syntax: DomainSyntax
    ) -> SourceItemSyntax:
        scope, selector = value.split(marker, 1)
        if not selector:
            return SourceItemSyntax(
                item_kind="invalid_cosmetic_filter",
                error_reason="cosmetic_filter_requires_selector",
            )
        if scope:
            scopes = scope.split(",")
            for item in scopes:
                domain = item.removeprefix("~")
                if not domain or not syntax.looks_like_domain(domain):
                    return SourceItemSyntax(
                        item_kind="invalid_cosmetic_filter",
                        error_reason="invalid_cosmetic_filter_scope",
                    )
        return SourceItemSyntax(
            item_kind=(
                "cosmetic_exception_filter" if marker == "#@#" else "cosmetic_filter"
            ),
            no_target_reason="cosmetic_scope_is_context_not_request_host",
        )

    def _split_options(self, value: str) -> tuple[str, str | None, str | None]:
        """Split modifier text at the first unescaped pattern dollar."""
        for index, char in enumerate(value):
            if char != "$":
                continue
            backslashes = 0
            cursor = index - 1
            while cursor >= 0 and value[cursor] == "\\":
                backslashes += 1
                cursor -= 1
            if backslashes % 2:
                continue
            pattern, options = value[:index], value[index + 1 :]
            if not options:
                return pattern, None, "empty_adblock_modifier_list"
            return pattern, options, None
        return value, None, None

    def _validate_options(self, option_text: str | None) -> str | None:
        if option_text is None:
            return None
        options = option_text.split(",")
        if not options or any(not option for option in options):
            return "empty_adblock_modifier"
        seen: set[str] = set()
        for option in options:
            name, separator, value = option.partition("=")
            normalized_name = name.removeprefix("~").lower()
            if normalized_name not in self._modifier_names:
                return f"unsupported_adblock_modifier:{name}"
            if normalized_name in seen:
                return f"duplicate_adblock_modifier:{normalized_name}"
            seen.add(normalized_name)
            if normalized_name == "third-party":
                if separator:
                    return "third_party_modifier_must_not_have_a_value"
                continue
            if not separator or not value:
                return f"adblock_modifier_requires_value:{normalized_name}"
            values = value.split("|") if normalized_name in {"domain", "denyallow"} else [value]
            if any(not part for part in values):
                return f"empty_adblock_modifier_value:{normalized_name}"
            if normalized_name in {"domain", "denyallow"}:
                for part in values:
                    scope = part.removeprefix("~") if normalized_name == "domain" else part
                    if not scope or not DomainSyntax().looks_like_domain(scope):
                        return f"invalid_adblock_modifier_domain:{normalized_name}"
            elif any(char.isspace() for char in value):
                return f"invalid_adblock_modifier_value:{normalized_name}"
        return None

    @staticmethod
    def _regex_closing_delimiter(pattern: str) -> int | None:
        """Return the first unescaped slash after the regex opening slash."""
        for index in range(1, len(pattern)):
            if pattern[index] != "/":
                continue
            backslashes = 0
            cursor = index - 1
            while cursor >= 0 and pattern[cursor] == "\\":
                backslashes += 1
                cursor -= 1
            if backslashes % 2 == 0:
                return index
        return None

    @staticmethod
    def _literal_request_host(
        pattern: str, syntax: DomainSyntax
    ) -> SourceTargetCandidate | None:
        if syntax.looks_like_domain(pattern):
            return SourceTargetCandidate(host=pattern, role="request_host")
        authority_pattern = AdblockFormatHandler._anchored_host_pattern(pattern)
        if authority_pattern is None:
            return None
        host_end = len(authority_pattern)
        for delimiter in ("^", "/", "|", "?", ":", "#"):
            found = authority_pattern.find(delimiter)
            if found >= 0:
                host_end = min(host_end, found)
        host = authority_pattern[:host_end]
        if not host or "*" in host or not syntax.looks_like_domain(host):
            return None
        return SourceTargetCandidate(host=host, role="request_host")

    @staticmethod
    def _anchored_host_pattern(pattern: str) -> str | None:
        """Return the host portion of a domain-anchored network pattern."""
        if not pattern.startswith("||"):
            return None
        authority_pattern = pattern[2:]
        host_end = len(authority_pattern)
        for delimiter in ("^", "/", "|", "?", ":", "#"):
            found = authority_pattern.find(delimiter)
            if found >= 0:
                host_end = min(host_end, found)
        return authority_pattern[:host_end]

    @staticmethod
    def _no_target_reason(pattern: str) -> str:
        if not pattern.startswith("||"):
            return "network_filter_is_not_host_anchored"
        host_pattern = re.split(r"[\^/|?:]", pattern[2:], maxsplit=1)[0]
        if "*" in host_pattern:
            return "wildcard_request_host_is_not_a_worker_target"
        return "request_host_is_not_a_valid_domain_name"


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
        host = parts[1] if len(parts) >= 2 else line
        return ParsedFormatLine(host)

    def parse_hosts(self, line: str, syntax: DomainSyntax) -> list[str]:
        """Extract all syntactically valid host aliases from a hosts-file line."""
        parts = line.split()
        if len(parts) < 2:
            return []
        aliases = parts[1:]
        if not all(syntax.looks_like_domain(alias) for alias in aliases):
            return []
        return aliases

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
        return ParsedFormatLine(line)


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
        _, value = self._parts(line) or ("", "")
        return ParsedFormatLine(value)

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
            return ParsedFormatLine(line[1:])
        return ParsedFormatLine(line)


class DomainListParser:
    """Parses, cleans, and extracts hosts from various list formats.

    Each input source must match one predefined format before any host extraction
    runs. Supported explicit formats are plain domain lists, classic hosts
    files, AdBlock network filters, and dnsmasq server rules. Auto-detected-only
    formats include supported Surge RULE-SET domain declarations and Surge
    DOMAIN-SET domain lists. Extracted hosts are normalized, validated,
    converted to PSL registrable domains with publicsuffix2, and deduplicated.
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

    def _strip_comments_and_cosmetics(self, source_line: str) -> str:
        """Remove blank and comment lines while retaining cosmetic filters.

        Args:
            source_line: A source list entry.

        Returns:
            The stripped line, or empty for a blank/comment line.
        """
        line = source_line.strip()
        if not line or line.startswith("!"):
            return ""
        if line.startswith("#") and not any(
            marker in line
            for marker in ("##", "#@#", "#@?#", "#?#", "#$#", "#%#")
        ):
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
            for source_line in lines
            if (line := self._strip_comments_and_cosmetics(source_line))
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
        plain_handler = self._handlers_by_format[InputFileFormat.PLAIN]
        if plain_handler.matches_line(line, self.syntax):
            return {InputFileFormat.PLAIN}

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

    def _host_token(
        self,
        source_line: str,
        input_format: InputFileFormat,
    ) -> str:
        """Return the extracted host token for one source line."""
        line = self._strip_comments_and_cosmetics(source_line)
        if not line:
            return ""
        handler = self._handlers_by_format.get(input_format)
        if handler is None:
            return ""
        if not handler.matches_line(line, self.syntax):
            return ""
        parsed = handler.parse_line(line, self.syntax)
        return parsed.host

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
    ) -> Iterator[DomainEntry]:
        """Process lines into unique normalized host entries.

        Args:
            lines: Iterable of source input lines.
            stats: Optional mutable mapping populated with detected-format counters.

        Yields:
            Unique normalized hosts with their registrable domain.
        """
        parsed_source_file = self.parse_source_file(
            lines,
            source_name=source_name,
            forced_format=forced_format,
        )
        file_format = parsed_source_file.file_format
        if stats is not None:
            stats[f"format_{file_format.value}"] = (
                stats.get(f"format_{file_format.value}", 0) + 1
            )
        yield from self.entries_from_parsed_source_file(parsed_source_file)

    def parse_source_file(
        self,
        lines: Iterable[str],
        *,
        source_name: str = "<input>",
        forced_format: InputFileFormat | str | None = None,
    ) -> ParsedSourceFile:
        """Parse every physical line once under the detected or forced format."""
        source_lines = list(lines)
        file_format = self._resolve_file_format(source_lines, forced_format)
        if file_format in {InputFileFormat.UNKNOWN, InputFileFormat.MIXED}:
            log.warning(
                "Skipped input source %s: detected %s file format",
                source_name,
                file_format.value,
            )
            parsed_lines = tuple(
                ParsedSourceLine(line_number, raw_line, None)
                for line_number, raw_line in enumerate(source_lines, start=1)
            )
            return ParsedSourceFile(file_format=file_format, lines=parsed_lines)

        log.info("Detected %s input format for %s", file_format.value, source_name)
        parsed_lines = tuple(
            ParsedSourceLine(
                line_number=line_number,
                raw_line=raw_line,
                parsed_item=self.parse_source_item(raw_line, file_format=file_format),
            )
            for line_number, raw_line in enumerate(source_lines, start=1)
        )
        return ParsedSourceFile(file_format=file_format, lines=parsed_lines)

    def entries_from_parsed_source_file(
        self, parsed_source_file: ParsedSourceFile
    ) -> Iterator[DomainEntry]:
        """Yield unique worker entries from an existing per-line parse."""
        if parsed_source_file.file_format in {
            InputFileFormat.UNKNOWN,
            InputFileFormat.MIXED,
        }:
            return
        seen_hosts: Set[str] = set()
        for source_line in parsed_source_file.lines:
            parsed = source_line.parsed_item
            if parsed is None or parsed.error_reason is not None:
                continue
            for target in parsed.targets:
                if target.error_reason is not None or target.host in seen_hosts:
                    continue
                seen_hosts.add(target.host)
                yield DomainEntry(
                    host=target.host,
                    registrable_domain=target.registrable_domain,
                )

    def prepare_source_lines(
        self,
        lines: Iterable[str],
        *,
        source_name: str = "<input>",
        forced_format: InputFileFormat | str | None = None,
    ) -> tuple[InputFileFormat, list[PreparedSourceLine]]:
        """Clean a source and retain valid lines with parsed domain targets."""
        source_lines = list(lines)
        file_format = self._resolve_file_format(source_lines, forced_format)
        if file_format in {InputFileFormat.UNKNOWN, InputFileFormat.MIXED}:
            log.warning(
                "Skipped input source %s: detected %s file format",
                source_name,
                file_format.value,
            )
            return file_format, []

        handler = self._handlers_by_format.get(file_format)
        if handler is None:
            return file_format, []

        prepared_lines: list[PreparedSourceLine] = []
        for source_line in source_lines:
            parsed = self.parse_source_item(source_line, file_format=file_format)
            if parsed is None or parsed.error_reason is not None:
                continue
            entries = [
                DomainEntry(
                    host=target.host,
                    registrable_domain=target.registrable_domain,
                )
                for target in parsed.targets
                if target.error_reason is None
            ]
            if not parsed.is_metadata and not parsed.no_target_reason and not entries:
                continue
            prepared_lines.append(
                PreparedSourceLine(
                    content=source_line,
                    entries=tuple(entries),
                )
            )
        return file_format, prepared_lines

    def parse_source_item(
        self,
        source_line: str,
        *,
        file_format: InputFileFormat,
    ) -> ParsedSourceItem | None:
        """Parse one source item, keeping syntax, targets, and PSL validity apart.

        Comments and blank lines return ``None``. A structurally invalid line or
        a target that fails strict PSL matching carries an explicit error and is
        not converted into a valid no-target item.
        """
        cleaned = self._strip_comments_and_cosmetics(source_line)
        if not cleaned:
            return None
        handler = self._handlers_by_format.get(file_format)
        if handler is None:
            return ParsedSourceItem(
                item_kind="unsupported_source_format",
                error_reason=f"unsupported_source_format:{file_format.value}",
            )

        syntax_result: SourceItemSyntax | None = None
        if isinstance(handler, AdblockFormatHandler):
            syntax_result = handler.parse_syntax(cleaned, self.syntax)
            if syntax_result is None:
                return None
            if syntax_result.error_reason is not None:
                return ParsedSourceItem(
                    item_kind=syntax_result.item_kind,
                    error_reason=syntax_result.error_reason,
                )
            candidates = syntax_result.targets
        else:
            if not handler.matches_line(cleaned, self.syntax):
                return ParsedSourceItem(
                    item_kind="invalid_source_item",
                    error_reason="line_not_valid_for_source_format",
                )
            candidates = tuple(
                SourceTargetCandidate(host=host, role="domain_target")
                for host in handler.parse_hosts(cleaned, self.syntax)
            )

        if not candidates:
            if syntax_result is None:
                return ParsedSourceItem(
                    item_kind=file_format.value,
                    error_reason="source_item_has_no_extractable_target",
                )
            return ParsedSourceItem(
                item_kind=syntax_result.item_kind,
                no_target_reason=syntax_result.no_target_reason,
                is_metadata=syntax_result.is_metadata,
            )

        parsed_targets: list[ParsedSourceTarget] = []
        for candidate in candidates:
            normalized = self.normalize(candidate.host)
            if not normalized or not self.is_valid_syntax(normalized):
                parsed_targets.append(
                    ParsedSourceTarget(
                        host=normalized or candidate.host,
                        registrable_domain=None,
                        role=candidate.role,
                        error_reason="invalid_target_domain_syntax",
                    )
                )
                continue
            public_suffix_parts = self._public_suffix_parts(normalized)
            if public_suffix_parts is None:
                parsed_targets.append(
                    ParsedSourceTarget(
                        host=normalized,
                        registrable_domain=None,
                        role=candidate.role,
                        error_reason="no_strict_public_suffix_match",
                    )
                )
                continue
            _public_suffix, registrable_domain = public_suffix_parts
            parsed_targets.append(
                ParsedSourceTarget(
                    host=normalized,
                    registrable_domain=registrable_domain,
                    role=candidate.role,
                )
            )
        return ParsedSourceItem(
            item_kind=(syntax_result.item_kind if syntax_result else file_format.value),
            targets=tuple(parsed_targets),
        )

    def parse_source_line_entries(
        self,
        source_line: str,
        *,
        file_format: InputFileFormat,
    ) -> list[DomainEntry]:
        """Return normalized domain targets carried by one valid source line."""
        parsed = self.parse_source_item(source_line, file_format=file_format)
        if parsed is None:
            return []
        return [
            DomainEntry(
                host=target.host,
                registrable_domain=target.registrable_domain,
            )
            for target in parsed.targets
            if target.error_reason is None
        ]

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

    def _parse_entry(
        self,
        source_line: str,
        file_format: InputFileFormat,
    ) -> DomainEntry | None:
        """Return one parsed entry for a source line."""
        host = self._host_token(source_line, file_format)
        normalized = self.normalize(host)
        if not normalized:
            log.debug("Skipped (empty after normalization): %r", source_line.strip())
            return None
        if not self.is_valid_syntax(normalized):
            log.debug("Skipped (invalid syntax): %r", normalized)
            return None

        return self._entry_for_normalized_host(normalized)

    def _entry_for_normalized_host(self, normalized: str) -> DomainEntry | None:
        """Create a domain entry after syntax and public-suffix validation."""
        public_suffix_parts = self._public_suffix_parts(normalized)
        if public_suffix_parts is None:
            return None
        public_suffix, root = public_suffix_parts
        return DomainEntry(
            host=normalized,
            registrable_domain=None if normalized == public_suffix else root,
        )

    def _public_suffix_parts(self, normalized: str) -> tuple[str, str | None] | None:
        """Return strict PSL suffix and nullable registrable domain."""
        try:
            public_suffix_list = _full_public_suffix_list()
            public_suffix = public_suffix_list.get_tld(normalized, strict=True)
            root = public_suffix_list.get_sld(normalized, strict=True)
        except (ValueError, TypeError) as exc:
            log.debug("Skipped (publicsuffix2 error for %r): %s", normalized, exc)
            return None

        if public_suffix is None:
            log.debug("Skipped (no strict public suffix match): %s", normalized)
            return None
        suffix = str(public_suffix)
        registrable_domain = None if normalized == suffix else root
        return suffix, None if registrable_domain is None else str(registrable_domain)
