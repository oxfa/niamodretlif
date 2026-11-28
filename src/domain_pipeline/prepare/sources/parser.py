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
* **AdBlock / uBlock filters** - network rules can carry a literal anchored
  request host. Supported rules without a literal host are retained for replay.
* **dnsmasq server rules** - lines like ``server=/example.com/8.8.8.8``.

Auto-detected-only formats:

* **Surge RULE-SET domain declarations** - concrete ``DOMAIN`` and
  ``DOMAIN-SUFFIX`` declarations without policy. Unsupported Surge rule types
  are not partially parsed; the source remains unrecognized.
* **Surge DOMAIN-SET lists** - domain-list entries where leading-dot names map
  to suffix semantics including the apex domain.

Comments follow the selected source grammar. AdBlock cosmetic filters are
retained as valid non-domain source lines.

Processing steps applied to each file:

1. Select one file format, accounting for each grammar's blanks and comments.
2. Extract literal domain targets under the chosen grammar.
3. Lowercase and remove trailing dots.
4. Encode IDN labels to Punycode (IDNA).
5. Validate structural syntax (RFC 1035 label limits).
6. Extract the DNS delegation target (PSL eTLD+1, including PRIVATE rules).
7. Deduplicate normalized entries by host while preserving their registrable
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
class SourceTargetCandidate:
    """One format-extracted domain target before PSL validation."""

    host: str
    role: str


@dataclasses.dataclass(frozen=True)
class SourceItemSyntax:
    """Structural source parse before target validation."""

    item_kind: str
    targets: tuple[SourceTargetCandidate, ...] = ()
    no_target_reason: str | None = None
    is_metadata: bool = False
    error_reason: str | None = None
    is_simple_positive_adblock_rule: bool = False


_UNRECOGNIZED_SOURCE_ITEM = SourceItemSyntax(
    item_kind="invalid_source_item",
    error_reason="line_not_valid_for_source_format",
)


@dataclasses.dataclass(frozen=True)
class ParsedSourceTarget:
    """One normalized target and its strict-PSL outcome."""

    host: str
    registrable_domain: str | None
    role: str
    error_reason: str | None = None


@dataclasses.dataclass(frozen=True)
class ParsedSourceItem:
    """Structural source facts and separately validated targets."""

    item_kind: str
    targets: tuple[ParsedSourceTarget, ...] = ()
    no_target_reason: str | None = None
    is_metadata: bool = False
    error_reason: str | None = None
    is_simple_positive_adblock_rule: bool = False


@dataclasses.dataclass(frozen=True)
class ParsedSourceLine:
    """One physical source line and its already-computed item parse."""

    line_number: int
    raw_line: str
    parsed_item: ParsedSourceItem | None
    is_ignored: bool


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
    """Recognize and extract source records under a single grammar."""

    format: InputFileFormat
    comment_prefixes = ("#", "!")

    def is_ignored(self, value: str) -> bool:
        """Classify blanks and comments in a stripped source line."""
        return not value or value.startswith(self.comment_prefixes)

    def parse_syntax(self, line: str, syntax: DomainSyntax) -> SourceItemSyntax | None:
        """Return ignored, recognized, or invalid syntax for a physical line."""
        value = line.strip()
        if self.is_ignored(value):
            return None
        return self._parse_record(value, syntax) or _UNRECOGNIZED_SOURCE_ITEM

    def _parse_record(self, value: str, syntax: DomainSyntax) -> SourceItemSyntax | None:
        """Return the structural parse when the record belongs to this grammar."""
        raise NotImplementedError


DNSMASQ_SERVER_PATTERN = re.compile(r"server=/([^\s]+)")
DNSMASQ_DIRECTIVE_PATTERN = re.compile(r"(?:server|local|address|rev-server)\s*=")


class DnsmasqFormatHandler(SourceFormatHandler):
    """Parse domain-qualified forwarding directives."""

    format = InputFileFormat.DNSMASQ
    source_record_pattern = DNSMASQ_SERVER_PATTERN

    def _parse_record(self, value: str, syntax: DomainSyntax) -> SourceItemSyntax | None:
        if DNSMASQ_DIRECTIVE_PATTERN.match(value) is None:
            return None
        invalid = SourceItemSyntax(
            item_kind=self.format.value, error_reason="line_not_valid_for_source_format"
        )
        match = self.source_record_pattern.fullmatch(value)
        if match is None:
            return invalid
        *selectors, upstream = match[1].split("/")
        if not selectors or not upstream:
            return invalid
        targets: list[SourceTargetCandidate] = []
        for selector in selectors:
            if selector.startswith("*."):
                host, role = selector[2:], "dnsmasq_wildcard_selector"
            elif selector.startswith("."):
                host, role = selector[1:], "dnsmasq_dot_selector"
            else:
                host, role = selector, "dnsmasq_selector"
            if not syntax.looks_like_domain(host):
                return invalid
            targets.append(SourceTargetCandidate(host=host, role=role))
        return SourceItemSyntax(item_kind=self.format.value, targets=tuple(targets))


class AdblockFormatHandler(SourceFormatHandler):
    """Parse the bounded AdBlock syntax profile."""

    format = InputFileFormat.ADBLOCK
    metadata_header = "[Adblock Plus 2.0]"
    cosmetic_markers = ("#@#", "##")
    unsupported_cosmetic_markers = ("#@?#", "#?#", "#$#", "#%#")
    _modifier_names = {"third-party", "dnstype", "denyallow", "domain"}

    def is_ignored(self, value: str) -> bool:
        """Keep supported and unsupported cosmetic forms visible to parsing."""
        if value.startswith("#"):
            return not value.startswith(
                self.cosmetic_markers + self.unsupported_cosmetic_markers
            )
        return super().is_ignored(value)

    def _parse_record(self, value: str, syntax: DomainSyntax) -> SourceItemSyntax:
        if value == self.metadata_header:
            return SourceItemSyntax(
                item_kind="metadata",
                no_target_reason="format_metadata",
                is_metadata=True,
            )

        is_exception = value.startswith("@@")
        pattern_and_options = value.removeprefix("@@")
        if pattern_and_options.startswith("/"):
            return self._parse_regex(pattern_and_options, is_exception)

        if any(marker in value for marker in self.unsupported_cosmetic_markers):
            return SourceItemSyntax(
                item_kind="unsupported_cosmetic_filter",
                error_reason="unsupported_cosmetic_filter_syntax",
            )
        for marker in self.cosmetic_markers:
            if marker in value:
                return self._parse_cosmetic(value, marker, syntax)

        if not pattern_and_options or any(char.isspace() for char in pattern_and_options):
            return SourceItemSyntax(
                item_kind="invalid_network_filter",
                error_reason="empty_or_whitespace_network_filter",
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
        item_kind = "exception_network_filter" if is_exception else "network_filter"
        anchored_host = self._anchored_host_pattern(pattern)
        if anchored_host is not None:
            if not anchored_host:
                return SourceItemSyntax(
                    item_kind="invalid_network_filter",
                    error_reason="host_anchored_filter_requires_host",
                )
            if "*" in anchored_host:
                return SourceItemSyntax(
                    item_kind=item_kind,
                    no_target_reason="wildcard_request_host_is_not_a_worker_target",
                )
            if not syntax.looks_like_domain(anchored_host):
                return SourceItemSyntax(
                    item_kind="invalid_network_filter",
                    error_reason="invalid_host_anchored_request_host",
                )
            return SourceItemSyntax(
                item_kind=item_kind,
                targets=(SourceTargetCandidate(host=anchored_host, role="request_host"),),
                is_simple_positive_adblock_rule=value == f"||{anchored_host}^",
            )
        return SourceItemSyntax(
            item_kind=item_kind,
            no_target_reason="network_filter_is_not_host_anchored",
        )

    def _parse_regex(self, value: str, is_exception: bool) -> SourceItemSyntax:
        """Parse the regex literal before examining any cosmetic operators."""
        if any(char.isspace() for char in value):
            return SourceItemSyntax(
                item_kind="invalid_network_filter",
                error_reason="empty_or_whitespace_network_filter",
            )
        closing = self._regex_closing_delimiter(value)
        if closing is None:
            return SourceItemSyntax(
                item_kind="invalid_regex_filter",
                error_reason="unterminated_regular_expression_filter",
            )
        trailing = value[closing + 1 :]
        if trailing and (not trailing.startswith("$") or len(trailing) == 1):
            return SourceItemSyntax(
                item_kind="invalid_regex_filter",
                error_reason="unexpected_text_after_regular_expression",
            )
        option_error = self._validate_options(trailing[1:] if trailing else None)
        if option_error:
            return SourceItemSyntax(
                item_kind="invalid_regex_filter", error_reason=option_error
            )
        if not _is_valid_ecmascript_regex(value[1:closing]):
            return SourceItemSyntax(
                item_kind="invalid_regex_filter",
                error_reason="invalid_regular_expression_filter",
            )
        return SourceItemSyntax(
            item_kind="exception_regex_filter" if is_exception else "regex_filter",
            no_target_reason="regular_expression_has_no_literal_request_host",
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


class HostsFormatHandler(SourceFormatHandler):
    """Matcher and extractor for hosts-file address mappings."""

    format = InputFileFormat.HOSTS

    def _parse_record(self, value: str, syntax: DomainSyntax) -> SourceItemSyntax | None:
        parts = value.partition("#")[0].split()
        if len(parts) < 2 or not self._is_valid_hosts_address(parts[0]):
            return None
        aliases = parts[1:]
        if not all(syntax.looks_like_domain(alias) for alias in aliases):
            return SourceItemSyntax(
                item_kind=self.format.value,
                error_reason="source_item_has_no_extractable_target",
            )
        return SourceItemSyntax(
            item_kind=self.format.value,
            targets=tuple(
                SourceTargetCandidate(alias, "domain_target") for alias in aliases
            ),
        )

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

    def _parse_record(self, value: str, syntax: DomainSyntax) -> SourceItemSyntax | None:
        if not syntax.looks_like_domain(value):
            return None
        return SourceItemSyntax(
            self.format.value, (SourceTargetCandidate(value, "domain_target"),)
        )


class SurgeRuleSetFormatHandler(SourceFormatHandler):
    """Matcher and extractor for supported Surge RULE-SET domain rules."""

    format = InputFileFormat.SURGE_RULESET
    comment_prefixes = ("#", "!", "//", ";")
    rule_roles = {"DOMAIN": "exact_host", "DOMAIN-SUFFIX": "domain_suffix"}
    unsupported_rule_types = {
        "AND", "CELLULAR-CARRIER", "CELLULAR-RADIO", "DEST-PORT", "DEVICE-NAME",
        "DOMAIN-KEYWORD", "DOMAIN-SET", "DOMAIN-WILDCARD", "FINAL", "GEOIP",
        "HOSTNAME-TYPE", "IN-PORT", "IP-ASN", "IP-CIDR", "IP-CIDR6", "MAC-ADDRESS",
        "NOT", "OR", "PROCESS-NAME", "PROTOCOL", "RULE-SET", "SCRIPT", "SRC-IP",
        "SRC-PORT", "SUBNET", "URL-REGEX", "USER-AGENT",
    }

    def _parse_record(self, value: str, syntax: DomainSyntax) -> SourceItemSyntax | None:
        rule_type, separator, host = value.partition(",")
        if not separator:
            return None
        rule_type = rule_type.strip().upper()
        role = self.rule_roles.get(rule_type)
        if role is None and rule_type not in self.unsupported_rule_types:
            return None
        host = host.strip()
        if role is None or not syntax.looks_like_domain(host):
            return SourceItemSyntax(
                item_kind=self.format.value,
                error_reason="line_not_valid_for_source_format",
            )
        return SourceItemSyntax(self.format.value, (SourceTargetCandidate(host, role),))


class SurgeDomainSetFormatHandler(SourceFormatHandler):
    """Matcher and extractor for supported Surge DOMAIN-SET entries."""

    format = InputFileFormat.SURGE_DOMAIN_SET
    comment_prefixes = ("#", "!", "//")

    def _parse_record(self, value: str, syntax: DomainSyntax) -> SourceItemSyntax | None:
        host = value.removeprefix(".")
        if not syntax.looks_like_domain(host):
            return None
        role = "exact_host" if host == value else "domain_suffix"
        return SourceItemSyntax(self.format.value, (SourceTargetCandidate(host, role),))


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
        self._directive_handlers = (
            DnsmasqFormatHandler(),
            SurgeRuleSetFormatHandler(),
            HostsFormatHandler(),
        )
        self._adblock_handler = AdblockFormatHandler()
        self._plain_handler = PlainFormatHandler()
        self._domain_set_handler = SurgeDomainSetFormatHandler()
        self._handlers_by_format = {
            handler.format: handler
            for handler in (
                *self._directive_handlers,
                self._adblock_handler,
                self._plain_handler,
                self._domain_set_handler,
            )
        }

    def detect_file_format(self, lines: Iterable[str]) -> InputFileFormat:
        """Classify the entire source under one format's syntax and comments."""
        file_format, _ = self._detect_syntax(list(self._physical_lines(lines)))
        return file_format

    @staticmethod
    def _physical_lines(lines: Iterable[str]) -> Iterator[str]:
        """Yield the decoded lines without their original terminators."""
        for line in lines:
            yield from line.splitlines() or ("",)

    def _detect_syntax(
        self, lines: list[str]
    ) -> tuple[InputFileFormat, list[SourceItemSyntax | None]]:
        """Select a format and carry its syntax results forward."""
        evidence = [self._directive_syntax(line) for line in lines]
        concrete_formats = {result[0] for result in evidence if result is not None}
        if len(concrete_formats) > 1:
            return InputFileFormat.MIXED, []
        if concrete_formats:
            file_format = next(iter(concrete_formats))
            handler = self._handlers_by_format[file_format]
            parsed: list[SourceItemSyntax | None] = []
            for line, result in zip(lines, evidence, strict=True):
                if result is not None:
                    parsed.append(result[1])
                elif handler.is_ignored(line.strip()):
                    parsed.append(None)
                else:
                    parsed.append(_UNRECOGNIZED_SOURCE_ITEM)
            if self._valid_file_syntax(parsed):
                return file_format, parsed
            for line, item in zip(lines, parsed, strict=True):
                if item is not _UNRECOGNIZED_SOURCE_ITEM:
                    continue
                adblock = self._adblock_handler.parse_syntax(line, self.syntax)
                domain_set = self._domain_set_handler.parse_syntax(line, self.syntax)
                if any(
                    other is not None and other.error_reason is None
                    for other in (adblock, domain_set)
                ):
                    return InputFileFormat.MIXED, []
            return InputFileFormat.UNKNOWN, []

        if any(line.lstrip().startswith(".") for line in lines):
            domain_set = [
                self._domain_set_handler.parse_syntax(line, self.syntax) for line in lines
            ]
            if self._valid_file_syntax(domain_set):
                return InputFileFormat.SURGE_DOMAIN_SET, domain_set

        plain = [self._plain_handler.parse_syntax(line, self.syntax) for line in lines]
        has_cosmetic_syntax = any(
            value.startswith("#") and not self._adblock_handler.is_ignored(value)
            for line in lines
            if (value := line.strip())
        )
        if self._valid_file_syntax(plain) and not has_cosmetic_syntax:
            return InputFileFormat.PLAIN, plain

        adblock = [
            self._adblock_handler.parse_syntax(line, self.syntax) for line in lines
        ]
        if self._valid_file_syntax(adblock):
            return InputFileFormat.ADBLOCK, adblock
        return InputFileFormat.UNKNOWN, []

    @staticmethod
    def _valid_file_syntax(items: list[SourceItemSyntax | None]) -> bool:
        """Require at least one record and a valid parse of every content line."""
        return any(item is not None for item in items) and all(
            item is None or item.error_reason is None for item in items
        )

    def _directive_syntax(
        self, line: str
    ) -> tuple[InputFileFormat, SourceItemSyntax] | None:
        """Find records reserved to a directive family even when malformed."""
        for handler in self._directive_handlers:
            item = handler.parse_syntax(line, self.syntax)
            if item is not None and item is not _UNRECOGNIZED_SOURCE_ITEM:
                return handler.format, item
        return None

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
        """Validate the selected grammar's parse of each physical line."""
        source_lines = list(self._physical_lines(lines))
        if forced_format is None or forced_format == "auto":
            file_format, parsed_syntax = self._detect_syntax(source_lines)
        else:
            file_format = InputFileFormat(forced_format)
            parsed_syntax = [
                self._parse_item_syntax(raw_line, file_format)
                for raw_line in source_lines
            ]
        if file_format in {InputFileFormat.UNKNOWN, InputFileFormat.MIXED}:
            log.warning(
                "Skipped input source %s: detected %s file format",
                source_name,
                file_format.value,
            )
            parsed_lines = tuple(
                ParsedSourceLine(
                    line_number=line_number,
                    raw_line=raw_line,
                    parsed_item=None,
                    is_ignored=self._adblock_handler.is_ignored(raw_line.strip()),
                )
                for line_number, raw_line in enumerate(source_lines, start=1)
            )
            return ParsedSourceFile(file_format=file_format, lines=parsed_lines)

        log.info("Detected %s input format for %s", file_format.value, source_name)
        parsed_lines = tuple(
            ParsedSourceLine(
                line_number=line_number,
                raw_line=raw_line,
                parsed_item=self._validate_item_syntax(item),
                is_ignored=item is None,
            )
            for line_number, (raw_line, item) in enumerate(
                zip(source_lines, parsed_syntax, strict=True), start=1
            )
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
        item = self._parse_item_syntax(source_line, file_format)
        return self._validate_item_syntax(item)

    def _parse_item_syntax(
        self, source_line: str, file_format: InputFileFormat
    ) -> SourceItemSyntax | None:
        handler = self._handlers_by_format.get(file_format)
        if handler is not None:
            return handler.parse_syntax(source_line, self.syntax)
        if self._adblock_handler.is_ignored(source_line.strip()):
            return None
        return SourceItemSyntax(
            item_kind="unsupported_source_format",
            error_reason=f"unsupported_source_format:{file_format.value}",
        )

    def _validate_item_syntax(
        self, item: SourceItemSyntax | None
    ) -> ParsedSourceItem | None:
        if item is None:
            return None
        parsed_targets: list[ParsedSourceTarget] = []
        for candidate in item.targets:
            normalized = self.syntax.normalize(candidate.host)
            if not self.syntax.is_valid_syntax(normalized):
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
            item_kind=item.item_kind,
            targets=tuple(parsed_targets),
            no_target_reason=item.no_target_reason,
            is_metadata=item.is_metadata,
            error_reason=item.error_reason,
            is_simple_positive_adblock_rule=item.is_simple_positive_adblock_rule,
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
