"""WHOIS fallback lookup and stdout classification helpers."""

from __future__ import annotations

import dataclasses
import re
import subprocess
from collections.abc import Callable, Sequence
from typing import Literal

WHOIS_STATUS_REGISTERED = "registered"
WHOIS_STATUS_UNREGISTERED = "unregistered"
WHOIS_STATUS_UNKNOWN = "unknown"
WHOIS_STATUS_TIMEOUT = "timeout"
WHOIS_STATUS_ERROR = "error"
WHOIS_STATUS_MISSING_COMMAND = "missing_command"
WHOIS_COMMAND_MODE_IANA_REFERRAL = "iana_referral"

WhoisFallbackStatus = Literal[
    "registered",
    "unregistered",
    "unknown",
    "timeout",
    "error",
    "missing_command",
]

WhoisRunner = Callable[..., subprocess.CompletedProcess[str]]


@dataclasses.dataclass(frozen=True)
class WhoisFallbackResult:
    """Registration verdict from a WHOIS fallback attempt."""

    domain: str
    status: WhoisFallbackStatus
    reason: str
    matched_pattern: str = ""
    exit_code: int | None = None
    command_mode: str = WHOIS_COMMAND_MODE_IANA_REFERRAL
    from_cache: bool = False

    def is_registered(self) -> bool:
        """Return True when WHOIS evidence says the domain exists."""
        return self.status == WHOIS_STATUS_REGISTERED

    def is_unregistered(self) -> bool:
        """Return True when WHOIS evidence says the domain does not exist."""
        return self.status == WHOIS_STATUS_UNREGISTERED


@dataclasses.dataclass(frozen=True)
class _WhoisPattern:
    """One named WHOIS stdout evidence pattern."""

    name: str
    search: Callable[[str], object | None]


def _compile_unregistered_patterns() -> tuple[_WhoisPattern, ...]:
    """Return known WHOIS stdout patterns for unregistered domains."""
    flags = re.IGNORECASE | re.MULTILINE
    return (
        _WhoisPattern(
            "no_match_for_domain",
            re.compile(r"\bno match for domain\b", flags).search,
        ),
        _WhoisPattern("no_match_for", re.compile(r"\bno match for\b", flags).search),
        _WhoisPattern(
            "queried_object_does_not_exist",
            re.compile(r"\bthe queried object does not exist\b", flags).search,
        ),
        _WhoisPattern(
            "not_found",
            re.compile(r"^\s*(?:domain\s+)?not found\b", flags).search,
        ),
        _WhoisPattern("no_data_found", re.compile(r"\bno data found\b", flags).search),
        _WhoisPattern(
            "no_entries_found",
            re.compile(r"\bno entries found\b", flags).search,
        ),
        _WhoisPattern(
            "no_match_found",
            re.compile(r"\bno match found\b", flags).search,
        ),
        _WhoisPattern(
            "domain_not_found",
            re.compile(r"\bdomain not found\b", flags).search,
        ),
        _WhoisPattern(
            "no_object_found",
            re.compile(r"\bno object found\b", flags).search,
        ),
        _WhoisPattern(
            "no_such_domain",
            re.compile(r"\bno such domain\b", flags).search,
        ),
    )


UNREGISTERED_PATTERNS = _compile_unregistered_patterns()


def _normalized_domain_for_matching(domain: str) -> str:
    """Return a lower-cased ASCII domain token for exact WHOIS field matching."""
    return domain.strip().rstrip(".").encode("idna").decode("ascii").lower()


def _find_unregistered_pattern(stdout: str) -> str:
    """Return the first matching unregistered-pattern name, or empty string."""
    for pattern in UNREGISTERED_PATTERNS:
        if pattern.search(stdout):
            return pattern.name
    return ""


def _find_registered_pattern(domain: str, stdout: str) -> str:
    """Return a registered-evidence pattern name, or empty string."""
    normalized_domain = _normalized_domain_for_matching(domain)
    escaped_domain = re.escape(normalized_domain)
    domain_name_pattern = re.compile(
        rf"^\s*domain name\s*:\s*{escaped_domain}\.?\s*$",
        re.IGNORECASE | re.MULTILINE,
    )
    if domain_name_pattern.search(stdout):
        return "domain_name_exact"
    return ""


def parse_whois_stdout(
    domain: str,
    stdout: str,
    *,
    exit_code: int | None = None,
) -> WhoisFallbackResult:
    """Classify WHOIS stdout without using stderr as registration evidence."""
    normalized_domain = _normalized_domain_for_matching(domain)
    unregistered_pattern = _find_unregistered_pattern(stdout)
    registered_pattern = _find_registered_pattern(normalized_domain, stdout)
    if unregistered_pattern and registered_pattern:
        return WhoisFallbackResult(
            domain=normalized_domain,
            status=WHOIS_STATUS_UNKNOWN,
            reason="conflicting_whois_evidence",
            matched_pattern=f"{registered_pattern},{unregistered_pattern}",
            exit_code=exit_code,
        )
    if unregistered_pattern:
        return WhoisFallbackResult(
            domain=normalized_domain,
            status=WHOIS_STATUS_UNREGISTERED,
            reason="whois_stdout_unregistered",
            matched_pattern=unregistered_pattern,
            exit_code=exit_code,
        )
    if registered_pattern:
        return WhoisFallbackResult(
            domain=normalized_domain,
            status=WHOIS_STATUS_REGISTERED,
            reason="whois_stdout_registered",
            matched_pattern=registered_pattern,
            exit_code=exit_code,
        )
    reason = (
        "whois_exit_code_without_registration_evidence"
        if exit_code
        else "whois_stdout_unknown"
    )
    return WhoisFallbackResult(
        domain=normalized_domain,
        status=WHOIS_STATUS_UNKNOWN,
        reason=reason,
        exit_code=exit_code,
    )


def whois_result_from_cache(
    domain: str, status: WhoisFallbackStatus
) -> WhoisFallbackResult:
    """Build a WHOIS fallback result reconstructed from the root cache."""
    normalized_domain = _normalized_domain_for_matching(domain)
    if status not in {WHOIS_STATUS_REGISTERED, WHOIS_STATUS_UNREGISTERED}:
        raise ValueError(f"unsupported cached WHOIS status: {status!r}")
    return WhoisFallbackResult(
        domain=normalized_domain,
        status=status,
        reason="root_registration_cache",
        command_mode=WHOIS_COMMAND_MODE_IANA_REFERRAL,
        from_cache=True,
    )


def run_whois_lookup(
    domain: str,
    *,
    command: str,
    timeout: float,
    runner: WhoisRunner = subprocess.run,
) -> WhoisFallbackResult:
    """Run the Ubuntu whois client in IANA-referral mode and parse stdout."""
    normalized_domain = _normalized_domain_for_matching(domain)
    args: Sequence[str] = (command, "-I", normalized_domain)
    try:
        completed = runner(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return WhoisFallbackResult(
            domain=normalized_domain,
            status=WHOIS_STATUS_MISSING_COMMAND,
            reason="whois_command_not_found",
        )
    except subprocess.TimeoutExpired:
        return WhoisFallbackResult(
            domain=normalized_domain,
            status=WHOIS_STATUS_TIMEOUT,
            reason="whois_command_timeout",
        )
    except OSError as exc:
        return WhoisFallbackResult(
            domain=normalized_domain,
            status=WHOIS_STATUS_ERROR,
            reason=f"whois_command_error:{exc.__class__.__name__}",
        )

    return parse_whois_stdout(
        normalized_domain,
        completed.stdout,
        exit_code=completed.returncode,
    )
