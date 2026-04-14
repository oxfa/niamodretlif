"""Domain checking utilities for registrable-domain RDAP decisions and host DNS outcomes.

This module defines a high-level ``DomainChecker`` class for two separate
concerns:

1. checking whether a registrable domain is registered in RDAP, and
2. evaluating exact-host DNS outcomes once that registrable domain is not
   proven RDAP-unregistered.

It also exposes a convenience ``classify`` function that instantiates a
checker with authoritative-RDAP defaults and performs all steps in one call.

**Important:** raw input files should first be processed by
``DomainListParser`` (see ``domain_pipeline.io.parser``), which detects one
predefined format per source, extracts hosts, normalizes them, validates
syntax, derives registrable domains, and deduplicates exact hosts.
``DomainChecker`` expects pre-validated hostnames paired with the
registrable domain that the root-level RDAP check should evaluate.

The design goal of this module is to provide transparent, easily testable
interfaces. Each network interaction (RDAP lookup and DNS resolution) is
isolated into its own method. Unit tests can patch these methods to simulate
different network conditions and verify the root-filter and host-processing
logic.

Dependencies:
    - ``requests`` for HTTP requests to RDAP servers.
    - ``dnspython`` (``dns.resolver``) for DNS lookups.

Usage example:

.. code-block:: python

    from domain_pipeline import classify

    result = classify("example.co.uk")
    print(result)
"""

from __future__ import annotations

import dataclasses
import email.utils
import ipaddress
import json
import logging
import socket
import time
from typing import Dict, List, Optional, Tuple

import dns.exception
import dns.resolver
import requests
from tenacity import RetryCallState
from tenacity import Retrying
from tenacity import retry_if_exception_type
from tenacity import stop_after_attempt
from tenacity import wait_exponential

from domain_pipeline.classifications import (
    CLASSIFICATION_DNS_LOOKUP_SERVFAIL,
    CLASSIFICATION_DNS_LOOKUP_TIMEOUT,
    CLASSIFICATION_DNS_REGISTERED_APEX_NODATA,
    CLASSIFICATION_DNS_REGISTERED_APEX_NXDOMAIN,
    CLASSIFICATION_DNS_REGISTERED_SUBDOMAIN_NODATA,
    CLASSIFICATION_DNS_REGISTERED_SUBDOMAIN_NXDOMAIN,
    CLASSIFICATION_DNS_RESOLVES,
    CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED,
    CLASSIFICATION_RDAP_STATUS_DELETION_OTHER,
    CLASSIFICATION_RDAP_STATUS_HOLD_OTHER,
    RDAP_STATUS_CLASSIFICATION_ORDER,
    RDAP_STATUS_CLASSIFICATIONS,
)
from domain_pipeline.checking.http_requestor import HTTPRequester, HTTPRetryPolicy

logger = logging.getLogger(__name__)


class MissingAuthoritativeBootstrapError(RuntimeError):
    """Raised when the IANA bootstrap has no authoritative RDAP entry."""


class RDAPUnavailableError(RuntimeError):
    """Raised when RDAP cannot produce a semantic 200/404 verdict."""


class CacheableRDAPUnavailableError(RDAPUnavailableError):
    """Raised for RDAP-unavailable states that should be cached."""


class RetryableRDAPError(RuntimeError):
    """Base class for RDAP failures that should be retried."""


class RetryableRDAPHTTPStatusError(RetryableRDAPError):
    """Raised for retryable RDAP HTTP statuses."""

    def __init__(self, response: requests.Response, log_name: str) -> None:
        super().__init__(f"{log_name} returned HTTP {response.status_code}")
        self.response = response
        self.log_name = log_name


class RetryableRDAPTransportError(RetryableRDAPError):
    """Raised for retryable RDAP transport failures."""

    def __init__(self, log_name: str, exc: Exception) -> None:
        super().__init__(f"{log_name} request failed: {exc}")
        self.log_name = log_name
        self.original_exception = exc


class RetryableDNSLookupError(RuntimeError):
    """Raised for transient DNS failures that should be retried."""


@dataclasses.dataclass
class RDAPResult:
    """Result of an RDAP lookup.

    Attributes:
        exists: Whether the registrable domain is registered.  If False
            indicates the domain is not found (unregistered).
        statuses: A list of status strings returned by the RDAP server.  These
            values correspond to EPP status codes such as ``clientHold``,
            ``inactive``, ``redemptionPeriod``, etc.  The list
            is empty if no status information was returned or the domain does
            not exist.
    """

    exists: bool
    statuses: List[str] = dataclasses.field(default_factory=list)
    from_cache: bool = False


@dataclasses.dataclass
class DNSState:
    """Internal DNS outcome flags."""

    exists: bool
    nodata: bool
    nxdomain: bool
    timeout: bool
    servfail: bool


@dataclasses.dataclass
class DNSResult:
    """Result of DNS lookups for a hostname.

    Attributes:
        host: The fully qualified hostname that was queried.
        a_exists: ``True`` if at least one A record was returned, ``False``
            otherwise.
        a_nodata: ``True`` if the DNS query returned NOERROR/NODATA (the
            name exists but no A record).
        a_nxdomain: ``True`` if the DNS query returned NXDOMAIN (name does
            not exist).
        a_timeout: ``True`` if the DNS query timed out or raised a timeout
            exception.
        a_servfail: ``True`` if the DNS query resulted in SERVFAIL or
            misconfigured nameservers.
        canonical_name: If the resolver returned a CNAME, the canonical
            hostname.  Otherwise ``None``.
    """

    # This record intentionally keeps the public DNS flag fields flat so the
    # tests and call sites can inspect them directly.
    # pylint: disable=too-many-instance-attributes

    host: str
    a_exists: bool
    a_nodata: bool
    a_nxdomain: bool
    a_timeout: bool
    a_servfail: bool
    canonical_name: Optional[str] = None
    ipv4_addresses: List[str] = dataclasses.field(default_factory=list)
    ipv6_addresses: List[str] = dataclasses.field(default_factory=list)

    @property
    def resolved_ips(self) -> List[str]:
        """Return resolved IPs in stable IPv4-then-IPv6 order."""
        return [*self.ipv4_addresses, *self.ipv6_addresses]

    @property
    def status(self) -> str:
        """Condense the various flags into a coarse status string.

        Returns one of ``nx`` (NXDOMAIN), ``nodata`` (NOERROR/NODATA),
        ``noerror`` (record exists), ``timeout``, ``servfail``, or ``error``.
        """
        if self.a_timeout:
            return "timeout"
        if self.a_servfail:
            return "servfail"
        if self.a_nxdomain:
            return "nx"
        if self.a_exists:
            return "noerror"
        if self.a_nodata:
            return "nodata"
        return "error"


class DomainChecker:
    """High-level orchestrator for root RDAP and host DNS checks.

    An instance of ``DomainChecker`` encapsulates configuration for RDAP
    queries and DNS lookups. By default it resolves authoritative
    registry RDAP servers directly using the live IANA domain bootstrap
    registry, but it can also use ``https://rdap.org/`` as a
    bootstrap/redirecting RDAP endpoint. DNS lookups leverage the
    system's resolver by default but can be pointed at specific
    nameservers by overriding the ``nameservers`` attribute on the
    created ``dns.resolver.Resolver`` instance.
    """

    RDAP_BASE_URL = "https://rdap.org/domain/"
    IANA_DNS_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
    RDAP_MODE_RDAP_ORG = "rdap_org"
    RDAP_MODE_AUTHORITATIVE = "authoritative"
    RDAP_MODES = {RDAP_MODE_RDAP_ORG, RDAP_MODE_AUTHORITATIVE}
    MAX_RDAP_RETRY_ATTEMPTS = 4
    MAX_DNS_RETRY_ATTEMPTS = 3

    #: EPP status codes which indicate a domain is registered but not
    #: published in the DNS. When any of these are present, the domain is
    #: classified into an explicit RDAP hold-status bucket.
    HOLD_STATUSES = {
        "inactive",  # not delegated
        "clientHold",  # registrar instructs registry to withhold
        "serverHold",  # registry instructs DNS to withhold
    }
    #: EPP status codes indicating the domain is in the process of being
    #: deleted and will soon be available for re-registration.
    DELETION_STATUSES = {
        "redemptionPeriod",
        "pendingDelete",
        "pendingRestore",
        "pendingRenew",
    }

    def __init__(
        self,
        rdap_timeout: float = 10.0,
        dns_timeout: float = 5.0,
        resolver: Optional[dns.resolver.Resolver] = None,
        rdap_mode: str = RDAP_MODE_AUTHORITATIVE,
    ) -> None:
        if rdap_mode not in self.RDAP_MODES:
            raise ValueError(
                f"Unsupported rdap_mode {rdap_mode!r}; expected one of {sorted(self.RDAP_MODES)}"
            )
        self.rdap_timeout = rdap_timeout
        self.dns_timeout = dns_timeout
        self.rdap_mode = rdap_mode
        self.session = requests.Session()
        self._rdap_requestor = HTTPRequester(
            session=self.session,
            timeout=self.rdap_timeout,
            retry_policy=HTTPRetryPolicy(
                max_attempts=self.MAX_RDAP_RETRY_ATTEMPTS,
                retryable_status_codes=frozenset({408, 429, 502, 503, 504}),
                retry_after_status_codes=frozenset({429, 503}),
                status_delay_overrides={408: 0.0},
                backoff_multiplier=0.5,
                backoff_min=0.5,
                backoff_max=30.0,
                retry_after_cap_seconds=120,
            ),
            retryable_exceptions=(RetryableRDAPError,),
            transport_error_factory=self._build_retryable_rdap_transport_error,
            status_error_factory=self._build_retryable_rdap_status_error,
            retry_logger=self._log_rdap_retry,
            sleep=self._sleep_for_retry,
        )
        self._bootstrap_services: Optional[Dict[str, List[str]]] = None
        self._bootstrap_expires_at: Optional[float] = None
        # Use a custom resolver to allow injection of nameservers for testing.
        if resolver is None:
            self.resolver = dns.resolver.Resolver(configure=True)
        else:
            self.resolver = resolver
        # Set timeouts on the resolver.  dnspython uses seconds.
        self.resolver.timeout = dns_timeout
        self.resolver.lifetime = dns_timeout

    @staticmethod
    def _sleep_for_retry(seconds: float) -> None:
        """Sleep for one retry interval using the stage-local time module."""
        time.sleep(seconds)

    # ------------------------------------------------------------------
    # RDAP lookup
    # ------------------------------------------------------------------
    def _log_rdap_retry(
        self,
        exc: BaseException,
        next_sleep: float,
        attempt_number: int,
        max_attempts: int,
    ) -> None:
        """Log one pending RDAP retry attempt."""
        if isinstance(exc, RetryableRDAPHTTPStatusError):
            logger.info(
                "%s returned retryable HTTP %d; retrying in %s seconds (attempt %d/%d)",
                exc.log_name.capitalize(),
                exc.response.status_code,
                next_sleep,
                attempt_number,
                max_attempts,
            )
            return
        if isinstance(exc, RetryableRDAPTransportError):
            logger.info(
                "%s transport failure; retrying in %s seconds (attempt %d/%d): %s",
                exc.log_name.capitalize(),
                next_sleep,
                attempt_number,
                max_attempts,
                exc.original_exception,
            )

    @staticmethod
    def _build_retryable_rdap_transport_error(
        log_name: str, exc: requests.RequestException
    ) -> RetryableRDAPTransportError:
        """Create one retryable RDAP transport error."""
        return RetryableRDAPTransportError(log_name, exc)

    @staticmethod
    def _build_retryable_rdap_status_error(
        log_name: str, response: requests.Response
    ) -> RetryableRDAPHTTPStatusError:
        """Create one retryable RDAP HTTP-status error."""
        return RetryableRDAPHTTPStatusError(response, log_name)

    def _get_with_rdap_retry_policy(self, url: str, log_name: str) -> requests.Response:
        """GET a URL with tenacity-based retries for transient RDAP failures."""
        return self._rdap_requestor.get(url, log_name=log_name)

    def _response_expires_at(self, response: requests.Response) -> Optional[float]:
        """Return a Unix timestamp when cached bootstrap data should expire."""
        cache_control = response.headers.get("cache-control", "")
        for directive in cache_control.split(","):
            directive = directive.strip().lower()
            if directive.startswith("max-age="):
                try:
                    max_age = int(directive.split("=", 1)[1])
                except ValueError:
                    break
                return time.time() + max(0, max_age)

        expires_header = response.headers.get("expires")
        if not expires_header:
            return None
        try:
            expires_at = email.utils.parsedate_to_datetime(expires_header)
        except (TypeError, ValueError, IndexError):
            return None
        return expires_at.timestamp()

    def _normalize_lookup_domain(self, domain: str) -> str:
        """Normalize a library caller's input before RDAP lookup."""
        normalized = domain.strip().rstrip(".").lower()
        try:
            return normalized.encode("idna").decode("ascii")
        except UnicodeError:
            return normalized

    def _load_bootstrap_services(self) -> Dict[str, List[str]]:
        """Fetch and parse the IANA RDAP DNS bootstrap registry."""
        response = self._get_with_rdap_retry_policy(
            self.IANA_DNS_BOOTSTRAP_URL,
            "bootstrap",
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"bootstrap request returned unexpected status {response.status_code}"
            )

        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            raise RuntimeError("bootstrap response is not valid JSON") from exc

        services = payload.get("services")
        if not isinstance(services, list):
            raise RuntimeError(
                "bootstrap response does not contain a valid services array"
            )

        parsed_services: Dict[str, List[str]] = {}
        for service in services:
            if not (
                isinstance(service, list)
                and len(service) == 2
                and isinstance(service[0], list)
                and isinstance(service[1], list)
            ):
                continue
            entries, urls = service
            usable_urls = [
                url for url in urls if isinstance(url, str) and url.endswith("/")
            ]
            if not usable_urls:
                continue
            ordered_urls = sorted(
                usable_urls,
                key=lambda url: (not url.lower().startswith("https://"), url),
            )
            for entry in entries:
                if isinstance(entry, str):
                    parsed_services[entry.lower()] = ordered_urls

        self._bootstrap_expires_at = self._response_expires_at(response)
        return parsed_services

    def _get_bootstrap_services(self) -> Dict[str, List[str]]:
        """Return cached bootstrap data, refreshing it when needed."""
        now = time.time()
        if self._bootstrap_services is None or (
            self._bootstrap_expires_at is not None and now >= self._bootstrap_expires_at
        ):
            self._bootstrap_services = self._load_bootstrap_services()
            logger.info(
                "Loaded IANA RDAP bootstrap data (%d entries)",
                len(self._bootstrap_services),
            )
        return self._bootstrap_services

    def _authoritative_base_url(self, domain: str) -> Optional[str]:
        """Return the authoritative RDAP base URL for a domain per RFC 9224."""
        lookup_domain = self._normalize_lookup_domain(domain)
        labels = lookup_domain.split(".")
        services = self._get_bootstrap_services()
        candidates: List[str] = []
        for start_index in range(len(labels)):
            candidate = ".".join(labels[start_index:])
            candidates.append(candidate)
            urls = services.get(candidate)
            if urls:
                logger.debug(
                    "Authoritative RDAP bootstrap match for %s -> %s via %s",
                    lookup_domain,
                    candidate,
                    urls[0],
                )
                return urls[0]
        logger.debug(
            "No authoritative RDAP bootstrap match for %s; tried candidates=%s",
            lookup_domain,
            ",".join(candidates) or "(none)",
        )
        return None

    def _rdap_query_url(
        self, domain: str, *, authoritative_base_url: str | None = None
    ) -> str:
        """Resolve the final RDAP URL for the configured lookup mode."""
        normalized_domain = self._normalize_lookup_domain(domain)
        if self.rdap_mode == self.RDAP_MODE_RDAP_ORG:
            logger.debug("Using rdap.org redirector for %s", normalized_domain)
            return f"{self.RDAP_BASE_URL}{normalized_domain}"

        base_url = authoritative_base_url or self._authoritative_base_url(
            normalized_domain
        )
        if base_url is None:
            raise MissingAuthoritativeBootstrapError(
                f"no authoritative bootstrap entry for {normalized_domain}"
            )
        logger.debug(
            "Authoritative RDAP base URL for %s -> %s", normalized_domain, base_url
        )
        return f"{base_url}domain/{normalized_domain}"

    def _perform_rdap_request(self, url: str, domain: str) -> RDAPResult:
        """GET a fully resolved RDAP URL and return a semantic verdict."""
        try:
            resp = self._get_with_rdap_retry_policy(url, f"RDAP query for {domain}")
        except RetryableRDAPError as exc:
            # Cache retry-exhausted lookup failures only after we know the final
            # per-root RDAP query URL. Bootstrap/setup failures stay non-cacheable.
            raise CacheableRDAPUnavailableError(str(exc)) from exc
        return self._parse_rdap_response(resp, domain)

    def _parse_rdap_response(
        self, response: requests.Response, domain: str
    ) -> RDAPResult:
        """Convert an RDAP HTTP response into an ``RDAPResult``."""
        if response.status_code == 200:
            try:
                data = response.json()
            except json.JSONDecodeError as exc:
                raise RDAPUnavailableError(
                    f"RDAP response for {domain} is not valid JSON"
                ) from exc
            statuses: List[str] = []
            if isinstance(data, dict):
                # 'status' may appear at top level or inside 'objectClassName' objects
                if "status" in data and isinstance(data["status"], list):
                    statuses = [s for s in data["status"] if isinstance(s, str)]

                # Some RDAP implementations nest objects under 'entities'
                # or 'domainSearchResults'.  Extract statuses if present.
                def _extract_status(obj: object) -> None:
                    nonlocal statuses
                    if isinstance(obj, dict):
                        if "status" in obj and isinstance(obj["status"], list):
                            statuses.extend(
                                [s for s in obj["status"] if isinstance(s, str)]
                            )
                        for value in obj.values():
                            _extract_status(value)
                    elif isinstance(obj, list):
                        for item in obj:
                            _extract_status(item)

                _extract_status(data)
                statuses = sorted(set(statuses))
            return RDAPResult(True, statuses)
        if response.status_code == 404:
            return RDAPResult(False, [])

        raise RDAPUnavailableError(
            f"Unexpected RDAP status {response.status_code} for {domain}"
        )

    def rdap_lookup(
        self,
        domain: str,
        *,
        authoritative_base_url: str | None = None,
    ) -> RDAPResult:
        """Query RDAP for a registrable domain.

        Depending on ``rdap_mode``, this either resolves the authoritative
        registry URL from the IANA bootstrap registry first or uses the
        ``rdap.org`` redirector URL directly.  A successful lookup returns
        registration data as JSON, including the EPP status codes under the
        ``status`` key and possibly within ``domainSearchResults`` or other
        nested objects.  If the domain is not registered, RDAP returns
        HTTP 404.  See ICANN's documentation for details about domain
        status codes.

        Args:
            domain: Registrable domain (eTLD+1) to query.

        Returns:
            An ``RDAPResult`` object indicating registration status and
            associated EPP codes.

        Raises:
            RDAPUnavailableError: The lookup could not produce a semantic
                200/404 verdict.
        """
        try:
            url = self._rdap_query_url(
                domain,
                authoritative_base_url=authoritative_base_url,
            )
        except MissingAuthoritativeBootstrapError as exc:
            logger.info("RDAP lookup setup for %s skipped: %s", domain, exc)
            raise CacheableRDAPUnavailableError(str(exc)) from exc
        except RuntimeError as exc:
            logger.warning("RDAP lookup setup for %s failed: %s", domain, exc)
            raise RDAPUnavailableError(str(exc)) from exc
        return self._perform_rdap_request(url, self._normalize_lookup_domain(domain))

    # ------------------------------------------------------------------
    # DNS lookup
    # ------------------------------------------------------------------
    def _dns_wait_seconds(self, retry_state: RetryCallState) -> float:
        """Return the next DNS retry delay."""
        return float(wait_exponential(multiplier=0.1, min=0.1, max=1.0)(retry_state))

    def _before_sleep_dns_retry(self, retry_state: RetryCallState) -> None:
        """Log one pending DNS retry attempt."""
        exc = retry_state.outcome.exception() if retry_state.outcome else None
        next_sleep = retry_state.next_action.sleep if retry_state.next_action else 0.0
        logger.info(
            "DNS lookup retry in %s seconds (attempt %d/%d): %s",
            next_sleep,
            retry_state.attempt_number,
            self.MAX_DNS_RETRY_ATTEMPTS,
            exc,
        )

    def _resolve_with_retry(self, host: str, record_type: str):
        """Resolve one RRset with retries for transient resolver failures."""

        def perform_resolve():
            try:
                return self.resolver.resolve(
                    host, record_type, raise_on_no_answer=False
                )
            except dns.resolver.LifetimeTimeout as exc:
                raise RetryableDNSLookupError(
                    f"{host} {record_type} timed out"
                ) from exc
            except dns.resolver.NoNameservers as exc:
                raise RetryableDNSLookupError(
                    f"{host} {record_type} has no usable nameservers"
                ) from exc
            except socket.gaierror as exc:
                raise RetryableDNSLookupError(
                    f"{host} {record_type} socket resolution failed"
                ) from exc

        return Retrying(
            retry=retry_if_exception_type(RetryableDNSLookupError),
            stop=stop_after_attempt(self.MAX_DNS_RETRY_ATTEMPTS),
            wait=self._dns_wait_seconds,
            before_sleep=self._before_sleep_dns_retry,
            sleep=time.sleep,
            reraise=True,
        )(perform_resolve)

    def _query_record(
        self, host: str, record_type: str
    ) -> Tuple[bool, bool, bool, bool, bool, Optional[str], List[str]]:
        exists, nodata, nx_domain, timeout, servfail, cname = (
            False,
            False,
            False,
            False,
            False,
            None,
        )
        addresses: List[str] = []
        try:
            answer = self._resolve_with_retry(host, record_type)
            if answer.rrset is None:
                nodata = True
            else:
                for rr in answer:
                    if record_type in ("A", "AAAA"):
                        address = str(rr)
                        try:
                            ipaddress.ip_address(address)
                        except ValueError:
                            continue
                        addresses.append(address)
                        exists = True
                        continue
                    if record_type == "CNAME":
                        exists = True
                        cname = str(rr.target)
                        break
                else:
                    # Only treat A/AAAA lookups as positive when they yielded
                    # at least one IP address. CNAME-only answers should fall
                    # through so the dedicated CNAME lookup can capture the
                    # canonical host for output.
                    if record_type == "CNAME":
                        exists = True
                    else:
                        exists = bool(addresses)
        except dns.resolver.NXDOMAIN:
            nx_domain = True
        except dns.resolver.NoAnswer:
            nodata = True
        except RetryableDNSLookupError:
            if record_type in {"A", "AAAA"}:
                timeout = True
            else:
                servfail = True
        except dns.resolver.NoNameservers:
            servfail = True
        except dns.resolver.LifetimeTimeout:
            timeout = True
        except (dns.exception.DNSException, socket.gaierror):
            servfail = True
        return exists, nodata, nx_domain, timeout, servfail, cname, addresses

    def dns_lookup(self, host: str) -> DNSResult:
        """Perform DNS queries for the given hostname."""
        ret = self._query_record(host, "A")
        exists, nodata, nx_domain, timeout, servfail, cname, ipv4_addresses = ret
        ipv6_addresses: List[str] = []

        if not exists and not nx_domain:
            aaaa_ret = self._query_record(host, "AAAA")
            exists = aaaa_ret[0]
            # Prefer a concrete AAAA NXDOMAIN outcome over an earlier A NODATA
            # so mixed-family results do not collapse into the fallback error path.
            nx_domain = aaaa_ret[2]
            nodata = nodata and not aaaa_ret[2] and aaaa_ret[1]
            timeout = timeout or aaaa_ret[3]
            servfail = servfail or aaaa_ret[4]
            cname = cname or aaaa_ret[5]
            ipv6_addresses = aaaa_ret[6]
        elif not nx_domain:
            aaaa_ret = self._query_record(host, "AAAA")
            timeout = timeout or aaaa_ret[3]
            servfail = servfail or aaaa_ret[4]
            ipv6_addresses = aaaa_ret[6]

        if not exists and not nx_domain and not cname:
            cname_ret = self._query_record(host, "CNAME")
            if cname_ret[0]:
                cname = cname_ret[5]
                exists = True
                nodata = False
                nx_domain = False
            timeout = timeout or cname_ret[3]
            servfail = servfail or cname_ret[4]

        if exists:
            nodata = False
            nx_domain = False
        if nx_domain:
            exists = False
            nodata = False

        a_timeout = (
            timeout and not exists and not nx_domain and not nodata and not servfail
        )
        result = DNSResult(
            host=host,
            a_exists=exists,
            a_nodata=nodata,
            a_nxdomain=nx_domain,
            a_timeout=a_timeout,
            a_servfail=servfail,
            canonical_name=cname,
            ipv4_addresses=ipv4_addresses,
            ipv6_addresses=ipv6_addresses,
        )
        logger.debug("DNS %s -> %s (cname=%s)", host, result.status, cname)
        return result

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------
    def _classify_host_with_rdap(
        self,
        host: str,
        registrable_domain: str,
        rdap_result: RDAPResult | None,
    ) -> Tuple[str, RDAPResult | None, DNSResult]:
        """Classify a host using an optional caller-supplied RDAP verdict."""
        is_registrable_domain_input = host == registrable_domain
        if rdap_result is not None and not rdap_result.exists:
            logger.debug(
                "%s: RDAP not found for %s -> %s",
                host,
                registrable_domain,
                CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED,
            )
            return (
                CLASSIFICATION_RDAP_REGISTRABLE_DOMAIN_UNREGISTERED,
                rdap_result,
                DNSResult(
                    host=host,
                    a_exists=False,
                    a_nodata=False,
                    a_nxdomain=True,
                    a_timeout=False,
                    a_servfail=False,
                    canonical_name=None,
                ),
            )

        dns_result = self.dns_lookup(host)
        if dns_result.status == "timeout":
            return CLASSIFICATION_DNS_LOOKUP_TIMEOUT, rdap_result, dns_result
        if dns_result.status == "servfail":
            return CLASSIFICATION_DNS_LOOKUP_SERVFAIL, rdap_result, dns_result
        if dns_result.a_nxdomain:
            if is_registrable_domain_input:
                return (
                    CLASSIFICATION_DNS_REGISTERED_APEX_NXDOMAIN,
                    rdap_result,
                    dns_result,
                )
            return (
                CLASSIFICATION_DNS_REGISTERED_SUBDOMAIN_NXDOMAIN,
                rdap_result,
                dns_result,
            )
        if dns_result.a_nodata:
            if is_registrable_domain_input:
                return (
                    CLASSIFICATION_DNS_REGISTERED_APEX_NODATA,
                    rdap_result,
                    dns_result,
                )
            return (
                CLASSIFICATION_DNS_REGISTERED_SUBDOMAIN_NODATA,
                rdap_result,
                dns_result,
            )
        if rdap_result is not None:
            statuses_lower = {s.lower() for s in rdap_result.statuses}
            for status_name in RDAP_STATUS_CLASSIFICATION_ORDER:
                if status_name in statuses_lower:
                    return (
                        RDAP_STATUS_CLASSIFICATIONS[status_name],
                        rdap_result,
                        dns_result,
                    )
            if statuses_lower & {s.lower() for s in self.HOLD_STATUSES}:
                return CLASSIFICATION_RDAP_STATUS_HOLD_OTHER, rdap_result, dns_result
            if statuses_lower & {s.lower() for s in self.DELETION_STATUSES}:
                return (
                    CLASSIFICATION_RDAP_STATUS_DELETION_OTHER,
                    rdap_result,
                    dns_result,
                )
        return CLASSIFICATION_DNS_RESOLVES, rdap_result, dns_result

    def classify_host_with_registrable_domain(
        self, host: str, registrable_domain: str
    ) -> Tuple[str, RDAPResult | None, DNSResult]:
        """Classify a host using RDAP on the supplied registrable domain.

        Exact hosts are evaluated by DNS, while RDAP remains scoped to the
        registrable domain. A subdomain whose registered root exists but whose
        exact host returns NXDOMAIN or NODATA is classified into an explicit
        `dns_registered_subdomain_*` bucket.
        """
        try:
            rdap_result = self.rdap_lookup(registrable_domain)
        except RDAPUnavailableError:
            rdap_result = None
        return self.classify_host_with_known_rdap(host, registrable_domain, rdap_result)

    def classify_host_with_known_rdap(
        self,
        host: str,
        registrable_domain: str,
        rdap_result: RDAPResult | None,
    ) -> Tuple[str, RDAPResult | None, DNSResult]:
        """Classify a host using a previously computed RDAP verdict."""
        return self._classify_host_with_rdap(host, registrable_domain, rdap_result)

    def classify_host(self, host: str) -> Tuple[str, RDAPResult | None, DNSResult]:
        """Classify a single registrable-domain hostname.

        The classification algorithm follows these rules:

        1. Perform an RDAP lookup on the registrable domain.  If the domain
           does not exist, classification is
           ``rdap_registrable_domain_unregistered``.
        2. Perform DNS lookups for the host.  If the result indicates
           ``timeout`` or ``servfail``, classification is
           ``dns_lookup_timeout`` or ``dns_lookup_servfail``.
        3. If the DNS lookup indicates NXDOMAIN, classification is
           ``dns_registered_apex_nxdomain`` for the registrable domain itself
           or ``dns_registered_subdomain_nxdomain`` for a subdomain.
           Likewise NODATA becomes the corresponding
           ``dns_registered_*_nodata`` classification.
        4. If RDAP returns a semantic root verdict and statuses include any of the codes in
           ``HOLD_STATUSES`` or ``DELETION_STATUSES``, classification becomes
           the matching explicit RDAP status bucket even if DNS responds,
           because the registry instructs that the domain should not resolve.
        5. If RDAP is unavailable, continue with DNS-based host evaluation.
        6. Otherwise, classification is ``dns_resolves``.

        Args:
            host: Pre-validated registrable domain (eTLD+1) from
                ``DomainListParser``.

        Returns:
            A tuple of (classification, rdap_result, dns_result).
        """
        return self.classify_host_with_registrable_domain(host, host)


def classify(host: str) -> Tuple[str, RDAPResult | None, DNSResult]:
    """Convenience function to classify a single host using default parameters.

    This function instantiates a ``DomainChecker`` with default timeouts and
    the default authoritative RDAP mode, then uses it to classify the given
    host.  See ``DomainChecker.classify_host`` for details of the
    classification algorithm.

    Args:
        host: Pre-validated registrable domain (eTLD+1) from
            ``DomainListParser``.

    Returns:
        A tuple of (classification, rdap_result, dns_result).
    """
    checker = DomainChecker()
    return checker.classify_host(host)
