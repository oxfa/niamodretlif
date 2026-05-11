"""Delegation DNS lookup ownership."""

from __future__ import annotations

import dataclasses
import logging
import socket
from collections.abc import Callable
from typing import Any

import dns.exception
import dns.message
import dns.rcode
import dns.resolver
import dns.rdatatype

from domain_pipeline.worker.delegation.query_coordinator import (
    DelegationQueryCoordinator,
)
from domain_pipeline.worker.dns_query.lookup import (
    DNSCheckerBaseRequest,
    DNSQueryService,
    RetryableDNSLookupError,
    dns_stage_query_rate_limit,
    dns_stage_resolver_profile,
    dns_stage_retry_backoff_base_seconds,
    dns_stage_timeout,
)

logger = logging.getLogger(__name__)


def delegation_stage_dns_profile(dns_config: dict[str, Any]) -> dict[str, Any]:
    """Return the normalized delegation stage profile without ECS."""
    delegation_config = dict(dns_config.get("delegation") or {})
    resolvers, weights = dns_stage_resolver_profile(dns_config, delegation_config)
    return {
        "resolvers": resolvers,
        "resolver_weights": weights,
        "timeout": dns_stage_timeout(dns_config, delegation_config),
        "retry_backoff_base_seconds": dns_stage_retry_backoff_base_seconds(
            dns_config, delegation_config
        ),
        "query_rate_limit": dns_stage_query_rate_limit(dns_config, delegation_config),
    }


@dataclasses.dataclass(frozen=True)
class DelegationDnsEvidence:
    """DNS evidence from the primary delegation NS lookup."""

    ns_records_exist: bool = False
    ns_nodata: bool = False
    ns_nxdomain: bool = False
    ns_retry_exhausted: bool = False
    ns_lookup_error: bool = False


@dataclasses.dataclass(frozen=True)
class DelegationSoaEvidence:
    """DNS evidence from same-owner SOA checks after NS needs disambiguation."""

    soa_exists: bool = False
    soa_absent: bool = False
    soa_inconclusive: bool = False
    soa_source: str = ""


@dataclasses.dataclass(frozen=True)
class DelegationResult:
    """Delegation result with primary NS evidence and SOA fallback evidence."""

    domain: str
    dns: DelegationDnsEvidence = dataclasses.field(
        default_factory=DelegationDnsEvidence
    )
    soa: DelegationSoaEvidence = dataclasses.field(
        default_factory=DelegationSoaEvidence
    )
    no_nameservers: bool = False
    nameservers: list[str] = dataclasses.field(default_factory=list)
    from_cache: bool = False

    @property
    def ns_records_exist(self) -> bool:
        """Return whether NS records exist for the registrable domain."""
        return self.dns.ns_records_exist

    @property
    def ns_nodata(self) -> bool:
        """Return whether the NS query produced NODATA."""
        return self.dns.ns_nodata

    @property
    def ns_nxdomain(self) -> bool:
        """Return whether the NS query produced NXDOMAIN."""
        return self.dns.ns_nxdomain

    @property
    def ns_retry_exhausted(self) -> bool:
        """Return whether the NS lookup exhausted its retry budget."""
        return self.dns.ns_retry_exhausted

    @property
    def ns_lookup_error(self) -> bool:
        """Return whether the NS lookup failed outside retry-exhausted handling."""
        return self.dns.ns_lookup_error

    @property
    def soa_exists(self) -> bool:
        """Return whether SOA fallback found a same-owner SOA."""
        return self.soa.soa_exists

    @property
    def soa_absent(self) -> bool:
        """Return whether same-owner SOA was proven absent."""
        return self.soa.soa_absent

    @property
    def soa_inconclusive(self) -> bool:
        """Return whether SOA lookup did not prove SOA exists or absent."""
        return self.soa.soa_inconclusive

    @property
    def soa_source(self) -> str:
        """Return the SOA evidence source label."""
        return self.soa.soa_source

    @property
    def status(self) -> str:
        """Return the explicit delegation status used in rows and logs."""
        return _delegation_status(self)

    @property
    def actionable(self) -> bool:
        """Return whether the domain is delegated and currently actionable."""
        return self.status in {
            "ns_records_exist",
            "ns_nodata",
            "ns_nxdomain_soa_exists",
            "ns_retry_exhausted_soa_exists",
        }


@dataclasses.dataclass(frozen=True)
class DelegationCheckerRequest:
    """Construction request for a delegation checker."""

    base: DNSCheckerBaseRequest = dataclasses.field(
        default_factory=DNSCheckerBaseRequest
    )
    delegation_dns: dict[str, Any] | None = None
    delegation_retry_attempts: int | None = None


_DelegationStatusPredicate = Callable[[DelegationResult], bool]
_DELEGATION_STATUS_RULES: tuple[tuple[str, _DelegationStatusPredicate], ...] = (
    (
        "ns_records_exist",
        lambda result: result.dns.ns_records_exist and bool(result.nameservers),
    ),
    ("ns_nodata", lambda result: result.dns.ns_nodata),
    (
        "ns_nxdomain_soa_exists",
        lambda result: result.dns.ns_nxdomain and result.soa.soa_exists,
    ),
    (
        "ns_nxdomain_soa_absent",
        lambda result: result.dns.ns_nxdomain and result.soa.soa_absent,
    ),
    (
        "ns_nxdomain_soa_inconclusive",
        lambda result: result.dns.ns_nxdomain,
    ),
    (
        "ns_retry_exhausted_soa_exists",
        lambda result: result.dns.ns_retry_exhausted and result.soa.soa_exists,
    ),
    (
        "ns_retry_exhausted_soa_absent",
        lambda result: result.dns.ns_retry_exhausted and result.soa.soa_absent,
    ),
    (
        "ns_retry_exhausted_soa_inconclusive",
        lambda result: result.dns.ns_retry_exhausted,
    ),
    ("ns_empty_answer", lambda result: result.no_nameservers),
    ("ns_lookup_error", lambda result: result.dns.ns_lookup_error),
)


def _delegation_status(result: DelegationResult) -> str:
    """Return the first matching explicit delegation status."""
    for status, predicate in _DELEGATION_STATUS_RULES:
        if predicate(result):
            return status
    return "unknown"


class DelegationChecker(DNSQueryService):
    """Checker for registrable-domain delegation lookups."""

    def __init__(
        self,
        request: DelegationCheckerRequest,
        *,
        coordinator_state: Any | None = None,
    ) -> None:
        super().__init__(coordinator_state=coordinator_state)
        dns_config = self.stage_dns_base_config(
            default_resolvers=request.base.default_resolvers,
            timeout=request.base.timeout,
            retry_backoff_base_seconds=request.base.retry_backoff_base_seconds,
            query_rate_limit=request.base.query_rate_limit,
        )
        dns_config["delegation"] = dict(request.delegation_dns or {})
        self.delegation_stage_dns_profile = delegation_stage_dns_profile(dns_config)
        self.delegation_resolver_endpoints = list(
            self.delegation_stage_dns_profile["resolvers"]
        )
        self.delegation_retry_attempts = max(
            1,
            int(
                request.delegation_retry_attempts
                if request.delegation_retry_attempts is not None
                else request.base.retry_attempts
            ),
        )
        self.delegation_query_coordinator = self.build_query_coordinator(
            coordinator_cls=DelegationQueryCoordinator,
            dns_profile=self.delegation_stage_dns_profile,
        )

    @property
    def resolver(self) -> Any:
        """Return the first delegation endpoint resolver."""
        return self.delegation_query_coordinator.primary_resolver

    @resolver.setter
    def resolver(self, resolver: Any) -> None:
        """Install one resolver for delegation DNS queries."""
        self.delegation_query_coordinator = self.single_resolver_coordinator(
            coordinator_cls=DelegationQueryCoordinator,
            resolver_key=self.delegation_resolver_key(),
            resolver=resolver,
        )

    def delegation_resolver_key(self) -> str:
        """Return a deterministic cache key for the delegation resolver profile."""
        return self.delegation_query_coordinator.resolver_key()

    def _resolve_delegation_record(
        self, name: str, record_type: str, retry_attempts: int
    ) -> Any:
        """Resolve one delegation DNS record with the delegation profile.

        NS and fallback SOA both describe registrable-domain delegation state,
        so they intentionally share resolver pools, retry policy, and cache key.
        """
        return self.resolve_with_coordinator(
            self.delegation_query_coordinator,
            name,
            record_type,
            retry_attempts,
        )

    @staticmethod
    def _normalize_dns_name(name: Any) -> str:
        """Return a lower-case DNS owner name without the root-dot suffix."""
        return str(name).rstrip(".").lower()

    def _response_matches_question(
        self, response: dns.message.Message, domain: str, record_type: str
    ) -> bool:
        """Return whether a response belongs to the expected DNS question."""
        if response.rcode() not in {dns.rcode.NOERROR, dns.rcode.NXDOMAIN}:
            return False
        if not response.question:
            return False
        question = response.question[0]
        return (
            self._normalize_dns_name(question.name) == self._normalize_dns_name(domain)
            and dns.rdatatype.to_text(question.rdtype).upper() == record_type.upper()
        )

    def _response_has_same_owner_authority_soa(
        self, response: dns.message.Message | None, domain: str
    ) -> bool:
        """Return whether an NS negative response proves same-owner SOA."""
        if response is None or not self._response_matches_question(
            response, domain, "NS"
        ):
            return False
        normalized_domain = self._normalize_dns_name(domain)
        # Negative answers can carry zone SOA in authority. Only same-owner SOA
        # proves this registrable domain has actionable delegation evidence.
        return any(
            rrset.rdtype == dns.rdatatype.SOA
            and self._normalize_dns_name(rrset.name) == normalized_domain
            for rrset in response.authority
        )

    def _noanswer_response(
        self, exc: dns.resolver.NoAnswer
    ) -> dns.message.Message | None:
        """Return the response carried by dnspython NoAnswer when available."""
        try:
            response = exc.response()
        except (KeyError, AttributeError):
            return None
        return response if isinstance(response, dns.message.Message) else None

    def _ns_nxdomain_response(
        self, exc: dns.resolver.NXDOMAIN, domain: str
    ) -> dns.message.Message | None:
        """Return the matching NXDOMAIN response when dnspython exposes one."""
        try:
            responses = exc.responses()
        except (KeyError, AttributeError):
            return None
        for response in responses.values():
            if isinstance(
                response, dns.message.Message
            ) and self._response_matches_question(response, domain, "NS"):
                return response
        return None

    def _soa_answer_exists_for_domain(self, answer: Any, domain: str) -> bool:
        """Return whether an explicit SOA answer proves SOA at the queried domain."""
        rrset = getattr(answer, "rrset", None)
        if rrset is None and all(
            hasattr(answer, attribute) for attribute in ("rdtype", "name")
        ):
            rrset = answer
        if rrset is not None:
            return rrset.rdtype == dns.rdatatype.SOA and self._normalize_dns_name(
                rrset.name
            ) == self._normalize_dns_name(domain)
        # A direct SOA fallback only proves actionability when the response
        # exposes an SOA RRset owned by the queried registrable domain. Do not
        # infer SOA existence from a generic iterable/record payload; that would
        # collapse malformed or wrong-owner answers into an actionable result.
        return False

    def _delegation_soa_query_fallback(
        self,
        *,
        domain: str,
        dns_evidence: DelegationDnsEvidence,
        reason: str,
    ) -> DelegationResult:
        """Resolve direct SOA fallback after NS authority evidence was inconclusive."""
        logger.debug(
            "DNS delegation %s starting SOA fallback domain=%s soa_source=%s",
            reason,
            domain,
            "soa_query",
        )
        try:
            answer = self._resolve_delegation_record(
                domain, "SOA", self.delegation_retry_attempts
            )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            result = DelegationResult(
                domain=domain,
                dns=dns_evidence,
                soa=DelegationSoaEvidence(soa_absent=True),
            )
        except RetryableDNSLookupError:
            result = DelegationResult(
                domain=domain,
                dns=dns_evidence,
                soa=DelegationSoaEvidence(soa_inconclusive=True),
            )
        except (dns.exception.DNSException, socket.gaierror):
            result = DelegationResult(
                domain=domain,
                dns=dns_evidence,
                soa=DelegationSoaEvidence(soa_inconclusive=True),
            )
        else:
            result = (
                DelegationResult(
                    domain=domain,
                    dns=dns_evidence,
                    soa=DelegationSoaEvidence(
                        soa_exists=True,
                        soa_source="soa_query",
                    ),
                )
                if self._soa_answer_exists_for_domain(answer, domain)
                else DelegationResult(
                    domain=domain,
                    dns=dns_evidence,
                    soa=DelegationSoaEvidence(soa_absent=True),
                )
            )
        logger.debug(
            "DNS delegation %s SOA fallback completed domain=%s status=%s "
            "soa_source=%s",
            reason,
            domain,
            result.status,
            result.soa_source or "soa_query",
        )
        return result

    def _delegation_ns_nodata_result(
        self, domain: str, exc: dns.resolver.NoAnswer
    ) -> DelegationResult:
        """Return actionable NS NODATA without a host or SOA probe."""
        del exc
        return DelegationResult(
            domain=domain,
            dns=DelegationDnsEvidence(ns_nodata=True),
        )

    def _delegation_ns_nxdomain_with_soa_fallback(
        self, domain: str, exc: dns.resolver.NXDOMAIN
    ) -> DelegationResult:
        """Resolve same-owner SOA before treating NS NXDOMAIN as unactionable."""
        response = self._ns_nxdomain_response(exc, domain)
        if self._response_has_same_owner_authority_soa(response, domain):
            logger.debug(
                "DNS delegation NS NXDOMAIN reused authority SOA "
                "domain=%s soa_source=%s",
                domain,
                "ns_authority",
            )
            return DelegationResult(
                domain=domain,
                dns=DelegationDnsEvidence(ns_nxdomain=True),
                soa=DelegationSoaEvidence(
                    soa_exists=True,
                    soa_source="ns_authority",
                ),
            )
        return self._delegation_soa_query_fallback(
            domain=domain,
            dns_evidence=DelegationDnsEvidence(ns_nxdomain=True),
            reason="NS NXDOMAIN",
        )

    def _delegation_ns_retry_exhausted_with_soa_fallback(
        self, domain: str
    ) -> DelegationResult:
        """Resolve SOA after NS retry exhaustion before returning a terminal status."""
        return self._delegation_soa_query_fallback(
            domain=domain,
            dns_evidence=DelegationDnsEvidence(ns_retry_exhausted=True),
            reason="NS retry exhausted",
        )

    def delegation_lookup(self, domain: str) -> DelegationResult:
        """Run delegation check: NS first, with SOA fallback for inconclusive NS."""
        try:
            answer = self._resolve_delegation_record(
                domain, "NS", self.delegation_retry_attempts
            )
        except dns.resolver.NXDOMAIN as exc:
            result = self._delegation_ns_nxdomain_with_soa_fallback(domain, exc)
        except dns.resolver.NoAnswer as exc:
            result = self._delegation_ns_nodata_result(domain, exc)
        except RetryableDNSLookupError:
            result = self._delegation_ns_retry_exhausted_with_soa_fallback(domain)
        except (dns.exception.DNSException, socket.gaierror):
            result = DelegationResult(
                domain=domain,
                dns=DelegationDnsEvidence(ns_lookup_error=True),
            )
        else:
            result = self._delegation_result_from_answer(domain, answer)
        return result

    @staticmethod
    def _delegation_result_from_answer(domain: str, answer: Any) -> DelegationResult:
        """Return delegation result evidence from a successful NS answer."""
        nameservers = sorted({str(rr.target).rstrip(".").lower() for rr in answer})
        if not nameservers:
            return DelegationResult(domain=domain, no_nameservers=True)
        return DelegationResult(
            domain=domain,
            dns=DelegationDnsEvidence(ns_records_exist=True),
            nameservers=nameservers,
        )
