"""Delegation DNS lookup ownership."""

from __future__ import annotations

import dataclasses
import logging
import socket
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
class DelegationResult:
    """Delegation result with NS state and SOA fallback state.

    ``soa_*`` fields are meaningful only with ``ns_nodata`` and distinguish
    plain NS-NODATA from the SOA-only-domain path.
    """

    domain: str
    ns_exists: bool = False
    ns_nodata: bool = False
    ns_nxdomain: bool = False
    ns_timeout: bool = False
    ns_servfail: bool = False
    soa_exists: bool = False
    soa_nodata: bool = False
    soa_nxdomain: bool = False
    soa_timeout: bool = False
    soa_servfail: bool = False
    soa_source: str = ""
    no_nameservers: bool = False
    nameservers: list[str] = dataclasses.field(default_factory=list)
    from_cache: bool = False

    @property
    def status(self) -> str:
        """Return the compact delegation status used in rows and logs."""
        if self.ns_exists and self.nameservers:
            return "exists"
        if self.ns_nxdomain:
            return "nxdomain"
        if self.ns_nodata and self.soa_exists:
            return "ns_nodata_soa_exists"
        if self.ns_nodata and (self.soa_nodata or self.soa_nxdomain):
            return "ns_nodata_soa_absent"
        if self.ns_nodata and self.soa_timeout:
            return "ns_nodata_soa_timeout"
        if self.ns_nodata and self.soa_servfail:
            return "ns_nodata_soa_servfail"
        if self.ns_nodata:
            return "nodata"
        if self.no_nameservers:
            return "no_nameservers"
        if self.ns_timeout:
            return "timeout"
        if self.ns_servfail:
            return "servfail"
        return "unknown"

    @property
    def actionable(self) -> bool:
        """Return whether the domain is delegated and currently actionable."""
        return self.status in {"exists", "ns_nodata_soa_exists"}


class DelegationChecker(DNSQueryService):
    """Checker for registrable-domain delegation lookups."""

    def __init__(
        self,
        *,
        resolvers: list[Any] | tuple[Any, ...] | None = None,
        nameservers: list[str] | tuple[str, ...] | None = None,
        timeout: float = 5.0,
        query_rate_limit: dict[str, Any] | None = None,
        query_coordinator: Any | None = None,
        delegation_dns: dict[str, Any] | None = None,
        retry_attempts: int = 3,
        delegation_retry_attempts: int | None = None,
    ) -> None:
        default_resolvers = (
            list(resolvers)
            if resolvers is not None
            else list(nameservers or self.DEFAULT_NAMESERVERS)
        )
        dns_config = {
            "default_resolvers": default_resolvers,
            "timeout": float(timeout),
            "query_rate_limit": query_rate_limit or {},
            "delegation": dict(delegation_dns or {}),
        }
        self.delegation_stage_dns_profile = delegation_stage_dns_profile(dns_config)
        self.delegation_resolver_endpoints = list(
            self.delegation_stage_dns_profile["resolvers"]
        )
        self.delegation_resolvers = list(self.delegation_resolver_endpoints)
        self.delegation_retry_attempts = max(
            1,
            int(
                delegation_retry_attempts
                if delegation_retry_attempts is not None
                else retry_attempts
            ),
        )
        self.delegation_query_coordinator = (
            query_coordinator
            if query_coordinator is not None
            else self._build_query_coordinator(
                coordinator_cls=DelegationQueryCoordinator,
                dns_profile=self.delegation_stage_dns_profile,
            )
        )

    @property
    def resolver(self) -> Any:
        """Return the first delegation endpoint resolver."""
        return self.delegation_query_coordinator.primary_resolver

    @resolver.setter
    def resolver(self, resolver: Any) -> None:
        """Install one resolver for delegation DNS queries."""
        self.delegation_query_coordinator = self._single_resolver_coordinator(
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
        return self._resolve_with_coordinator(
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
        if response.rcode() != dns.rcode.NOERROR or not response.question:
            return False
        question = response.question[0]
        return (
            self._normalize_dns_name(question.name) == self._normalize_dns_name(domain)
            and dns.rdatatype.to_text(question.rdtype).upper() == record_type.upper()
        )

    def _response_has_same_owner_authority_soa(
        self, response: dns.message.Message | None, domain: str
    ) -> bool:
        """Return whether the original NS NODATA response proves same-owner SOA."""
        if response is None or not self._response_matches_question(
            response, domain, "NS"
        ):
            return False
        normalized_domain = self._normalize_dns_name(domain)
        # RFC 2308 negative answers can carry zone SOA in authority. Only a
        # same-owner SOA proves this registrable domain is SOA-only.
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

    def _delegation_nodata_with_soa_fallback(
        self, domain: str, exc: dns.resolver.NoAnswer
    ) -> DelegationResult:
        """Resolve NS NODATA by reusing authority SOA or querying SOA directly."""
        response = self._noanswer_response(exc)
        if self._response_has_same_owner_authority_soa(response, domain):
            logger.debug(
                "DNS delegation NS NODATA reused authority SOA domain=%s soa_source=%s",
                domain,
                "ns_authority",
            )
            return DelegationResult(
                domain=domain,
                ns_nodata=True,
                soa_exists=True,
                soa_source="ns_authority",
            )
        # Ask SOA directly when NS authority did not prove it. This is a new
        # query because DNS cache semantics are keyed by QNAME/QTYPE/QCLASS.
        logger.debug(
            "DNS delegation NS NODATA starting SOA fallback domain=%s soa_source=%s",
            domain,
            "soa_query",
        )
        try:
            answer = self._resolve_delegation_record(
                domain, "SOA", self.delegation_retry_attempts
            )
        except dns.resolver.NXDOMAIN:
            result = DelegationResult(domain=domain, ns_nodata=True, soa_nxdomain=True)
        except dns.resolver.NoAnswer:
            result = DelegationResult(domain=domain, ns_nodata=True, soa_nodata=True)
        except RetryableDNSLookupError as fallback_exc:
            result = (
                DelegationResult(domain=domain, ns_nodata=True, soa_timeout=True)
                if fallback_exc.is_timeout
                else DelegationResult(domain=domain, ns_nodata=True, soa_servfail=True)
            )
        except (dns.exception.DNSException, socket.gaierror):
            result = DelegationResult(domain=domain, ns_nodata=True, soa_servfail=True)
        else:
            result = (
                DelegationResult(
                    domain=domain,
                    ns_nodata=True,
                    soa_exists=True,
                    soa_source="soa_query",
                )
                if self._soa_answer_exists_for_domain(answer, domain)
                else DelegationResult(domain=domain, ns_nodata=True, soa_nodata=True)
            )
        logger.debug(
            "DNS delegation NS NODATA SOA fallback completed domain=%s status=%s "
            "soa_source=%s",
            domain,
            result.status,
            result.soa_source or "soa_query",
        )
        return result

    def delegation_lookup(self, domain: str) -> DelegationResult:
        """Run delegation check: NS first, SOA fallback only after NS NODATA."""
        try:
            answer = self._resolve_delegation_record(
                domain, "NS", self.delegation_retry_attempts
            )
        except dns.resolver.NXDOMAIN:
            return DelegationResult(domain=domain, ns_nxdomain=True)
        except dns.resolver.NoAnswer as exc:
            return self._delegation_nodata_with_soa_fallback(domain, exc)
        except RetryableDNSLookupError as exc:
            if exc.is_timeout:
                return DelegationResult(domain=domain, ns_timeout=True)
            return DelegationResult(domain=domain, ns_servfail=True)
        except (dns.exception.DNSException, socket.gaierror):
            return DelegationResult(domain=domain, ns_servfail=True)

        nameservers = sorted({str(rr.target).rstrip(".").lower() for rr in answer})
        if not nameservers:
            return DelegationResult(domain=domain, no_nameservers=True)
        return DelegationResult(domain=domain, ns_exists=True, nameservers=nameservers)
