"""DNS checker factory owned by the worker runtime."""

from __future__ import annotations

from typing import Any

from domain_pipeline.worker.delegation.lookup import (
    DelegationChecker,
    DelegationCheckerRequest,
)
from domain_pipeline.worker.dns_query.lookup import DNSCheckerBaseRequest
from domain_pipeline.worker.dns_query.query_coordinator import DNSQueryCoordinatorState
from domain_pipeline.worker.host_resolution.lookup import (
    HostResolutionChecker,
    HostResolutionCheckerRequest,
)


class RuntimeDNSChecker:
    """Runtime facade over independently owned DNS stage checkers."""

    def __init__(
        self,
        *,
        delegation_checker: DelegationChecker,
        host_resolution_checker: HostResolutionChecker,
    ) -> None:
        self.delegation_checker = delegation_checker
        self.host_resolution_checker = host_resolution_checker

    @property
    def delegation_stage_dns_profile(self) -> dict[str, Any]:
        """Return the delegation checker profile."""
        return dict(self.delegation_checker.delegation_stage_dns_profile)

    @property
    def delegation_resolver_endpoints(self) -> list[str]:
        """Return delegation resolver endpoints."""
        return list(self.delegation_checker.delegation_resolver_endpoints)

    @property
    def host_resolution_dns_profile(self) -> dict[str, Any]:
        """Return the host-resolution checker profile."""
        return dict(self.host_resolution_checker.host_resolution_dns_profile)

    @property
    def delegation_query_coordinator(self) -> Any:
        """Return the delegation query coordinator."""
        return self.delegation_checker.delegation_query_coordinator

    @property
    def host_resolution_query_coordinator(self) -> Any:
        """Return the host-resolution query coordinator."""
        return self.host_resolution_checker.host_resolution_query_coordinator

    def delegation_resolver_key(self) -> str:
        """Return the delegation resolver cache key."""
        return self.delegation_checker.delegation_resolver_key()

    def host_resolution_resolver_key(self) -> str:
        """Return the host-resolution resolver cache key."""
        return self.host_resolution_checker.host_resolution_resolver_key()

    def delegation_lookup(self, domain: str) -> Any:
        """Run the delegation lookup stage."""
        return self.delegation_checker.delegation_lookup(domain)

    def host_resolution_lookup(self, host: str) -> Any:
        """Run the host-resolution lookup stage."""
        return self.host_resolution_checker.host_resolution_lookup(host)


class RuntimeDNSCheckerFactory:
    """Build DNS checkers from normalized runtime source configuration."""

    def __init__(
        self, *, coordinator_state: DNSQueryCoordinatorState | None = None
    ) -> None:
        self._coordinator_state = coordinator_state

    def build_from_checkers(
        self,
        *,
        delegation_checker: DelegationChecker,
        host_resolution_checker: HostResolutionChecker,
    ) -> RuntimeDNSChecker:
        """Build a runtime facade from already-created stage checkers."""
        return RuntimeDNSChecker(
            delegation_checker=delegation_checker,
            host_resolution_checker=host_resolution_checker,
        )

    def build(
        self,
        source_config: dict[str, Any],
    ) -> RuntimeDNSChecker:
        """Build a runtime DNS checker from one normalized source config."""
        dns_config = {
            **dict(source_config["dns_query"]),
            "delegation": dict(source_config["delegation"]),
            "host_resolution": dict(source_config["host_resolution"]),
        }
        base_request = DNSCheckerBaseRequest(
            default_resolvers=dns_config.get("default_resolvers"),
            timeout=float(dns_config.get("timeout", 5.0)),
            retry_backoff_base_seconds=float(
                dns_config.get("retry_backoff_base_seconds", 1.0)
            ),
            query_rate_limit=dns_config.get("query_rate_limit", {}),
        )
        return self.build_from_checkers(
            delegation_checker=DelegationChecker(
                DelegationCheckerRequest(
                    base=base_request,
                    delegation_dns=dict(dns_config.get("delegation", {})),
                    delegation_retry_attempts=int(
                        dns_config.get("delegation", {}).get("retry_attempts", 3)
                    ),
                ),
                coordinator_state=self._coordinator_state,
            ),
            host_resolution_checker=HostResolutionChecker(
                HostResolutionCheckerRequest(
                    base=base_request,
                    host_resolution_dns=dict(dns_config.get("host_resolution", {})),
                    host_retry_attempts=int(
                        dns_config.get("host_resolution", {}).get("retry_attempts", 3)
                    ),
                ),
                coordinator_state=self._coordinator_state,
            ),
        )
