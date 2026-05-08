"""DNS checker factory owned by the worker runtime."""

from __future__ import annotations

from typing import Any

from domain_pipeline.worker.delegation import DelegationChecker
from domain_pipeline.worker.host_resolution import HostResolutionChecker


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
    def delegation_resolvers(self) -> list[str]:
        """Return delegation resolvers."""
        return list(self.delegation_checker.delegation_resolvers)

    @property
    def host_resolution_dns_profile(self) -> dict[str, Any]:
        """Return the host-resolution checker profile."""
        return dict(self.host_resolution_checker.host_resolution_dns_profile)

    @property
    def resolvers(self) -> list[str]:
        """Return host-resolution resolvers."""
        return list(self.host_resolution_checker.resolvers)

    @property
    def nameservers(self) -> list[str]:
        """Return host-resolution nameservers."""
        return list(self.host_resolution_checker.nameservers)

    @property
    def delegation_query_coordinator(self) -> Any:
        """Return the delegation query coordinator."""
        return self.delegation_checker.delegation_query_coordinator

    @property
    def host_resolution_query_coordinator(self) -> Any:
        """Return the host-resolution query coordinator."""
        return self.host_resolution_checker.host_resolution_query_coordinator

    @property
    def query_coordinator(self) -> Any:
        """Return the host-resolution query coordinator for existing callers."""
        return self.host_resolution_checker.query_coordinator

    @property
    def resolver(self) -> Any:
        """Return the host-resolution primary resolver."""
        return self.host_resolution_checker.resolver

    @resolver.setter
    def resolver(self, resolver: Any) -> None:
        """Install one resolver for both runtime DNS stages."""
        self.delegation_checker.resolver = resolver
        self.host_resolution_checker.resolver = resolver

    def delegation_resolver_key(self) -> str:
        """Return the delegation resolver cache key."""
        return self.delegation_checker.delegation_resolver_key()

    def host_resolution_resolver_key(self) -> str:
        """Return the host-resolution resolver cache key."""
        return self.host_resolution_checker.host_resolution_resolver_key()

    def resolver_key(self) -> str:
        """Return the host-resolution resolver cache key."""
        return self.host_resolution_resolver_key()

    def delegation_lookup(self, domain: str) -> Any:
        """Run the delegation lookup stage."""
        return self.delegation_checker.delegation_lookup(domain)

    def host_resolution_lookup(self, host: str) -> Any:
        """Run the host-resolution lookup stage."""
        return self.host_resolution_checker.host_resolution_lookup(host)


class RuntimeDNSCheckerFactory:
    """Build DNS checkers from normalized runtime source configuration."""

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
        return RuntimeDNSChecker(
            delegation_checker=DelegationChecker(
                timeout=float(dns_config.get("timeout", 5.0)),
                query_rate_limit=dns_config.get("query_rate_limit", {}),
                delegation_dns=dict(dns_config.get("delegation", {})),
                delegation_retry_attempts=int(
                    dns_config.get("delegation", {}).get("retry_attempts", 3)
                ),
            ),
            host_resolution_checker=HostResolutionChecker(
                timeout=float(dns_config.get("timeout", 5.0)),
                query_rate_limit=dns_config.get("query_rate_limit", {}),
                host_resolution_dns=dict(dns_config.get("host_resolution", {})),
                host_retry_attempts=int(
                    dns_config.get("host_resolution", {}).get("retry_attempts", 3)
                ),
            ),
        )
