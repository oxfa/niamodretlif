"""DNS checker factory owned by the worker runtime."""

from __future__ import annotations

from typing import Any

from domain_pipeline.worker.dns import (
    DomainChecker,
    delegation_dns_profile,
    host_resolution_dns_profile,
)


class RuntimeDNSCheckerFactory:
    """Build DNS checkers from normalized runtime source configuration."""

    def build(
        self,
        source_config: dict[str, Any],
    ) -> DomainChecker:
        """Build a DNS checker from one normalized source config."""
        dns_config = source_config["dns"]
        return DomainChecker(
            timeout=float(dns_config.get("timeout", 5.0)),
            query_rate_limit=dns_config.get("query_rate_limit", {}),
            delegation_dns=delegation_dns_profile(dns_config),
            host_resolution_dns=host_resolution_dns_profile(dns_config),
            delegation_retry_attempts=int(
                dns_config.get("delegation", {}).get("retry_attempts", 3)
            ),
            host_retry_attempts=int(
                dns_config.get("host_resolution", {}).get("retry_attempts", 3)
            ),
        )
