"""Delegation-owned DNS query coordinator."""

from __future__ import annotations

from domain_pipeline.worker.dns_query.query_coordinator import DNSQueryCoordinatorBase


class DelegationQueryCoordinator(DNSQueryCoordinatorBase):
    """Coordinator for the delegation DNS query stage."""

    stage = "delegation"
