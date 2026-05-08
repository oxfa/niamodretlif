"""Host-resolution-owned DNS query coordinator."""

from __future__ import annotations

from domain_pipeline.worker.dns_query.query_coordinator import DNSQueryCoordinatorBase


class HostResolutionQueryCoordinator(DNSQueryCoordinatorBase):
    """Coordinator for the host-resolution DNS query stage."""

    stage = "host_resolution"
